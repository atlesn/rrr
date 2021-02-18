/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "../lib/log.h"

#include "../lib/rrr_strerror.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_config_data.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"

#define RRR_CMODULE_NATIVE_CTX
#include "../cmodules/cmodule.h"

const char *cmodule_library_paths[] = {
		"/usr/lib/rrr/cmodules",
		"/lib/rrr/cmodules",
		"/usr/local/lib/rrr/cmodules",
		"./src/cmodules/.libs",
		"./src/cmodules",
		"../cmodules/.libs", // <!-- For test suite
		"../cmodules", // <!-- For test suite
		"./cmodules",
		"./",
		""
};

struct cmodule_data {
	struct rrr_instance_runtime_data *thread_data;

	char *cmodule_name;
	char *cleanup_function;
};

static void cmodule_data_cleanup(void *arg) {
	struct cmodule_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->cmodule_name);
	RRR_FREE_IF_NOT_NULL(data->cleanup_function);
}

static int cmodule_data_init(struct cmodule_data *data, struct rrr_instance_runtime_data *thread_data) {
	int ret = 0;
	data->thread_data = thread_data;
	if (ret != 0) {
		cmodule_data_cleanup(data);
	}
	return ret;
}

static int cmodule_parse_config (struct cmodule_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("cmodule_name", cmodule_name);

	if (data->cmodule_name == NULL || *(data->cmodule_name) == '\0') {
		RRR_MSG_0("cmodule_name configuration parameter missing for cmodule instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("cmodule_cleanup_function", cleanup_function);

	out:
	return ret;
}

struct cmodule_run_data {
	struct rrr_cmodule_ctx ctx;
	void *dl_ptr;

	struct cmodule_data *data;

	int (*config_function)(RRR_CONFIG_ARGS);
	int (*source_function)(RRR_SOURCE_ARGS);
	int (*process_function)(RRR_PROCESS_ARGS);
	int (*cleanup_function)(RRR_CLEANUP_ARGS);
};

#define GET_FUNCTION(from,name)															\
	do { if (from->name != NULL && *(from->name) != '\0') {								\
		if ((run_data->name = dlsym(handle, from->name)) == NULL) {						\
			RRR_MSG_0("Could not load function '%s' from cmodule instance %s: %s\n",	\
					from->name, INSTANCE_D_NAME(data->thread_data), dlerror());			\
			function_err = 1;															\
		}																				\
	} } while(0)

static void __cmodule_dl_unload (
		void *handle
) {
	if (handle == NULL) {
		return;
	}
	if (dlclose(handle) != 0) {
		RRR_MSG_0 ("Warning: Error while unloading cmodule: %s\n", dlerror());
	}
}

static int __cmodule_load (
		struct cmodule_run_data *run_data,
		struct cmodule_data *data
) {
	const struct rrr_cmodule_config_data *cmodule_config_data = rrr_cmodule_helper_config_data_get(data->thread_data);

	int ret = 1; // Default is NOT OK

	void *handle = NULL;

	for (int i = 0; *(cmodule_library_paths[i]) != '\0'; i++) {
		char path[256 + strlen(data->cmodule_name) + 1];
		sprintf(path, "%s/%s.so", cmodule_library_paths[i], data->cmodule_name);

//		printf("check path %s\n", path);
		struct stat buf;
		if (stat(path, &buf) != 0) {
			if (errno == ENOENT) {
				continue;
			}
			RRR_MSG_0 ("Could not stat %s while loading module: %s\n", path, rrr_strerror(errno));
			continue;
		}

		__cmodule_dl_unload(handle);
		handle = dlopen(path, RTLD_LAZY);

		RRR_DBG_1 ("dlopen handle for %s: %p\n", data->cmodule_name, handle);

		if (handle == NULL) {
			RRR_MSG_0 ("Error while opening module %s: %s\n", path, dlerror());
			continue;
		}

		int function_err = 0;

		GET_FUNCTION(cmodule_config_data,config_function);
		GET_FUNCTION(cmodule_config_data,source_function);
		GET_FUNCTION(cmodule_config_data,process_function);
		GET_FUNCTION(data,cleanup_function);

		if (function_err != 0) {
			continue;
		}

		ret = 0; // OK
		break;
	}

	if (ret != 0) {
		__cmodule_dl_unload(handle);
	}
	else {
		run_data->dl_ptr = handle;
	}

	return ret;
}

static void __cmodule_application_cleanup (void *arg) {
	struct cmodule_run_data *run_data = arg;

	if (run_data->cleanup_function == NULL) {
		RRR_DBG_1("Note: No cleanup function set for cmodule instance %s\n",
				INSTANCE_D_NAME(run_data->data->thread_data));
		goto out;
	}

	int ret = 0;
	if ((ret = run_data->cleanup_function(&run_data->ctx)) != 0) {
		RRR_MSG_0("Warning: Error %i from cleanup function in cmodule instance %s\n",
				ret, INSTANCE_D_NAME(run_data->data->thread_data));
		goto out;
	}

	out:
	return;
}

static int cmodule_init_wrapper_callback (RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	struct cmodule_data *data = private_arg;

	(void)(configuration_callback_arg);
	(void)(process_callback_arg);

	int ret = 0;

	struct cmodule_run_data run_data = {0};

	if (__cmodule_load(&run_data, data) != 0) {
		RRR_MSG_0("Loading failed in cmodule instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	run_data.data = data;
	run_data.ctx.worker = worker;

	pthread_cleanup_push(__cmodule_dl_unload, run_data.dl_ptr);
	pthread_cleanup_push(__cmodule_application_cleanup, &run_data);

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			configuration_callback,
			&run_data,
			process_callback,
			&run_data,
			custom_tick_callback,
			custom_tick_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from worker loop in __rrr_cmodule_worker_loop_init_wrapper_default\n");
		// Don't goto out, run cleanup functions
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	if (run_data.ctx.application_ptr != NULL) {
		RRR_MSG_0("Warning: application_ptr in ctx for cmodule instance %s was not NULL upon exit\n",
				INSTANCE_D_NAME(data->thread_data));
	}

	out:
	return ret;
}

static int cmodule_configuration_callback (RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	struct cmodule_run_data *run_data = private_arg;

	(void)(worker);

	int ret = 0;

	if (run_data->config_function == NULL) {
		RRR_DBG_1("Note: No configuration function set for cmodule instance %s\n",
				INSTANCE_D_NAME(run_data->data->thread_data));
		goto out;
	}

	if ((ret = run_data->config_function(&run_data->ctx, INSTANCE_D_CONFIG(run_data->data->thread_data))) != 0) {
		RRR_MSG_0("Error %i from configuration function in cmodule instance %s\n",
				ret, INSTANCE_D_NAME(run_data->data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int cmodule_process_callback (RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	struct cmodule_run_data *run_data = private_arg;

	(void)(worker);

	int ret = 0;

	struct rrr_msg_msg *message_copy = rrr_msg_msg_duplicate(message);
	if (message_copy == NULL) {
		RRR_MSG_0("Could not allocate message in cmodule_process_callback\n");
		ret = 1;
		goto out;
	}

	if (is_spawn_ctx) {
		if (run_data->source_function == NULL) {
			RRR_BUG("BUG: Source function was NULL but we tried to source anyway in cmodule_process_callback\n");
		}
		ret = run_data->source_function(&run_data->ctx, message_copy, message_addr);
		// Don't goto out here, print error further down
	}
	else {
		if (run_data->process_function == NULL) {
			RRR_BUG("BUG: Process function was NULL but we tried to source anyway in cmodule_process_callback\n");
		}
		ret = run_data->process_function(&run_data->ctx, message_copy, message_addr);
		// Don't goto out here, print error further down
	}

	if (ret != 0) {
		RRR_MSG_0("Error %i returned from application in cmodule instance %s. Mode was %s.\n",
				ret, INSTANCE_D_NAME(run_data->data->thread_data), (is_spawn_ctx ? "sourcing" : "processing"));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct cmodule_fork_callback_data {
	struct rrr_instance_runtime_data *thread_data;
};

static int cmodule_fork (void *arg) {
	struct cmodule_fork_callback_data *callback_data = arg;
	struct rrr_instance_runtime_data *thread_data = callback_data->thread_data;
	struct cmodule_data *data = thread_data->private_data;

	int ret = 0;

	if (cmodule_parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}
	if (rrr_cmodule_helper_parse_config(thread_data, "cmodule", "function") != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_cmodule_helper_worker_forks_start (
			thread_data,
			cmodule_init_wrapper_callback,
			data,
			cmodule_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			cmodule_process_callback,
			NULL  // <-- in the init wrapper, this callback is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting cmodule worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}
	out:
	return ret;
}

static void *thread_entry_cmodule (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct cmodule_data *data = thread_data->private_data = thread_data->private_memory;

	if (cmodule_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in cmodule instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("cmodule thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(cmodule_data_cleanup, data);

	struct cmodule_fork_callback_data fork_callback_data = {
		thread_data
	};

	if (rrr_thread_start_condition_helper_fork(thread, cmodule_fork, &fork_callback_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("cmodule instance %s started thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_loop (
			thread_data,
			INSTANCE_D_STATS(thread_data),
			&thread_data->poll
	);

	out_message:
	RRR_DBG_1 ("cmodule instance %s stopping thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_cmodule,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "cmodule";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
}

void unload(void) {
	RRR_DBG_1 ("Destroy cmodule module\n");
}

