/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

extern "C" {

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
#include "../lib/allocator.h"

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

struct js_data {
	struct rrr_instance_runtime_data *thread_data;
	char *js_script;
};

/*
static void js_data_cleanup(void *arg) {
	struct js_data *data = (struct js_data *data) arg;

	RRR_FREE_IF_NOT_NULL(data->js_script);
}
*/

static void js_data_init(struct js_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static int js_parse_config (struct js_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("js_script", js_script);

	if (data->js_script == NULL || *(data->js_script) == '\0') {
		RRR_MSG_0("js_script configuration parameter missing for js instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct js_run_data {
	struct js_data *data = nullptr;

	int (*config_function)() = nullptr;
	int (*source_function)() = nullptr;
	int (*process_function)() = nullptr;
};

static int js_init_wrapper_callback (RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	struct js_data *data = (struct js_data *) private_arg;

	(void)(configuration_callback_arg);
	(void)(process_callback_arg);

	int ret = 0;

	struct js_run_data run_data;

	// LOAD JS

	run_data.data = data;
	//run_data.ctx.worker = worker;

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			configuration_callback,
			(void *) &run_data,
			process_callback,
			(void *) &run_data,
			custom_tick_callback,
			custom_tick_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		// Don't goto out, run cleanup functions
	}

/*	if (run_data.ctx.application_ptr != NULL) {
		RRR_MSG_0("Warning: application_ptr in ctx for js instance %s was not NULL upon exit\n",
				INSTANCE_D_NAME(data->thread_data));
	}*/

	return ret;
}

static int js_configuration_callback (RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	struct js_run_data *run_data = (struct js_run_data *) private_arg;

	(void)(worker);

	int ret = 0;

	if (run_data->config_function == NULL) {
		RRR_DBG_1("Note: No configuration function set for cmodule instance %s\n",
				INSTANCE_D_NAME(run_data->data->thread_data));
		goto out;
	}

	if ((ret = 0/*run_data->config_function(nullptr, INSTANCE_D_CONFIG(run_data->data->thread_data))*/) != 0) {
		RRR_MSG_0("Error %i from configuration function in cmodule instance %s\n",
				ret, INSTANCE_D_NAME(run_data->data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int js_process_callback (RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	struct js_run_data *run_data = (struct js_run_data *) private_arg;

	(void)(worker);

	int ret = 0;

	struct rrr_msg_msg *message_copy = rrr_msg_msg_duplicate(message);
	if (message_copy == NULL) {
		RRR_MSG_0("Could not allocate message in %s\n");
		ret = 1;
		goto out;
	}

	if (is_spawn_ctx) {
		if (run_data->source_function == NULL) {
			RRR_BUG("BUG: Source function was NULL but we tried to source anyway in %s\n", __func__);
		}
		//ret = run_data->source_function(nullptr, message_copy, message_addr);
		// Don't goto out here, print error further down
	}
	else {
		if (run_data->process_function == NULL) {
			RRR_BUG("BUG: Process function was NULL but we tried to source anyway in %s\n", __func__);
		}
		//ret = run_data->process_function(nullptr, message_copy, message_addr);
		// Don't goto out here, print error further down
	}

	if (ret != 0) {
		RRR_MSG_0("Error %i returned from application in js instance %s. Mode was %s.\n",
				ret, INSTANCE_D_NAME(run_data->data->thread_data), (is_spawn_ctx ? "sourcing" : "processing"));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct js_fork_callback_data {
	struct rrr_instance_runtime_data *thread_data;
};

static int js_fork (void *arg) {
	struct js_fork_callback_data *callback_data = (struct js_fork_callback_data *) arg;
	struct rrr_instance_runtime_data *thread_data = callback_data->thread_data;
	struct js_data *data = (struct js_data *) thread_data->private_data;
	const struct rrr_cmodule_config_data *cmodule_config_data = nullptr;

	int ret = 0;

	if (js_parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}
	if (rrr_cmodule_helper_parse_config(thread_data, "js", "function") != 0) {
		ret = 1;
		goto out;
	}

	// Contains function names etc.
	cmodule_config_data = rrr_cmodule_helper_config_data_get(data->thread_data);

	if (rrr_cmodule_helper_worker_forks_start (
			thread_data,
			js_init_wrapper_callback,
			data,
			js_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			js_process_callback,
			NULL  // <-- in the init wrapper, this callback is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting cmodule worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}
	out:
	return ret;
}

static void *thread_entry_js (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = (struct rrr_instance_runtime_data *) thread->private_data;
	struct js_data *data = (struct js_data *) thread_data->private_memory;
	thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("js thread thread_data is %p\n", thread_data);

	js_data_init(data, thread_data);

	struct js_fork_callback_data fork_callback_data = {
		thread_data
	};

	if (rrr_thread_start_condition_helper_fork(thread, js_fork, &fork_callback_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("js instance %s started thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_loop (
			thread_data
	);

	out_message:
	RRR_DBG_1 ("js instance %s stopping thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_js,
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
	data->event_functions = rrr_cmodule_helper_event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy cmodule module\n");
}

}; // extern "C"
