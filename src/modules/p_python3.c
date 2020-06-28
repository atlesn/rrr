/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include <unistd.h>
#include <inttypes.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "../lib/python3/python3_common.h"
#include "../lib/python3/python3_config.h"
#include "../lib/python3/python3_vl_message.h"
#include "../lib/python3/python3_cmodule.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/message_addr.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/log.h"
#include "../lib/cmodule.h"
#include "../lib/cmodule_common.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/array.h"

struct python3_data {
	struct rrr_instance_thread_data *thread_data;

	char *python3_module;
	char *source_function;
	char *process_function;
	char *config_function;
	char *module_path;
};

int data_init (
		struct python3_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return ret;
}

void data_cleanup(void *arg) {
	struct python3_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->python3_module);
	RRR_FREE_IF_NOT_NULL(data->source_function);
	RRR_FREE_IF_NOT_NULL(data->process_function);
	RRR_FREE_IF_NOT_NULL(data->config_function);
	RRR_FREE_IF_NOT_NULL(data->module_path);
}

int parse_config(struct python3_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->python3_module, config, "python3_module");

	if (ret != 0) {
		RRR_MSG_0("No python3_module specified for python module\n");
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_function, config, "python3_source_function");
	rrr_instance_config_get_string_noconvert_silent (&data->process_function, config, "python3_process_function");
	rrr_instance_config_get_string_noconvert_silent (&data->config_function, config, "python3_config_function");
	rrr_instance_config_get_string_noconvert_silent (&data->module_path, config, "python3_module_path");

	if (data->source_function == NULL && data->process_function == NULL) {
		RRR_MSG_0("No source or processor function defined for python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct python3_child_data {
	struct python3_data *parent_data;
	PyObject *config_function;
	PyObject *process_function;
	PyObject *source_function;
	struct python3_fork_runtime *runtime;
};

int python3_configuration_callback(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	int ret = 0;

	struct python3_child_data *data = private_arg;

	PyObject *config = NULL;

	if (data->config_function == NULL) {
		goto out;
	}

	// NOTE : The python config object operates on the original settings structure
	config = rrr_python3_config_new (worker->settings);

	if (config == NULL) {
		RRR_MSG_0("Could not create config object in __rrr_py_persistent_send_config \n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_py_cmodule_call_application_raw (
			data->config_function,
			config,
			NULL
	)) != 0) {
		RRR_MSG_0("Error from config function in __rrr_py_persistent_send_config \n");
		ret = 1;
		goto out;
	}

	out:
	Py_XDECREF(config);
	return ret;
}

int python3_process_callback(RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	int ret = 0;

	(void)(worker);

	struct python3_child_data *data = private_arg;

	PyObject *arg_message = NULL;

	arg_message = rrr_python3_rrr_message_new_from_message_and_address(message, (is_spawn_ctx ? NULL : message_addr));
	if (arg_message == NULL) {
		RRR_MSG_0("Could not create python3 message in python3_process_callback\n");
		ret = 1;
		goto out;
	}

	PyObject *function = NULL;

	if (is_spawn_ctx) {
		function = data->source_function;
	}
	else {
		function = data->process_function;
	}

	if (function != NULL) {
		ret = rrr_py_cmodule_call_application_raw(function, data->runtime->socket, arg_message);
	}
	else {
		RRR_DBG_3("Python3 no functions defined, is_spawn was %i\n", is_spawn_ctx);
	}

	if (ret != 0) {
		ret = RRR_FIFO_CALLBACK_ERR | RRR_FIFO_SEARCH_STOP;
	}

	out:
	RRR_Py_XDECREF(arg_message);

	return ret;

}

int python3_init_wrapper_callback(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	int ret = 0;

	(void)(process_callback_arg);
	(void)(configuration_callback_arg);

	struct python3_data *data = private_arg;
	struct python3_child_data child_data = {0};

	child_data.parent_data = data;

	PyObject *module = NULL;
	PyObject *module_dict = NULL;
	PyObject *py_module_name = NULL;
	PyObject *process_function = NULL;
	PyObject *source_function = NULL;
	PyObject *config_function = NULL;

	struct python3_fork_runtime runtime;

	if ((ret = rrr_py_cmodule_runtime_init (
			&runtime,
			worker,
			data->module_path
	)) != 0) {
		RRR_MSG_0("Could not initialize python3 runtime in __rrr_py_start_persistent_rw_fork_intermediate\n");
		ret = 1;
		goto out;
	}

	PyEval_RestoreThread(runtime.istate);

//	printf ("New fork main  refcount: %li\n", fork->socket_main->ob_refcnt);
//	printf ("New fork child refcount: %li\n", fork->socket_child->ob_refcnt);

	py_module_name = PyUnicode_FromString(data->python3_module);
	module = PyImport_GetModule(py_module_name);
//	printf ("Module %s already loaded? %p\n", module_name, module);
	if (module == NULL && (module = PyImport_ImportModule(data->python3_module)) == NULL) {
		RRR_MSG_0("Could not import module %s while starting thread:\n", data->python3_module);
		PyErr_Print();
		ret = 1;
		goto out_cleanup_runtime;
	}
//	printf ("Module %s loaded: %p\n", module_name, module);

	if ((module_dict = PyModule_GetDict(module)) == NULL) { // Borrowed reference
		RRR_MSG_0("Could not get dictionary of module %s while starting thread:\n", data->python3_module);
		PyErr_Print();
		ret = 1;
		goto out_cleanup_runtime;
	}

	if (data->config_function != NULL) {
		if ((config_function = rrr_py_import_function(module_dict, data->config_function)) == NULL) {
			RRR_MSG_0("Could not get config function '%s' from module '%s' while starting python3 fork\n",
					data->config_function, data->python3_module);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

	if (data->source_function != NULL) {
		if ((source_function = rrr_py_import_function(module_dict, data->source_function)) == NULL) {
			RRR_MSG_0("Could not get source function '%s' from module '%s' while starting python3 fork\n",
					data->source_function, data->python3_module);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

	if (data->process_function != NULL) {
		if ((process_function = rrr_py_import_function(module_dict, data->process_function)) == NULL) {
			RRR_MSG_0("Could not get process function '%s' from module '%s' while starting python3 fork\n",
					data->process_function, data->python3_module);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

/*	if (VL_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING IMPORTED USER MODULE ===========================\n");
		rrr_py_dump_dict_entries(module_dict);
		printf ("=== PYTHON3 DUMPING IMPORTED USER MODULE END =======================\n\n");
	}*/

	child_data.runtime = &runtime;
	child_data.config_function = config_function;
	child_data.source_function = source_function;
	child_data.process_function = process_function;

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			configuration_callback,
			&child_data,
			process_callback,
			&child_data
	)) != 0) {
		RRR_MSG_0("Error from worker loop in __rrr_cmodule_worker_loop_init_wrapper_default\n");
		// Don't goto out, run cleanup functions
	}

	out_cleanup_runtime:
		RRR_Py_XDECREF(config_function);
		RRR_Py_XDECREF(process_function);
		RRR_Py_XDECREF(source_function);
		RRR_Py_XDECREF(py_module_name);
		RRR_Py_XDECREF(module);
		PyEval_SaveThread();

		rrr_py_cmodule_runtime_cleanup(&runtime);

	out:
	return ret;
}

static void *thread_entry_python3 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll;

	RRR_DBG_1 ("python3 thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	rrr_poll_collection_init(&poll);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initalize data in python3 instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1("python3 instance %s\n", INSTANCE_D_NAME(thread_data));

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	rrr_poll_add_from_thread_senders(&poll, thread_data);

	int no_polling = 1;
	if (rrr_poll_collection_count (&poll) > 0) {
		if (!data->process_function) {
			RRR_MSG_0("Python3 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		no_polling = 0;
	}

	pid_t fork_pid = 0;
	rrr_setting_uint spawn_interval_ms = 0;

	if (rrr_cmodule_start_worker_fork (
			&fork_pid,
			thread_data->cmodule,
			INSTANCE_D_FORK(thread_data),
			spawn_interval_ms * 1000,
			10 * 1000,
			INSTANCE_D_NAME(thread_data),
			(data->source_function != NULL ? 1 : 0),
			(data->process_function != NULL ? 1 : 0),
			0, // <-- Drop on error
			INSTANCE_D_SETTINGS(thread_data),
			python3_init_wrapper_callback,
			data,
			python3_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			python3_process_callback,
			NULL  // <-- in the init wrapper, this callback is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting perl5 worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);

	RRR_DBG_1 ("python3 instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_common_loop (
			thread_data,
			stats,
			&poll,
			fork_pid,
			no_polling
	);

	out_message:
	RRR_DBG_1 ("python3 instance %s exiting\n", INSTANCE_D_NAME(thread_data));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct python3_data data;
	int ret = 0;
	if ((ret = data_init(&data, NULL)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_python3,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "python3";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = RRR_THREAD_START_PRIORITY_FORK;
}

void unload(void) {
	RRR_DBG_1 ("Destroy python3 module\n");
}

