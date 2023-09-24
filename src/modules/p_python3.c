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

// Enable assert, python seems to disable it in some header
#undef NDEBUG

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/python3/python3_common.h"
#include "../lib/python3/python3_config.h"
#include "../lib/python3/python3_message.h"
#include "../lib/python3/python3_cmodule.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/messages/msg_addr.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_config_data.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/message_holder/message_holder.h"

struct python3_method {
	RRR_LL_NODE(struct python3_method);
	char *name;
	PyObject *method;
};

struct python3_method_collection {
	RRR_LL_HEAD(struct python3_method);
};

static void python3_method_destroy(struct python3_method *m) {
	RRR_FREE_IF_NOT_NULL(m->name);
	Py_XDECREF(m->method);
	rrr_free(m);
}

static void python3_method_collection_clear(struct python3_method_collection *c) {
	RRR_LL_DESTROY(c, struct python3_method, python3_method_destroy(node));
}

static PyObject *python3_method_collection_get (const struct python3_method_collection *c, const char *name) {
	RRR_LL_ITERATE_BEGIN(c, const struct python3_method);
		if (strcmp(node->name, name) == 0) {
			return node->method;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static int python3_method_collection_put (struct python3_method_collection *c, const char *name, PyObject *method) {
	int ret = 0;

	struct python3_method *m;

	if ((m = rrr_allocate(sizeof(*m))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((m->name = rrr_strdup(name)) == NULL) {
		RRR_MSG_0("Failed to allocate name in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	m->method = method;
	Py_INCREF(method);

	RRR_LL_APPEND(c, m);

	goto out;
	out_free:
		rrr_free(m);
	out:
		return ret;
}

struct python3_data {
	struct rrr_instance_runtime_data *thread_data;

	char *python3_module;
	char *module_path;
};

int data_init (
		struct python3_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return ret;
}

void data_cleanup(void *arg) {
	struct python3_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->python3_module);
	RRR_FREE_IF_NOT_NULL(data->module_path);
}

int parse_config(struct python3_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->python3_module, config, "python3_module");

	if (ret != 0) {
		RRR_MSG_0("No python3_module specified for python module\n");
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->module_path, config, "python3_module_path");

	out:
	return ret;
}

struct python3_child_data {
	struct python3_data *parent_data;
	PyObject *config_method;
	PyObject *process_method;
	PyObject *source_method;
	struct python3_method_collection *methods;
	struct python3_fork_runtime *runtime;
};

int python3_configuration_callback(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	int ret = 0;

	struct python3_child_data *data = private_arg;

	PyObject *config = NULL;

	if (data->config_method == NULL) {
		goto out;
	}

	// NOTE : The python config object operates on the original settings structure
	config = rrr_python3_config_new (rrr_cmodule_worker_get_settings(worker));

	if (config == NULL) {
		RRR_MSG_0("Could not create config object in __rrr_py_persistent_send_config \n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_py_cmodule_call_application_raw (
			data->config_method,
			config,
			NULL,
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
	(void)(worker);

	int ret = 0;

	struct python3_child_data *data = private_arg;
	struct python3_data *parent_data = data->parent_data;

	PyObject *function = NULL;
	PyObject *arg_message = NULL;
	PyObject *arg_method = NULL;

	if (!is_spawn_ctx) {
		if (method != NULL) {
			if ((arg_method = PyUnicode_FromString(method)) == NULL) {
				RRR_MSG_0("Could not create python3 method string in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
		else {
			Py_INCREF(arg_method = Py_None);
		}
	}

	if ((arg_message = rrr_python3_rrr_message_new_from_message_and_address (
			message,
			is_spawn_ctx ? NULL : message_addr
	)) == NULL) {
		RRR_MSG_0("Could not create python3 message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (is_spawn_ctx) {
		function = data->source_method;
	}
	else if (INSTANCE_D_FLAGS(parent_data->thread_data) & RRR_INSTANCE_MISC_OPTIONS_METHODS_DIRECT_DISPATCH) {
		function = python3_method_collection_get(data->methods, method);
	}
	else {
		function = data->process_method;
	}

	if (function == NULL) {
		RRR_BUG("Python3 no functions defined in %s, some error in init wrapper causes functions not to be prepared correctly. is_spawn was %i\n",
			__func__, is_spawn_ctx);
	}

	if ((ret = rrr_py_cmodule_call_application_raw (
			function,
			data->runtime->socket,
			arg_message,
			arg_method
	)) != 0) {
		ret = RRR_FIFO_PROTECTED_CALLBACK_ERR | RRR_FIFO_PROTECTED_SEARCH_STOP;
	}

	out:
	RRR_Py_XDECREF(arg_message);
	RRR_Py_XDECREF(arg_method);

	return ret;

}

struct python3_method_name_callback_data {
	struct python3_data *data;
	struct python3_method_collection *methods;
	PyObject *module_dict;
};

int python3_method_name_callback(const char *stack_name, const char *method_name, void *arg) {
	struct python3_method_name_callback_data *callback_data = arg;
	struct python3_data *data = callback_data->data;

	int ret = 0;

	PyObject *method = NULL;

	if ((method = rrr_py_import_function(callback_data->module_dict, method_name)) == NULL) {
		RRR_MSG_0("Could not find function '%s' from method definition '%s' in module '%s' while starting python3 fork\n",
				method_name, stack_name, data->python3_module);
		ret = 1;
		goto out;
	}

	if ((ret = python3_method_collection_put(callback_data->methods, method_name, method)) != 0) {
		goto out;
	}

	RRR_DBG_1("python3 instance %s registered method %s from method definition %s\n",
		INSTANCE_D_NAME(data->thread_data), method_name, stack_name);

	out:
	Py_XDECREF(method);
	return ret;
}

int python3_init_wrapper_callback(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	int ret = 0;

	struct python3_data *data = private_arg;
	struct python3_child_data child_data = {0};
	struct python3_method_collection methods = {0};

	const struct rrr_cmodule_config_data *cmodule_config_data = rrr_cmodule_helper_config_data_get(data->thread_data);

	child_data.parent_data = data;

	PyObject *module = NULL;
	PyObject *module_dict = NULL;
	PyObject *py_module_name = NULL;
	PyObject *process_method = NULL;
	PyObject *source_method = NULL;
	PyObject *config_method = NULL;

	struct python3_fork_runtime runtime;

	if (rrr_py_cmodule_runtime_init (
			&runtime,
			worker,
			data->module_path
	) != 0) {
		RRR_MSG_0("Could not initialize python3 runtime in %s\n", __func__);
		ret = 1;
		goto out;
	}

	PyEval_RestoreThread(runtime.istate);


	py_module_name = PyUnicode_FromString(data->python3_module);
	module = PyImport_GetModule(py_module_name);
	if (module == NULL && (module = PyImport_ImportModule(data->python3_module)) == NULL) {
		RRR_MSG_0("Could not import module %s while starting thread:\n", data->python3_module);
		PyErr_Print();
		ret = 1;
		goto out_cleanup_runtime;
	}

	if ((module_dict = PyModule_GetDict(module)) == NULL) { // Borrowed reference
		RRR_MSG_0("Could not get dictionary of module %s while starting thread:\n", data->python3_module);
		PyErr_Print();
		ret = 1;
		goto out_cleanup_runtime;
	}

	if (cmodule_config_data->config_method != NULL) {
		if ((config_method = rrr_py_import_function(module_dict, cmodule_config_data->config_method)) == NULL) {
			RRR_MSG_0("Could not get config function '%s' from module '%s' while starting python3 fork\n",
					cmodule_config_data->config_method, data->python3_module);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

	if (cmodule_config_data->source_method != NULL) {
		if ((source_method = rrr_py_import_function(module_dict, cmodule_config_data->source_method)) == NULL) {
			RRR_MSG_0("Could not get source function '%s' from module '%s' while starting python3 fork\n",
					cmodule_config_data->source_method, data->python3_module);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

	if (cmodule_config_data->process_method != NULL) {
		if ((process_method = rrr_py_import_function(module_dict, cmodule_config_data->process_method)) == NULL) {
			RRR_MSG_0("Could not get process function '%s' from module '%s' while starting python3 fork\n",
					cmodule_config_data->process_method, data->python3_module);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

	struct python3_method_name_callback_data callback_data = {
		data,
		&methods,
		module_dict
	};

	if ((ret = rrr_cmodule_helper_methods_iterate (
			data->thread_data,
			python3_method_name_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed while iterating method names in python3 instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out_cleanup_runtime;
	}

	child_data.runtime = &runtime;
	child_data.config_method = config_method;
	child_data.source_method = source_method;
	child_data.process_method = process_method;
	child_data.methods = &methods;
	callbacks->configuration_callback_arg = &child_data;
	callbacks->process_callback_arg = &child_data;

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			callbacks
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		// Don't goto out, run cleanup functions
	}

	out_cleanup_runtime:
		python3_method_collection_clear(&methods);
		RRR_Py_XDECREF(config_method);
		RRR_Py_XDECREF(process_method);
		RRR_Py_XDECREF(source_method);
		RRR_Py_XDECREF(py_module_name);
		RRR_Py_XDECREF(module);
		PyEval_SaveThread();

		rrr_py_cmodule_runtime_cleanup(&runtime);

	out:
	return ret;
}

struct python3_fork_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	pid_t *fork_pid;
};

static int python3_fork (void *arg) {
	struct python3_fork_callback_data *callback_data = arg;
	struct rrr_instance_runtime_data *thread_data = callback_data->thread_data;
	struct python3_data *data = thread_data->private_data;

	int ret = 0;

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}
	if (rrr_cmodule_helper_parse_config(thread_data, "python3", "function") != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_cmodule_helper_worker_forks_start (
			thread_data,
			python3_init_wrapper_callback,
			data,
			python3_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			python3_process_callback,
			NULL  // <-- in the init wrapper, this callback is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting python3 worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_python3 (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;

	pthread_cleanup_push(data_cleanup, data);

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in python3 instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1("python3 instance %s\n", INSTANCE_D_NAME(thread_data));

	pid_t fork_pid = 0;

	struct python3_fork_callback_data fork_callback_data = {
		thread_data, &fork_pid
	};

	if (rrr_thread_start_condition_helper_fork(thread, python3_fork, &fork_callback_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("python3 instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_loop (
			thread_data
	);

	out_message:
	RRR_DBG_1 ("python3 instance %s exiting\n", INSTANCE_D_NAME(thread_data));

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_python3,
		NULL
};

static const char *module_name = "python3";

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
	RRR_DBG_1 ("Destroy python3 module\n");
}

