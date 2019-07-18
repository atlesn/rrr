/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <stddef.h>
#include <signal.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "settings.h"
#include "messages.h"
#include "python3.h"
#include "../global.h"

/*
 * GIL LOCKING MUST BE HANDLED BY THESE TWO FUNCTIONS, OTHER FUNCTIONS
 * DO NOT LOCK THEMSELVES. ALSO, THESE METHODS ARE NOT THREAD SAFE,
 * MUST ONLY BE USED BY ONE THREAD AT A TIME
 */

pthread_mutex_t rrr_global_tstate_lock = PTHREAD_MUTEX_INITIALIZER;

int python3_swap_thread_in(struct python3_thread_state *python3_thread_ctx, PyThreadState *tstate) {
	int ret = 0;

	PyThreadState *current_tstate = _PyThreadState_UncheckedGet();

	VL_DEBUG_MSG_4 ("Restore thread expected thread active %p actual tstate %p\n",
			tstate, current_tstate);

	if (python3_thread_ctx->tstate == NULL) {
		PyEval_RestoreThread(tstate);
		python3_thread_ctx->tstate = tstate;

		current_tstate = _PyThreadState_UncheckedGet();

		if (current_tstate != python3_thread_ctx->tstate) {
			VL_BUG("After python3 restore thread, current actual thread does not match\n");
		}

		VL_DEBUG_MSG_4 ("Restore thread complete expected thread active %p actual tstate %p\n",
				tstate, current_tstate);
		ret = 0;
	}
	else {
		if (current_tstate != python3_thread_ctx->tstate) {
			VL_BUG("Bug: We are tagged as holding lock already in python3_swap_thread_in but python3 says we do not\n");
		}
		VL_DEBUG_MSG_4 ("Restore did not run\n");
		ret = 1;
	}

	return ret;
}

int python3_swap_thread_out(struct python3_thread_state *tstate_holder) {
	int ret = 0;

	if (tstate_holder->tstate != NULL) {

		PyThreadState *current_tstate = _PyThreadState_UncheckedGet();

		VL_DEBUG_MSG_4 ("Save thread expected thread active %p actual tstate %p\n",
				tstate_holder->tstate, current_tstate);

		// GIL might have switched while inside a python function and
		// pthread_cancel was called. We cannot continue execution after
		// this.
		if (current_tstate != tstate_holder->tstate) {
			VL_MSG_ERR("Critical: Current actual tstate did not match, abort\n");
			return 1;
		}
		else if (PyEval_SaveThread() != tstate_holder->tstate) {
			VL_BUG("Bug: tstates did not match in python3_swap_thread_out\n");
		}

		VL_DEBUG_MSG_4 ("Save thread complete %p actual tstate %p\n",
				tstate_holder->tstate, current_tstate);

		tstate_holder->tstate = NULL;
	}

	return ret;
}

int rrr_py_object_cache_init (struct python3_object_cache *cache, unsigned int max) {
	int ret = 0;

	memset (cache, '\0', sizeof(*cache));

	if (pthread_mutex_init(&cache->lock, NULL) != 0) {
		VL_MSG_ERR("Could not initialize lock in rrr_py_object_cache_new\n");
		ret = RRR_PYTHON3_OBJECT_CACHE_ERR;
	}
	else {
		cache->initialized = 1;
		cache->max = max;
	}

	return ret;
}

void rrr_py_object_cache_destroy (struct python3_object_cache *cache) {
	if (!cache->initialized)
		return;
	struct python3_object_cache_entry *entry = cache->begin;
	while (entry) {
		struct python3_object_cache_entry *next = entry->next;
		Py_XDECREF(entry->object);
		free(entry);
		entry = next;
	}
	pthread_mutex_destroy(&cache->lock);
	cache->begin = NULL;
	cache->initialized = 0;
}

int rrr_py_object_cache_push (struct python3_object_cache *cache, PyObject *object) {
	int ret = RRR_PYTHON3_OBJECT_CACHE_OK;
	int full = 0;

	pthread_mutex_lock(&cache->lock);
	if (cache->entries > cache->max) {
		full = 1;
	}
	pthread_mutex_unlock(&cache->lock);

	if (full) {
		Py_XDECREF(object);
		return RRR_PYTHON3_OBJECT_CACHE_FULL;
	}

	struct python3_object_cache_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_py_object_cache_push\n");
		return RRR_PYTHON3_OBJECT_CACHE_ERR;
	}

	entry->object = object;

	pthread_mutex_lock(&cache->lock);
	entry->next = cache->begin;
	cache->begin = entry;
	cache->entries++;
	pthread_mutex_unlock(&cache->lock);

	return ret;
}

PyObject *rrr_py_object_cache_pop(struct python3_object_cache *cache) {
	struct python3_object_cache_entry *entry = NULL;

	pthread_mutex_lock(&cache->lock);
	if (cache->begin) {
		entry = cache->begin;
		cache->begin = entry->next;
		cache->entries--;
	}
	pthread_mutex_unlock(&cache->lock);

	if (!entry) {
		return NULL;
	}

	PyObject *ret = entry->object;
	free(entry);
	return ret;
}

PyObject *rrr_py_import_object (PyObject *dictionary, const char *symbol) {
	PyObject *res = PyDict_GetItemString(dictionary, symbol);
	Py_XINCREF(res);
	return res;
}

PyObject *rrr_py_import_function (PyObject *dictionary, const char *symbol) {
	PyObject *ret = rrr_py_import_object(dictionary, symbol);

	if (ret == NULL) {
		VL_MSG_ERR("Could not load %s function\n", symbol);
		goto out_err;
	}

	if (!PyCallable_Check(ret)) {
	        VL_MSG_ERR("%s was not a callable\n", symbol);
        	goto out_err_cleanup;
	}

	return ret;

	out_err_cleanup:
	Py_XDECREF(ret);

	out_err:
	return NULL;
}

PyObject *rrr_py_call_function_no_args(PyObject *function) {
	PyObject *args = PyTuple_New(0);
	PyObject *result = PyEval_CallObject(function, args);
	Py_XDECREF(args);
	if (result == NULL) {
		PyErr_Print();
	}
	return result;
}

PyObject *rrr_py_import_and_call_function_no_args(PyObject *dictionary, const char *symbol) {
	PyObject *result = NULL;

	PyObject *function = rrr_py_import_function(dictionary, symbol);
	if (function == NULL) {
		goto out_cleanup;
	}

	PyObject *args = PyTuple_New(0);
	result = PyEval_CallObject(function, args);
	Py_XDECREF(args);
	if (result == NULL) {
		VL_MSG_ERR("NULL result from function %s\n", symbol);
		PyErr_Print();
		goto out_cleanup;
	}

	out_cleanup:
	Py_XDECREF(function);

	return result;
}

int rrr_py_terminate_threads (struct python3_rrr_objects *rrr_objects) {
	int ret = 0;
	PyObject *result = NULL;
	PyObject *arglist = NULL;

	if (rrr_objects->rrr_thread_terminate_all == NULL || rrr_objects->rrr_global_process_dict == NULL) {
		ret = 0;
		goto out;
	}

	arglist = Py_BuildValue("(O)",
			rrr_objects->rrr_global_process_dict
	);

	result = PyObject_CallObject(rrr_objects->rrr_thread_terminate_all, arglist);

	if (result == NULL) {
		PyErr_Print();
		PyObject *exp = NULL;
		if ((exp = PyErr_Occurred()) == NULL) {
			VL_MSG_ERR("Could not run python3 thread terminate function, and could not get exception: \n");
			PyErr_Print();
			ret = 1;
			goto out;
		}
	}

	out:
	Py_XDECREF(result);
	Py_XDECREF(arglist);
	return ret;
}

int __rrr_py_start_persistent_thread (
		PyObject **result_process_pipe,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		PyObject *start_method
) {
	int ret = 0;

	*result_process_pipe = NULL;

	PyObject *arglist = NULL;
	PyObject *process_pipe = NULL;

	VL_DEBUG_MSG_3("Start persistent thread of module %s function %s\n", module_name, function_name);

	arglist = Py_BuildValue("Oss",
			rrr_objects->rrr_global_process_dict,
			module_name,
			function_name
	);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not prepare argument list while calling python3 object asynchronously:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	process_pipe = PyObject_CallObject(start_method, arglist);
	if (process_pipe == NULL) {
		VL_MSG_ERR("Could not run python3 thread starter: \n");
		PyErr_Print();
		ret = 1;
		goto out;
	}
	Py_XDECREF(arglist);

	arglist = Py_BuildValue("O",
			process_pipe
	);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not prepare argument list while calling getters for raw pipes:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	*result_process_pipe = process_pipe;

	out:
	if (ret != 0) {
		Py_XDECREF(process_pipe);
	}
	Py_XDECREF(arglist);
	return ret;
}

int rrr_py_start_persistent_thread (
		PyObject **result_process_pipe,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
) {
	return __rrr_py_start_persistent_thread (
			result_process_pipe,
			rrr_objects,
			module_name,
			function_name,
			rrr_objects->rrr_persistent_thread_start
	);
}

int rrr_py_start_persistent_readonly_thread (
		PyObject **result_process_pipe,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
) {
	return __rrr_py_start_persistent_thread (
			result_process_pipe,
			rrr_objects,
			module_name,
			function_name,
			rrr_objects->rrr_persistent_thread_readonly_start
	);
}

// First element of arglist must be function to call
int rrr_py_call_object_async (
		PyObject **result,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		PyObject *arg
) {
	int ret = 0;

	*result = NULL;

	PyObject *arglist = NULL;
	VL_DEBUG_MSG_3("Async call to module %s function %s\n", module_name, function_name);

	arglist = Py_BuildValue("OssO",
			rrr_objects->rrr_global_process_dict,
			module_name,
			function_name,
			arg
	);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not prepare argument list while calling python3 object asynchronously:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	*result = PyObject_CallObject(rrr_objects->rrr_onetime_thread_start, arglist);
	if (*result == NULL) {
		VL_MSG_ERR("Could not run python3 thread starter: \n");
		PyErr_Print();
		ret = 1;
		abort();
		goto out;
	}

	out:
	Py_XDECREF(arglist);
	return ret;
}

struct rrr_py_settings_iterate_data {
	PyObject *py_rrr_settings;
	struct python3_rrr_objects *rrr_objects;
	void *caller_data;
};

// rrr_setting is locked in this context
int __rrr_py_settings_update_used_callback (struct rrr_setting *setting, void *arg) {
	struct rrr_py_settings_iterate_data *callback_data = arg;
	PyObject *arglist = NULL;
	PyObject *result = NULL;
	int ret = 0;

	arglist = Py_BuildValue("(Os)",
			callback_data->py_rrr_settings,
			setting->name
	);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not generate argument list while checking if setting was used in python3 settings class:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	result = PyObject_CallObject(callback_data->rrr_objects->rrr_settings_check_used, arglist);
	if (result == NULL) {
		VL_MSG_ERR("Could not check python3 settings was used property (1st time): \n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	int was_used = PyLong_AsLong(result);
	if (was_used == -1) {
		VL_MSG_ERR("Could not check python3 settings was used property (2nd time): \n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	if (was_used == 0 && setting->was_used == 1) {
		VL_MSG_ERR("Warning: Was used property of settings %s changed from 1 to 0 after python3 config function\n",
				setting->name);
	}

	setting->was_used = was_used;

	out:
	Py_XDECREF(result);
	Py_XDECREF(arglist);
	return ret;
}

// rrr_setting is locked in this context
int __rrr_py_new_settings_callback (struct rrr_setting *setting, void *arg) {
	struct rrr_py_settings_iterate_data *callback_data = arg;
	PyObject *arglist = NULL;
	PyObject *result = NULL;
	int ret = 0;

	if (RRR_SETTING_IS_UINT(setting)) {
		unsigned long long value;
		if (rrr_settings_setting_to_uint_nolock(&value, setting) != 0) {
			VL_MSG_ERR("Bug: Could not convert unsigned integer to unsigned integer in __rrr_py_new_settings_callback\n");
			exit(EXIT_FAILURE);
		}
		arglist = Py_BuildValue("(OsKi)",
				callback_data->py_rrr_settings,
				setting->name,
				value,
				setting->was_used
		);
	}
	else {
		char *value;
		if (rrr_settings_setting_to_string_nolock(&value, setting) != 0) {
			VL_MSG_ERR("Could not convert setting %s to string while adding to python3 settings class\n", setting->name);
			ret = 1;
			goto out;
		}
		arglist = Py_BuildValue("(Ossi)",
				callback_data->py_rrr_settings,
				setting->name,
				value,
				setting->was_used
		);
		free (value);
	}

	if (arglist == NULL) {
		VL_MSG_ERR("Could not generate argument list while adding setting to python3 settings class:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	result = PyObject_CallObject(callback_data->rrr_objects->rrr_settings_set, arglist);
	if (result == NULL) {
		VL_MSG_ERR("Could not set python3 setting: \n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	out:
	Py_XDECREF(result);
	Py_XDECREF(arglist);
	return ret;
}

int __rrr_py_settings_iterate (
		struct python3_rrr_objects *rrr_objects,
		struct rrr_instance_settings *settings,
		PyObject *py_rrr_settings,
		int (*callback)(struct rrr_setting *setting, void *arg),
		void *caller_data
) {
	struct rrr_py_settings_iterate_data callback_data = { py_rrr_settings, rrr_objects, caller_data };

	return rrr_settings_iterate (
			settings,
			callback,
			&callback_data
	);
}

PyObject *rrr_py_new_settings(struct python3_rrr_objects *rrr_objects, struct rrr_instance_settings *settings) {
	PyObject *py_rrr_settings = NULL;
	int ret = 0;

	py_rrr_settings = rrr_py_call_function_no_args(rrr_objects->rrr_settings_new);
	if (py_rrr_settings == NULL) {
		VL_MSG_ERR("Could not get new python rrr_settings class instance\n");
		ret = 1;
		goto out;
	}

	ret = __rrr_py_settings_iterate  (
			rrr_objects,
			settings,
			py_rrr_settings,
			__rrr_py_new_settings_callback,
			NULL
	);

	out:
	if (ret != 0) {
		Py_XDECREF(py_rrr_settings);
		py_rrr_settings = NULL;
	}

	return py_rrr_settings;
}

int rrr_py_settings_update_used (
		struct python3_rrr_objects *rrr_objects,
		struct rrr_instance_settings *settings,
		PyObject *py_rrr_settings
) {
	return __rrr_py_settings_iterate  (
			rrr_objects,
			settings,
			py_rrr_settings,
			__rrr_py_settings_update_used_callback,
			NULL
	);
}

char dummy_data[MSG_DATA_MAX_LENGTH] = "a";
PyObject *rrr_py_new_empty_message (struct python3_rrr_objects *rrr_objects) {
	PyObject *ret = NULL;
	PyObject *binary_data = NULL;
	PyObject *arglist = NULL;

	if (*dummy_data == 'a') {
		memset(dummy_data, 'a', sizeof(dummy_data) - 1);
		dummy_data[sizeof(dummy_data)-1] = '\0';
	}

	binary_data = PyByteArray_FromStringAndSize(dummy_data, sizeof(dummy_data));
	if (binary_data == NULL) {
		VL_MSG_ERR("Could not create python3 binary data: \n");
		PyErr_Print();
		goto out;
	}

	arglist = Py_BuildValue("(kkKKKkO)",
			0,
			0,
			0,
			0,
			0,
			0,
			binary_data
	);

	int res = rrr_py_call_object_async(&ret, rrr_objects, "rrr_objects", "vl_message_new", arglist);
	if (res != 0) {
		VL_MSG_ERR("Could not create python3 message object: \n");
		PyErr_Print();
		goto out;
	}

	out:
	Py_XDECREF(arglist);
	Py_XDECREF(binary_data);
	return ret;
}

PyObject *__rrr_py_message_new_arglist(const struct vl_message *message) {
	PyObject *binary_data = NULL;
	PyObject *arglist = NULL;

	binary_data = PyByteArray_FromStringAndSize(message->data, message->length);
	if (binary_data == NULL) {
		VL_MSG_ERR("Could not create python3 binary data: \n");
		PyErr_Print();
		goto out;
	}

	arglist = Py_BuildValue("kkKKKkO",
			message->type,
			message->class,
			message->timestamp_from,
			message->timestamp_to,
			message->data_numeric,
			message->length,
			binary_data
	);

	out:
	Py_XDECREF(binary_data);
	return arglist;
}

PyObject *rrr_py_new_message (struct python3_rrr_objects *rrr_objects, const struct vl_message *message) {
	PyObject *ret = NULL;
	PyObject *arglist = NULL;

	if ((arglist = __rrr_py_message_new_arglist(message)) == NULL) {
		goto out;
	}

	int res = rrr_py_call_object_async(&ret, rrr_objects, "rrr_objects", "vl_message_new", arglist);
	if (res != 0) {
		VL_MSG_ERR("Could not create python3 message object in rrr_py_new_message: \n");
		PyErr_Print();
		goto out;
	}

	out:
	Py_XDECREF(arglist);
	return ret;
}

int rrr_py_message_to_internal(struct vl_message **target, PyObject *py_message) {
	int ret = 0;

	PyObject *type = NULL;
	PyObject *class = NULL;
	PyObject *timestamp_from = NULL;
	PyObject *timestamp_to = NULL;
	PyObject *data_numeric = NULL;
	PyObject *length = NULL;
	PyObject *data = NULL;

	*target = NULL;

	if (strcmp(Py_TYPE(py_message)->tp_name, "vl_message") != 0) {
		VL_MSG_ERR("Bug: rrr_py_message_to_internal was called with wrong object type '%s'\n", Py_TYPE(py_message)->tp_name);
		exit (EXIT_FAILURE);
	}

	struct vl_message *result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_py_message_to_internal\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	type = PyObject_GetAttrString(py_message, "type");
	class = PyObject_GetAttrString(py_message, "m_class");
	timestamp_from = PyObject_GetAttrString(py_message, "timestamp_from");
	timestamp_to = PyObject_GetAttrString(py_message, "timestamp_to");
	data_numeric  = PyObject_GetAttrString(py_message, "data_numeric");
	length = PyObject_GetAttrString(py_message, "length");
	data = PyObject_GetAttrString(py_message, "data");

	if (type == NULL ||
		class == NULL ||
		timestamp_from == NULL ||
		timestamp_to == NULL ||
		data_numeric == NULL ||
		length == NULL ||
		data == NULL
	) {
		VL_MSG_ERR("Could not find all required paramenters in python3 vl_message struct\n");
		ret = 1;
		goto out;
	}

	if (!PyByteArray_Check(data)) {
		VL_MSG_ERR("Returned data in returned message from python3 process function was not a byte array\n");
		ret = 1;
		goto out;
	}

	Py_ssize_t returned_length = PyByteArray_Size(data);
	if (returned_length > MSG_DATA_MAX_LENGTH) {
		VL_MSG_ERR("Returned length of data field was too large (returned: %li, required: <=%i)",
				returned_length, MSG_DATA_MAX_LENGTH);
		ret = 1;
		goto out;
	}

	char *returned_bytes = PyByteArray_AsString(data);
	memcpy(result->data, returned_bytes, returned_length);

	result->type = PyLong_AsUnsignedLong(type);
	result->class = PyLong_AsUnsignedLong(class);
	result->timestamp_from = PyLong_AsUnsignedLongLong(timestamp_from);
	result->timestamp_to = PyLong_AsUnsignedLongLong(timestamp_to);
	result->data_numeric = PyLong_AsUnsignedLongLong(data_numeric);
	result->length = PyLong_AsUnsignedLong(length);

	out:
	if (ret == 0) {
		*target = result;
	}
	else {
		RRR_FREE_IF_NOT_NULL(result);
	}

	Py_XDECREF(type);
	Py_XDECREF(class);
	Py_XDECREF(timestamp_from);
	Py_XDECREF(timestamp_to);
	Py_XDECREF(data_numeric);
	Py_XDECREF(length);
	Py_XDECREF(data);

	return ret;
}

int rrr_py_persistent_receive_message (
		int *pending_counter,
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		int (*callback)(PyObject *message, void *arg),
		void *callback_arg
) {
	int ret = 0;

	VL_DEBUG_MSG_3("rrr_py_persistent_receive_message getting message\n");

	PyObject *res = NULL;
//	PyObject *arglist = NULL;

	/*arglist = Py_BuildValue("(O)",
			processor_pipe
	);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not prepare argument list in rrr_py_persistent_receive_message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}*/

	int do_continue = 1;
	while (do_continue) {
		PYTHON3_PROFILE_START(recv_data,rrr_objects->accumulated_time_recv_message_nonblock);
		res = PyObject_CallFunction(rrr_objects->rrr_persistent_thread_recv_data_nonblock, "O", processor_pipe);
		if (res == NULL) {
			PyObject *exc = PyErr_Occurred();
			if (exc) {
				printf ("%s\n", Py_TYPE(exc)->tp_name);
			}
			VL_MSG_ERR("Could not run python3 rrr_persistent_thread_recv_data_nonblock: \n");
			PyErr_Print();
			ret = 1;
			goto out;
		}

		PYTHON3_PROFILE_STOP(recv_data);

//		VL_DEBUG_MSG_3("rrr_py_process_message received an object of type %s from process function\n", Py_TYPE(res)->tp_name);

		if (strcmp(Py_TYPE(res)->tp_name, "vl_message") == 0) {
			ret = callback (res, callback_arg);
			res = NULL;
			(*pending_counter)--;
		}
		else if (strcmp(Py_TYPE(res)->tp_name, "NoneType") == 0) {
			do_continue = 0;
		}
		else {
			VL_BUG("Bug: rrr_persistent_thread_recv_data received an object of unknown type back from process function\n");
		}
		Py_XDECREF(res);
	//	Py_XDECREF(arglist);
		res = NULL;
	}

	out:
	Py_XDECREF(res);
//	Py_XDECREF(arglist);
	return ret;
}

int rrr_py_persistent_process_data (
		PyObject *method,
		PyObject *processor_pipe,
		PyObject *arglist
) {
	int ret = 0;
	PyObject *arglist_new = NULL;
	PyObject *res = NULL;

	arglist_new = Py_BuildValue("(OO)",
			processor_pipe,
			arglist
	);

	if (arglist_new == NULL) {
		VL_MSG_ERR("Could not prepare argument list in rrr_py_persistent_receive_message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}


	res = PyObject_CallObject(method, arglist_new);
	if (res == NULL) {
		VL_MSG_ERR("Could not run python3 rrr_persistent_thread_send_data: \n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	out:
	Py_XDECREF(res);
	Py_XDECREF(arglist_new);
	return ret;
}

int rrr_py_persistent_readonly_send_counter (
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		int count
) {
	int ret = 0;
	PyObject *counter = NULL;
	PyObject *res = NULL;

	counter = PyLong_FromLong(count);
	if (counter == NULL) {
		VL_MSG_ERR("Could not convert long to PyLong in rr_py_persistent_readonly_send_counter:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	res = PyObject_CallFunction(rrr_objects->rrr_persistent_thread_send_data, "OO", processor_pipe, counter);
	if (res == NULL) {
		VL_MSG_ERR("Could not call python function in rr_py_persistent_readonly_send_counter:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	out:
	Py_XDECREF(res);
	Py_XDECREF(counter);
	return ret;
}

int rrr_py_persistent_process_message (
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		PyObject *message
) {
	int ret = 0;

	VL_DEBUG_MSG_3("rrr_py_persistent_process_message processing message\n");

	if (message == NULL || processor_pipe == NULL) {
		VL_BUG("Bug: Message or processor pipe was NULL in rrr_py_persistent_process_message\n");
	}

	ret = rrr_py_persistent_process_data (rrr_objects->rrr_persistent_thread_send_data, processor_pipe, message);
	if (ret != 0) {
		VL_MSG_ERR("Could not process new python3 message object in rrr_py_persistent_process_message\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_py_persistent_process_new_messages (
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		struct vl_message *messages[RRR_PERSISTENT_PROCESS_INPUT_MAX],
		int count
) {
	int ret = 0;
	PyObject *arglist = NULL;
	PyObject *message_arglist = NULL;
	PyObject *pycount = NULL;

	if (count == 0) {
		goto out;
	}

	arglist = PyTuple_New(count + 2);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not create PyTuple in rrr_py_persistent_process_new_message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	pycount = PyLong_FromLong(count);
	if (pycount == NULL) {
		VL_MSG_ERR("Could not create PyLong in rrr_py_persistent_process_new_message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	ret = PyTuple_SetItem(arglist, 0, processor_pipe); // Steals reference to processor_pipe
	if (ret != 0) {
		VL_MSG_ERR("Could not set PyTuple item in rrr_py_persistent_process_new_message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}
	Py_INCREF(processor_pipe);

	ret = PyTuple_SetItem(arglist, 1, pycount); // Steals reference to pycount
	if (ret != 0) {
		VL_MSG_ERR("Could not set PyTuple item in rrr_py_persistent_process_new_message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}
	Py_INCREF(pycount);


	for (int i = 0; i < count; i++) {
		message_arglist = __rrr_py_message_new_arglist(messages[i]);
		if (message_arglist == NULL) {
			VL_MSG_ERR("Could not create message argument list in rrr_py_persistent_process_new_message:\n");
			PyErr_Print();
			ret = 1;
			goto out;
		}

		ret = PyTuple_SetItem(arglist, i + 2, message_arglist); // Steals reference to message_arglist
		if (ret != 0) {
			VL_MSG_ERR("Could not set PyTuple item in rrr_py_persistent_process_new_message:\n");
			PyErr_Print();
			ret = 1;
			goto out;
		}
		message_arglist = NULL;
	}

	ret = rrr_py_persistent_process_data(rrr_objects->rrr_persistent_thread_send_new_vl_message, processor_pipe, arglist);
	if (ret != 0) {
		VL_MSG_ERR("Could not process new python3 message object in rrr_py_persistent_process_new_message\n");
		goto out;
	}

	out:
	Py_XDECREF(message_arglist);
	Py_XDECREF(arglist);;
	Py_XDECREF(pycount);
	return ret;
}

void rrr_py_destroy_rrr_objects (struct python3_rrr_objects *rrr_objects) {
	Py_XDECREF(rrr_objects->rrr_settings_class);
	Py_XDECREF(rrr_objects->rrr_settings_get);
	Py_XDECREF(rrr_objects->rrr_settings_set);
	Py_XDECREF(rrr_objects->rrr_settings_check_used);
	Py_XDECREF(rrr_objects->rrr_settings_new);

	Py_XDECREF(rrr_objects->rrr_global_process_dict);

	Py_XDECREF(rrr_objects->rrr_onetime_thread_start);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_start);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_readonly_start);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_send_data);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_send_new_vl_message);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_recv_data);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_recv_data_nonblock);
	Py_XDECREF(rrr_objects->rrr_thread_terminate_all);

	Py_XDECREF(rrr_objects->vl_message_class);
	Py_XDECREF(rrr_objects->vl_message_new);

	memset (rrr_objects, '\0', sizeof(*rrr_objects));
}

int __rrr_py_import_function_or_print_error(PyObject **target, PyObject *dictionary, const char *name) {
	*target = NULL;
	PyObject *res = rrr_py_import_function(dictionary, name);
	if (res == NULL) {
		VL_MSG_ERR("Could not find %s function: \n", name);
		PyErr_Print();
		return 1;
	}
	*target = res;
	return 0;
}

#define IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, function, error) \
		do {if (__rrr_py_import_function_or_print_error(&(target->function), dictionary, #function) != 0) { \
			error = 1; \
			goto out; \
		}} while(0)

int rrr_py_get_rrr_objects (struct python3_rrr_objects *target, PyObject *dictionary) {
	PyObject *res = NULL;
	PyObject *settings_class_dictionary = NULL;
	FILE *file = NULL;
	char *rrr_py_start_thread_final = NULL;
	int ret = 0;

	file = fopen("rrr_objects.py", "r");
	if (file == NULL) {
		VL_MSG_ERR("Could not open rrr_objects.py: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	res = PyRun_FileExFlags (file, "rrr_objects.py", Py_file_input, dictionary, dictionary, 1, NULL);
	if (res == NULL) {
		VL_MSG_ERR("Could generate import thread starter function A: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	Py_XDECREF(res);

	const char *rrr_py_start_thread_template =
			"import sys\n"
			"sys.path.append('.')\n"
			"import rrr_objects\n"
			"rrr_global_process_dict = rrr_process_dict()\n"
			"pipe_dummy, pipe_dummy_b = Pipe()\n"
	;

	rrr_py_start_thread_final = malloc(strlen(rrr_py_start_thread_template) + 1);
	strcpy(rrr_py_start_thread_final, rrr_py_start_thread_template);

	memset (target, '\0', sizeof(*target));

	res = PyRun_String(rrr_py_start_thread_final, Py_file_input, dictionary, dictionary);
	if (res == NULL) {
		VL_MSG_ERR("Could run import sys: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	Py_XDECREF(res);

	// IMPORT RESULT QUEUE OBJECT
	res = rrr_py_import_object(dictionary, "rrr_global_process_dict");
	if (res == NULL) {
		VL_MSG_ERR("Could not find rrr_global_process_dict object: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->rrr_global_process_dict = res;

	// IMPORT SETTINGS OBJECT
	res = rrr_py_import_object(dictionary, "rrr_instance_settings");
	if (res == NULL) {
		VL_MSG_ERR("Could not find rrr_instance_settings class: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->rrr_settings_class = res;

	settings_class_dictionary = PyObject_GenericGetDict(target->rrr_settings_class, NULL);
	if (settings_class_dictionary == NULL) {
		VL_MSG_ERR("Could not get dictionary of rrr_instance_settings class: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}

	res = rrr_py_import_function(settings_class_dictionary, "get");
	if (res == NULL) {
		VL_MSG_ERR("Could not find rrr_settings_class.get function: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->rrr_settings_get = res;

	res = rrr_py_import_function(settings_class_dictionary, "set");
	if (res == NULL) {
		VL_MSG_ERR("Could not find rrr_settings_class.set function: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->rrr_settings_set = res;

	res = rrr_py_import_function(settings_class_dictionary, "check_used");
	if (res == NULL) {
		VL_MSG_ERR("Could not find rrr_settings_class.check_used function: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->rrr_settings_check_used = res;

	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_settings_new, ret);

	// IMPORT THREAD FUNCTIONS
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_onetime_thread_start, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_start, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_readonly_start, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_send_data, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_send_new_vl_message, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_recv_data, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_recv_data_nonblock, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_thread_terminate_all, ret);

	// IMPORT MESSAGE OBJECT
	res = rrr_py_import_object(dictionary, "vl_message");
	if (res == NULL) {
		VL_MSG_ERR("Could not find vl_message class: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->vl_message_class = res;

	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, vl_message_new, ret);

	out:
	RRR_FREE_IF_NOT_NULL(rrr_py_start_thread_final);
	Py_XDECREF(settings_class_dictionary);
	if (ret != 0) {
		rrr_py_destroy_rrr_objects(target);
	}

	return ret;
}
