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
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "python3_socket.h"
#include "python3_common.h"
#include "python3_setting.h"
#include "python3_vl_message.h"
#include "python3_module.h"
#include "settings.h"
#include "rrr_socket.h"
#include "python3.h"
#include "../global.h"

//static PyThreadState *main_tstate = NULL;
static pthread_mutex_t main_python_lock = PTHREAD_MUTEX_INITIALIZER;
static PyThreadState *main_python_tstate = NULL;
static int python_users = 0;

/*
 * GIL LOCKING MUST BE HANDLED BY THESE TWO FUNCTIONS
 */

//pthread_mutex_t rrr_global_tstate_lock = PTHREAD_MUTEX_INITIALIZER;

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

int rrr_py_terminate_threads (struct python3_rrr_objects *rrr_objects) {
	int ret = 0;

	int count = 0;

	struct python3_fork *fork = rrr_objects->first_fork;
	while (fork != NULL) {
		kill(fork->pid, SIGTERM);
		fork = fork->next;
	}
	usleep(100000);
	while (fork != NULL) {
		struct python3_fork *next = fork->next;

		Py_XDECREF(fork->socket_child);
		Py_XDECREF(fork->socket_main);

		kill(fork->pid, SIGKILL);

		free(fork);

		fork = next;
		count++;
	}

	rrr_objects->first_fork = NULL;

	VL_MSG_DEBUG_1("Killed %i threads in python3 terminate threads\n", count);

	return 0;
}

static struct python3_fork *rrr_py_fork_new (struct python3_rrr_objects *rrr_objects) {
	struct python3_fork *ret = malloc(sizeof(*ret));
	PyObject *socket_main = NULL;
	PyObject *socket_child = NULL;

	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_py_fork_new\n");
		return NULL;
	}

	memset(ret, '\0', sizeof(*ret));

	socket_main = rrr_python3_socket_new(NULL);
	if (socket_main == NULL) {
		VL_MSG_ERR("Could not create socket in rrr_py_fork_new\n");
		goto err;
	}

	socket_child = rrr_python3_socket_new(rrr_python3_socket_get_filename(socket_main));
	if (socket_child == NULL) {
		VL_MSG_ERR("Could not create socket in rrr_py_fork_new\n");
		goto err;
	}

	ret->socket_main = socket_main;
	ret->socket_child = socket_child;

	if (rrr_objects->first_fork == NULL) {
		rrr_objects->first_fork = ret;
	}
	else {
		ret->next = rrr_objects->first_fork;
		rrr_objects->first_fork = ret;
	}

	return 0;

	err:
	Py_XDECREF(socket_main);
	Py_XDECREF(socket_child);
	RRR_FREE_IF_NOT_NULL(ret);

	return 1;
}

static void rrr_py_fork_destroy (struct python3_rrr_objects *rrr_objects, struct python3_fork *fork) {
	if (fork == NULL) {
		return;
	}

	if (fork->pid > 0) {
		kill(fork->pid, SIGTERM);
	}

	Py_XDECREF(fork->socket_main);
	Py_XDECREF(fork->socket_child);

	if (rrr_objects->first_fork == fork) {
		rrr_objects->first_fork = fork->next;
		goto found;
	}
	else {
		for (struct python3_fork *test = rrr_objects->first_fork; test != NULL; test = test->next) {
			if (test->next == fork) {
				test->next = fork->next;
				goto found;
			}
		}
	}

	VL_BUG("Bug: Fork not found in rrr_py_fork_destroy\n");

	found:
	free(fork);
}

PyObject *__rrr_py_socket_message_to_pyobject (struct rrr_socket_msg *message) {
	PyObject *ret = NULL;
	if (RRR_SOCKET_MSG_IS_VL_MESSAGE(message)) {
		ret = rrr_python3_vl_message_new_from_message (message);
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message)) {
		ret = rrr_python3_setting_new_from_setting (message);
	}
	else {
		VL_MSG_ERR("Unsupported socket message type %u received in __rrr_py_socket_message_to_pyobject\n", message->msg_type);
		goto out;
	}

	out:
	return ret;
}

void __rrr_py_start_onetime_thread_rw_child (PyObject *function, struct python3_fork *fork) {
	PyObject *socket = fork->socket_child;

	PyObject *result = NULL;
	struct rrr_socket_msg *messages = NULL;
	Py_ssize_t messages_length = 0;

	int ret = 0;
	while (messages_length == 0) {
		ret = fork->recv(&messages, &messages_length, socket);
		if (ret != 0) {
			VL_MSG_ERR("Error from python3 socket receive function in child\n");
			ret = 1;
			goto out;
		}
		if (messages_length == 1) {
			break;
		}
		else if (messages_length > 1) {
			VL_MSG_ERR("Warning: Received %li messages in python3 onetime thread, expected one only. The rest will be discarded.\n", messages_length);
			break;
		}
	}

	PyObject *arg = __rrr_py_socket_message_to_pyobject(&messages[0]);
	if (arg == NULL) {
		VL_MSG_ERR("Unknown message type received in __rrr_py_start_onetime_thread_rw_child\n");
		ret = 1;
		goto out;
	}

	result = PyObject_CallFunctionObjArgs(function, arg, NULL);
	if (!PyObject_IsTrue(result)) {
		VL_MSG_ERR("Non-true returned from python3 message process function\n");
		ret = 1;
		goto out;
	}

	out:
	Py_XDECREF(arg);
	Py_XDECREF(result);
	Py_XDECREF(socket);
	if (VL_DEBUGLEVEL_1 || ret != 0) {
		VL_DEBUG_MSG("Pytohn3 child process exiting with return value %i\n", ret);
	}
}

void __rrr_py_start_persistent_thread_rw_child (PyObject *function, struct python3_fork *fork) {
	PyObject *socket = fork->socket_child;

	PyObject *result = NULL;
	PyObject *arg = NULL;
	struct rrr_socket_msg *messages = NULL;
	Py_ssize_t messages_length = 0;

	int ret = 0;
	while (1) {
		ret = fork->recv(&messages, &messages_length, socket);
		if (ret != 0) {
			VL_MSG_ERR("Error from socket receive function in python3 child process\n");
			goto out;
		}
		for (int i = 0; i < messages_length; i++) {
			arg = __rrr_py_socket_message_to_pyobject(&messages[0]);
			if (arg == NULL) {
				VL_MSG_ERR("Unknown message type received in __rrr_py_start_persistent_thread_rw_child\n");
				ret = 1;
				goto out;
			}
			result = PyObject_CallFunctionObjArgs(function, arg, NULL);
			if (!PyObject_IsTrue(result)) {
				VL_MSG_ERR("Non-true returned from python3 message process function\n");
				ret = 1;
				goto out;
			}
			Py_XDECREF(result);
			Py_XDECREF(arg);
			result = NULL;
			arg = NULL;
		}
	}

	out:
	Py_XDECREF(result);
	Py_XDECREF(arg);
	Py_XDECREF(socket);
	if (VL_DEBUGLEVEL_1 || ret != 0) {
		VL_DEBUG_MSG("Pytohn3 child process exiting with return value %i\n", ret);
	}
}

void __rrr_py_start_persistent_thread_ro_child (PyObject *function, struct python3_fork *fork) {
	PyObject *socket = fork->socket_child;
	PyObject *result = NULL;

	int ret = 0;
	while (1) {
		result = PyObject_CallFunctionObjArgs(function, socket, NULL);
		if (PyObject_IsTrue(result)) {
			VL_MSG_ERR("Non-true returned from python3 message process function\n");
			goto out;
		}
		Py_XDECREF(result);
	}

	out:
	Py_XDECREF(result);
	Py_XDECREF(socket);
	if (VL_DEBUGLEVEL_1 || ret != 0) {
		VL_DEBUG_MSG("Pytohn3 child process exiting with return value %i\n", ret);
	}
}

static pid_t __rrr_py_fork_intermediate (
		PyObject *function,
		struct python3_fork *fork_data,
		void (*child_method)(PyObject *function, struct python3_fork *fork)
) {
	pid_t ret = 0;

	PyOS_BeforeFork();
	ret = fork();

	if (ret == 0) {
		goto child;
	}
	else {
		PyOS_AfterFork_Parent();
		if (ret < 0) {
			VL_MSG_ERR("Could not fork python3: %s\n", strerror(errno));
		}
		goto out_main;
	}

	child:
	PyOS_AfterFork_Child();

	child_method(function, fork_data);

	exit(ret);

	out_main:
	return ret;
}

static int __rrr_py_start_onetime_rw_thread_intermediate (
		PyObject *function,
		struct python3_fork *fork
) {
	int ret = 0;

	fork->poll = rrr_python3_socket_poll;
	fork->send = rrr_python3_socket_send;
	fork->recv = rrr_python3_socket_recv;

	pid_t pid = __rrr_py_fork_intermediate (
			function,
			fork,
			__rrr_py_start_onetime_thread_rw_child
	);

	if (pid < 1) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_py_start_persistent_rw_thread_intermediate (
		PyObject *function,
		struct python3_fork *fork
) {
	int ret = 0;

	fork->poll = rrr_python3_socket_poll;
	fork->send = rrr_python3_socket_send;
	fork->recv = rrr_python3_socket_recv;

	pid_t pid = __rrr_py_fork_intermediate (
			function,
			fork,
			__rrr_py_start_persistent_thread_rw_child
	);

	if (pid < 1) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_py_start_persistent_ro_thread_intermediate (
		PyObject *function,
		struct python3_fork *fork
) {
	int ret = 0;

	// The child should only have access to send()
	fork->poll = NULL;
	fork->send = rrr_python3_socket_send;
	fork->recv = NULL;

	pid_t pid = __rrr_py_fork_intermediate (
			function,
			fork,
			__rrr_py_start_persistent_thread_ro_child
	);

	// Alter the fork struct so that main does not have access to send()
	fork->poll = rrr_python3_socket_poll;
	fork->send = NULL;
	fork->recv = rrr_python3_socket_recv;

	if (pid < 1) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_py_start_thread (
		struct python3_fork **result_fork,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		int (*start_method)(PyObject *function, struct python3_fork *fork)
) {
	int ret = 0;

	pid_t pid = 0;
	PyObject *module = NULL;
	PyObject *module_dict = NULL;
	PyObject *function = NULL;
	struct python3_fork *fork = NULL;

	*result_fork = NULL;
	VL_DEBUG_MSG_3("Start thread of module %s function %s\n", module_name, function_name);

	fork = rrr_py_fork_new(rrr_objects);
	if (fork == NULL) {
		VL_MSG_ERR("Could not start thread.\n");
		ret = 1;
		goto out;
	}

	if ((module = PyImport_ImportModule(module_name)) == NULL) {
		VL_MSG_ERR("Could not import module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out;
	}

	if ((module_dict = PyModule_GetDict(module)) == NULL) {
		VL_MSG_ERR("Could not get dictionary of module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out;
	}

	if ((function = rrr_py_import_function(module_dict, function_name)) != NULL) {
		VL_MSG_ERR("Could not get function %s from module %s while starting thread\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	if ((pid = start_method(function, fork)) < 1) {
		VL_MSG_ERR("Could not fork python3 with function %s from %s\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	*result_fork = fork;

	out:
	Py_XDECREF(function);
	Py_XDECREF(module_dict);
	Py_XDECREF(module);
	if (ret != 0) {
		rrr_py_fork_destroy(rrr_objects, fork);
	}
	return ret;
}

int rrr_py_start_persistent_rw_thread (
		struct python3_fork **result_fork,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
) {
	return __rrr_py_start_thread (
			result_fork,
			rrr_objects,
			module_name,
			function_name,
			__rrr_py_start_persistent_rw_thread_intermediate
	);
}

int rrr_py_start_persistent_ro_thread (
		struct python3_fork **result_fork,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
) {
	return __rrr_py_start_thread (
			result_fork,
			rrr_objects,
			module_name,
			function_name,
			__rrr_py_start_persistent_ro_thread_intermediate
	);
}

// First element of arglist must be function to call
int rrr_py_start_onetime_rw_thread (
		struct rrr_socket_msg **result,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		struct rrr_socket_msg *arg
) {
	int ret = 0;
	struct python3_fork *fork = NULL;
	struct rrr_socket_msg *messages = NULL;
	Py_ssize_t message_count = 0;

	*result = NULL;

	ret = __rrr_py_start_thread (
			&fork,
			rrr_objects,
			module_name,
			function_name,
			__rrr_py_start_onetime_rw_thread_intermediate
	);

	if (ret != 0) {
		VL_MSG_ERR("Could not start onetime read-write thread with function %s from module %s\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	ret = fork->send(fork->socket_main, arg);
	if (ret != 0) {
		VL_MSG_ERR("Could send message to read-write thread with function %s from module %s\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	ret = fork->recv(&messages, &message_count, fork->socket_main);
	if (ret != 0) {
		VL_MSG_ERR("Could receive message from read-write thread with function %s from module %s\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	if (message_count != 1) {
		VL_BUG("Did not receive exactly one message in rrr_py_start_onetime_rw_thread from function %s from module %s\n",
				function_name, module_name);
	}

	*result = &messages[0];

	out:
	if (ret != 0) {
		RRR_FREE_IF_NOT_NULL(messages);
	}
	rrr_py_fork_destroy(rrr_objects, fork);
	return ret;
}
/*
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
*/
int rrr_py_persistent_receive_message (
		struct python3_fork *fork,
		int (*callback)(const struct rrr_socket_msg *message, void *arg),
		void *callback_arg
) {
	int ret = 0;

	VL_DEBUG_MSG_3("rrr_py_persistent_receive_message getting message\n");

	PyObject *res = NULL;

	struct rrr_socket_msg *messages = NULL;
	Py_ssize_t message_count;

	while (1) {
		ret = fork->recv(&messages, &message_count, fork->socket_main);
		if (ret != 0) {
			VL_MSG_ERR("Error while receiving message from python3 child\n");
			ret = 1;
			goto out;
		}
		for (int i = 0; i < message_count; i++) {
			ret = callback(&messages[i], callback_arg);
			if (ret != 0) {
				VL_MSG_ERR("Error from callback function while receiving message from python3 child\n");
				ret = 1;
				goto out;
			}
		}
		RRR_FREE_IF_NOT_NULL(messages);
	}

	out:
	RRR_FREE_IF_NOT_NULL(messages);
	Py_XDECREF(res);
	return ret;
}

int rrr_py_persistent_process_message (
		struct python3_fork *fork,
		struct rrr_socket_msg *message
) {
	int ret = 0;

	VL_DEBUG_MSG_3("rrr_py_persistent_process_message processing message\n");

	ret = fork->send(fork->socket_main, message);
	if (ret != 0) {
		VL_MSG_ERR("Could not process new python3 message object in rrr_py_persistent_process_message\n");
		goto out;
	}

	out:
	return ret;
}

void rrr_py_destroy_rrr_objects (struct python3_rrr_objects *rrr_objects) {
/*	Py_XDECREF(rrr_objects->rrr_settings_class);
	Py_XDECREF(rrr_objects->rrr_settings_get);
	Py_XDECREF(rrr_objects->rrr_settings_set);
	Py_XDECREF(rrr_objects->rrr_settings_check_used);
	Py_XDECREF(rrr_objects->rrr_settings_new);

	Py_XDECREF(rrr_objects->rrr_onetime_thread_start);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_start);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_readonly_start);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_send_data);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_send_new_vl_message);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_recv_data);
	Py_XDECREF(rrr_objects->rrr_persistent_thread_recv_data_nonblock);
	Py_XDECREF(rrr_objects->rrr_thread_terminate_all);

	Py_XDECREF(rrr_objects->vl_message_class);
	Py_XDECREF(rrr_objects->vl_message_new);*/

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

int rrr_py_get_rrr_objects (
		struct python3_rrr_objects *target,
		PyObject *dictionary,
		const char **extra_module_paths,
		int module_paths_length
) {
	PyObject *res = NULL;
	PyObject *settings_class_dictionary = NULL;
	char *rrr_py_import_final = NULL;
	int ret = 0;

	// FIX IMPORT PATHS AND IMPORT STUFF. INITIALIZE GLOBAL OBJECTS.
	int module_paths_total_size = 0;
	for (int i = 0; i < module_paths_length; i++) {
		module_paths_total_size += strlen(extra_module_paths[i]) + strlen("sys.path.append('')\n");
	}

	char extra_module_paths_concat[module_paths_total_size+1];
	*extra_module_paths_concat = '\0';
	for (int i = 0; i < module_paths_length; i++) {
		sprintf(extra_module_paths_concat + strlen(extra_module_paths_concat), "sys.path.append('%s')\n", extra_module_paths[i]);
	}

	// RUN STARTUP CODE
	const char *rrr_py_import_template =
			"import sys\n"
#ifdef RRR_PYTHON3_EXTRA_SYS_PATH
			"sys.path.append('.')\n"
			"sys.path.append('" RRR_PYTHON3_EXTRA_SYS_PATH "')\n"
			"sys.path.append('" RRR_PYTHON3_EXTRA_SYS_PATH "/src/python')\n"
			"sys.path.append('" RRR_PYTHON3_EXTRA_SYS_PATH "/src/tests')\n"
#endif /* RRR_PYTHON3_EXTRA_SYS_PATH */
#ifdef RRR_PYTHON3_PKGDIR
			"sys.path.append('" RRR_PYTHON3_PKGDIR "')\n"
#endif /* RRR_PYTHON3_PKGDIR */
#ifdef RRR_PYTHON3_SITE_PACKAGES_DIR
			"sys.path.append('" RRR_PYTHON3_SITE_PACKAGES_DIR "')\n"
#endif /* RRR_PYTHON3_PKGDIR */
			"%s"
//			"from rrr import *\n"
			"import rrr_helper\n"
			"from rrr_helper import *\n"
	;

	rrr_py_import_final = malloc(strlen(rrr_py_import_template) + strlen(extra_module_paths_concat) + 1);
	sprintf(rrr_py_import_final, rrr_py_import_template, extra_module_paths_concat);

	memset (target, '\0', sizeof(*target));

	res = PyRun_String(rrr_py_import_final, Py_file_input, dictionary, dictionary);
	if (res == NULL) {
		VL_MSG_ERR("Could not run initial python3 code to set up RRR environment: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	Py_XDECREF(res);

	// DEBUG
	if (VL_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING RRR HELPER MODULE ==============================\n");
		rrr_python3_module_dump_dict_keys();
		printf ("=== PYTHON3 DUMPING RRR HELPER MODULE END ==========================\n\n");
	}

	if (VL_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING GLOBAL MODULES =================================\n");
		rrr_py_dump_global_modules();
		printf ("=== PYTHON3 DUMPING GLOBAL MODULES END =============================\n\n");
	}

	// IMPORT RESULT QUEUE OBJECT
/*	res = rrr_py_import_object(dictionary, "rrr_global_process_dict");
	if (res == NULL) {
		VL_MSG_ERR("Could not find rrr_global_process_dict object: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->rrr_global_process_dict = res;*/

	// IMPORT SETTINGS OBJECT
/*	res = rrr_py_import_object(dictionary, "rrr_instance_settings");
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

	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_settings_new, ret);*/

	// IMPORT THREAD FUNCTIONS
/*	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_onetime_thread_start, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_start, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_readonly_start, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_send_data, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_send_new_vl_message, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_recv_data, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_persistent_thread_recv_data_nonblock, ret);
	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, rrr_thread_terminate_all, ret);*/

	// IMPORT MESSAGE OBJECT
/*	res = rrr_py_import_object(dictionary, "vl_message");
	if (res == NULL) {
		VL_MSG_ERR("Could not find vl_message class: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->vl_message_class = res;

	IMPORT_FUNCTION_OR_GOTO_OUT(target, dictionary, vl_message_new, ret);
*/
	out:
	RRR_FREE_IF_NOT_NULL(rrr_py_import_final);
//	Py_XDECREF(settings_class_dictionary);
	if (ret != 0) {
		rrr_py_destroy_rrr_objects(target);
	}

	return ret;
}

void __rrr_py_global_lock(void) {
	pthread_mutex_lock(&main_python_lock);
}

void __rrr_py_global_unlock(void *dummy) {
	(void)(dummy);
	pthread_mutex_unlock(&main_python_lock);
}

int __rrr_py_initialize_increment_users(void) {
	int ret = 0;
	__rrr_py_global_lock();

	if (++python_users == 1) {
		VL_DEBUG_MSG_1 ("python3 initialize\n");

		if (rrr_python3_module_append_inittab() != 0) {
			VL_MSG_ERR("Could not append python3 rrr_helper module to inittab before initializing\n");
			ret = 1;
			goto out;
		}

		Py_NoSiteFlag = 1;
		Py_InitializeEx(0);
		Py_NoSiteFlag = 0;

#ifdef RRR_PYTHON_VERSION_LT_3_7
		PyEval_InitThreads();
#endif

		main_python_tstate = PyEval_SaveThread();
	}

	out:
	if (ret != 0) {
		python_users--;
	}
	__rrr_py_global_unlock(NULL);
	return ret;
}

void __rrr_py_finalize_decrement_users(void) {
	__rrr_py_global_lock();
	/* If we are not last, only clean up after ourselves. */
	if (--python_users == 0) {
		VL_DEBUG_MSG_1 ("python3 finalize\n");
		PyEval_RestoreThread(main_python_tstate);
		Py_Finalize();
		main_python_tstate = NULL;
	}
	__rrr_py_global_unlock(NULL);
}

int rrr_py_with_global_tstate_do(int (*callback)(void *arg), void *arg) {
	int ret = 0;
	PyEval_RestoreThread(main_python_tstate);
	ret = callback(arg);
	PyEval_SaveThread();
	return ret;
}

void rrr_py_destroy_thread_state(PyThreadState *tstate) {
	__rrr_py_global_lock();
	PyEval_RestoreThread(tstate);
	Py_EndInterpreter(tstate);
	PyThreadState_Swap(main_python_tstate);
	PyEval_SaveThread();
	__rrr_py_global_unlock(NULL);

	__rrr_py_finalize_decrement_users();
}

PyThreadState *rrr_py_new_thread_state(void) {
	PyThreadState *ret = NULL;

	if (__rrr_py_initialize_increment_users() != 0) {
		return NULL;
	}

	__rrr_py_global_lock();

	PyEval_RestoreThread(main_python_tstate);
	ret = Py_NewInterpreter();
	PyEval_SaveThread();

	__rrr_py_global_unlock(NULL);

	return ret;
}
