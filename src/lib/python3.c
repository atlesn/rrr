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

// Put first to avoid problems with other files including sys/time.h
#include "vl_time.h"

#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <stdlib.h>

// Due to warnings in python (which defines this)
#undef _POSIX_C_SOURCE
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#undef _POSIX_C_SOURCE

#include "../global.h"
#include "posix.h"
#include "python3.h"
#include "python3_common.h"
#include "python3_setting.h"
#include "python3_vl_message.h"
#include "python3_array.h"
#include "python3_module.h"
#include "python3_socket.h"
#include "settings.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "buffer.h"
#include "rrr_strerror.h"
#include "messages.h"
#include "message_addr.h"
#include "ip_buffer_entry.h"
#include "linked_list.h"
#include "fork.h"
#include "rrr_mmap.h"
#include "mmap_channel.h"
#include "log.h"
#include "gnu.h"

struct python3_fork_runtime {
	PyThreadState *istate;

	PyObject *py_main;
	PyObject *py_main_dict;

	PyObject *socket;
};

static pthread_mutex_t fork_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t main_python_lock = PTHREAD_MUTEX_INITIALIZER;
static PyThreadState *main_python_tstate = NULL;
static int python_users = 0;

#define PYTHON3_MMAP_SIZE (1024*1024*2)

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
		RRR_DBG_1 ("python3 initialize\n");

		if (rrr_python3_module_append_inittab() != 0) {
			RRR_MSG_0("Could not append python3 rrr_helper module to inittab before initializing\n");
			ret = 1;
			goto out;
		}

		//Py_NoSiteFlag = 1;
		Py_InitializeEx(0); // 0 = no signal registering
		//Py_NoSiteFlag = 0;

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
		RRR_DBG_1 ("python3 finalize\n");
		PyEval_RestoreThread(main_python_tstate);
		Py_Finalize();
		main_python_tstate = NULL;
	}
	__rrr_py_global_unlock(NULL);
}

static void __rrr_py_destroy_thread_state(PyThreadState *tstate) {
	__rrr_py_global_lock();
	PyEval_RestoreThread(tstate);
	Py_EndInterpreter(tstate);
	PyThreadState_Swap(main_python_tstate);
	PyEval_SaveThread();
	__rrr_py_global_unlock(NULL);

	__rrr_py_finalize_decrement_users();
}

static PyThreadState *__rrr_py_new_thread_state(void) {
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

int __rrr_py_import_function_or_print_error(PyObject **target, PyObject *dictionary, const char *name) {
	*target = NULL;
	PyObject *res = rrr_py_import_function(dictionary, name);
	if (res == NULL) {
		RRR_MSG_0("Could not find %s function: \n", name);
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

static int __rrr_py_get_rrr_objects (
		PyObject *dictionary,
		const char **extra_module_paths,
		int module_paths_length
) {
	PyObject *res = NULL;
	PyObject *rrr_helper_module = NULL;
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

	if ((rrr_helper_module = PyImport_ImportModule("rrr_helper")) == NULL) {
		RRR_MSG_0("Could not add rrr_helper module to current thread state dict:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	//printf ("RRR helper module: %p refcount %li\n", rrr_helper_module, rrr_helper_module->ob_refcnt);
//	Py_XDECREF(rrr_helper_module);

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
//			"import rrr_helper\n"
//			"from rrr_helper import *\n"
	;

	rrr_py_import_final = malloc(strlen(rrr_py_import_template) + strlen(extra_module_paths_concat) + 1);
	sprintf(rrr_py_import_final, rrr_py_import_template, extra_module_paths_concat);

	res = PyRun_String(rrr_py_import_final, Py_file_input, dictionary, dictionary);
	if (res == NULL) {
		RRR_MSG_0("Could not run initial python3 code to set up RRR environment: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	RRR_Py_XDECREF(res);

	// DEBUG
	if (RRR_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING RRR HELPER MODULE ==============================\n");
		rrr_python3_module_dump_dict_keys();
		printf ("=== PYTHON3 DUMPING RRR HELPER MODULE END ==========================\n\n");
	}

	if (RRR_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING GLOBAL MODULES =================================\n");
		rrr_py_dump_global_modules();
		printf ("=== PYTHON3 DUMPING GLOBAL MODULES END =============================\n\n");
	}

	out:
	RRR_FREE_IF_NOT_NULL(rrr_py_import_final);

	return ret;
}

static int __rrr_py_fork_runtime_init (
		struct python3_fork_runtime *runtime,
		struct rrr_mmap_channel *channel_from_fork,
		const char *module_path_in
) {
	memset(runtime, '\0', sizeof(*runtime));

	int ret = 0;

	if ((runtime->istate = __rrr_py_new_thread_state()) == NULL) {
		goto out;
	}

	PyEval_RestoreThread(runtime->istate);

	// LOAD PYTHON MAIN DICTIONARY
	PyObject *py_main = PyImport_AddModule("__main__"); // Borrowed reference
	if (py_main == NULL) {
		RRR_MSG_0("Could not get python3 __main__ in __rrr_py_fork_runtime_init\n");
		PyErr_Print();
		ret = 1;
		goto out_cleanup_istate;
	}

	PyObject *py_main_dict = PyModule_GetDict(py_main); // Borrowed reference
	if (py_main_dict == NULL) {
		RRR_MSG_0("Could not get python3 main dictionary in __rrr_py_fork_runtime_init\n");
		PyErr_Print();
		ret = 1;
		goto out_cleanup_istate;
	}

	// PREPARE RRR ENVIRONMENT
	const char *module_path_array[1];
	int module_path_length = 0;
	if (module_path_in != NULL) {
		module_path_array[0] = module_path_in;
		module_path_length = 1;
	}

	if (__rrr_py_get_rrr_objects(py_main_dict, (const char **) module_path_array, module_path_length) != 0) {
		RRR_MSG_0("Could not get rrr objects  __rrr_py_fork_runtime_init\n");
		PyErr_Print();
		ret = 1;
		goto out_cleanup_istate;
	}

	if ((runtime->socket = rrr_python3_socket_new (channel_from_fork)) == NULL) {
		RRR_MSG_0("Could not create socket PyObject in  __rrr_py_fork_runtime_init\n");
		goto out_cleanup_istate;
	}

	PyEval_SaveThread();

	goto out;
	out_cleanup_istate:
		PyEval_SaveThread();
		__rrr_py_destroy_thread_state(runtime->istate);
	out:
		return ret;
}

static void __rrr_py_fork_runtime_cleanup (struct python3_fork_runtime *runtime) {
	PyEval_RestoreThread(runtime->istate);
	Py_XDECREF(runtime->socket);
	PyEval_SaveThread();
	__rrr_py_destroy_thread_state(runtime->istate);
}
/*
static void __rrr_py_fork_runtime_cleanup_void (void *runtime) {
	__rrr_py_fork_runtime_cleanup(runtime);
}
*/
void rrr_py_handle_sigchld (pid_t pid, void *exit_notify_arg) {
	struct python3_fork *fork_data = exit_notify_arg;

	if (pid != fork_data->pid) {
		RRR_BUG("PID mismatch in rrr_py_handle_sigchld: %i <> %i\n", pid, fork_data->pid);
	}

	pthread_mutex_lock (&fork_lock);
	fork_data->invalid = 1;
	pthread_mutex_unlock (&fork_lock);
}

void rrr_py_call_fork_notifications_if_needed (struct rrr_fork_handler *handler) {
	rrr_fork_handle_sigchld_and_notify_if_needed(handler);
}

static void __rrr_py_fork_destroy_unlocked (struct python3_fork *fork) {
	RRR_DBG_1("Terminating/destroying fork %i in python3 terminate fork\n", fork->pid);

	if (fork->pid > 0) {
		rrr_fork_unregister_exit_handler(fork->fork_handler, fork->pid);
		kill(fork->pid, SIGUSR1);
	}

	rrr_mmap_channel_destroy(fork->channel_to_fork);
	rrr_mmap_channel_destroy(fork->channel_from_fork);
	rrr_mmap_destroy(fork->mmap);

	free(fork);
}

void rrr_py_fork_terminate_and_destroy (struct python3_fork *fork) {
	if (fork == NULL) {
		return;
	}

	pthread_mutex_lock (&fork_lock);
	__rrr_py_fork_destroy_unlocked(fork);
	pthread_mutex_unlock (&fork_lock);
}

#define ALLOCATE_TMP_NAME(target, name1, name2)															\
	if (rrr_asprintf(&target, "%s-%s", name1, name2) <= 0) {											\
		RRR_MSG_0("Could not allocate temporary string for name in rrr_py_fork_new\n");				\
		goto err_free;																					\
	}

static struct python3_fork *__rrr_py_fork_new (
		struct rrr_fork_handler *fork_handler,
		const char *name
) {
	struct python3_fork *ret = NULL;

	// These are for debug messages
	char *mmap_name = NULL;
	char *mmap_channel_to_name = NULL;
	char *mmap_channel_from_name = NULL;

	ALLOCATE_TMP_NAME(mmap_name, name, "mmap");
	ALLOCATE_TMP_NAME(mmap_channel_to_name, name, "ch-to");
	ALLOCATE_TMP_NAME(mmap_channel_from_name, name, "ch-from");

	if ((ret = malloc(sizeof(*ret))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_py_fork_new\n");
		goto err_free;
	}

	memset(ret, '\0', sizeof(*ret));

	if (rrr_mmap_new(&ret->mmap, PYTHON3_MMAP_SIZE, mmap_name) != 0) {
		RRR_MSG_0("Could not create mmap in rrr_py_fork_new\n");
		goto err_free;
	}

	if (rrr_mmap_channel_new(&ret->channel_to_fork, ret->mmap, mmap_channel_to_name) != 0) {
		RRR_MSG_0("Could not create mmap channel in rrr_py_fork_new\n");
		goto err_destroy_mmap;
	}

	if (rrr_mmap_channel_new(&ret->channel_from_fork, ret->mmap, mmap_channel_from_name) != 0) {
		RRR_MSG_0("Could not create mmap channel in rrr_py_fork_new\n");
		goto err_destroy_mmap_channel_to_fork;
	}

	ret->fork_handler = fork_handler;

	goto out;

//	err_destroy_mmap_channel_from_fork:
//		rrr_mmap_channel_destroy(ret->channel_from_fork);
	err_destroy_mmap_channel_to_fork:
		rrr_mmap_channel_destroy(ret->channel_to_fork);
	err_destroy_mmap:
		rrr_mmap_destroy(ret->mmap);
	err_free:
		RRR_FREE_IF_NOT_NULL(ret);
	out:
		RRR_FREE_IF_NOT_NULL(mmap_name);
		RRR_FREE_IF_NOT_NULL(mmap_channel_to_name);
		RRR_FREE_IF_NOT_NULL(mmap_channel_from_name);
		return ret;
}

PyObject *__rrr_py_socket_message_to_pyobject (const struct rrr_socket_msg *message, struct rrr_message_addr *message_addr) {
	PyObject *ret = NULL;
	if (RRR_SOCKET_MSG_IS_RRR_MESSAGE(message)) {
		ret = rrr_python3_rrr_message_new_from_message_and_address (message, message_addr);
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message)) {
		ret = rrr_python3_setting_new_from_setting (message);
	}
	else if (RRR_SOCKET_MSG_IS_CTRL(message)) {
#if RRR_SOCKET_64_IS_LONG
		ret = PyLong_FromLong(message->msg_value);
#elif RRR_SOCKET_64_IS_LONG_LONG
		ret = PyLong_FromLongLong(message->msg_value);
#else
		#error "RRR_SOCKET_64_IS_LONG or RRR_SOCKET_64_IS_LONG_LONG not set"
#endif
	}
	else {
		RRR_MSG_0("Unsupported socket message type %u received in __rrr_py_socket_message_to_pyobject\n", message->msg_type);
		goto out;
	}

	out:
	return ret;
}

static int rrr_py_fork_running = 1;
static void __rrr_py_fork_signal_handler (int s) {
	if (s == SIGUSR1 || s == SIGINT || s == SIGTERM) {
		rrr_py_fork_running = 0;
	}
	if (s == SIGPIPE) {
	        RRR_MSG_0("Received SIGPIPE in fork, ignoring\n");
	}
}

struct rrr_py_persistent_process_read_callback_data {
	struct python3_fork_runtime *runtime;
	PyObject *function;
	PyObject *config_function;
	int *start_sourcing_requested;
	struct rrr_message_addr previous_addr_msg;
	int message_count;
};

int __rrr_py_persistent_process_call_application (
		const struct rrr_socket_msg *message,
		struct rrr_message_addr *addr_message,
		struct rrr_py_persistent_process_read_callback_data  *callback_data
) {
	PyObject *result = NULL;
	PyObject *arg = NULL;

	int ret = 0;

	arg = __rrr_py_socket_message_to_pyobject(message, addr_message);
	if (arg == NULL) {
		RRR_MSG_0("Unknown message type received in __rrr_py_start_persistent_thread_rw_child\n");
		ret = 1;
		goto out;
	}

	PyObject *function = NULL;

	if (rrr_python3_rrr_message_check(arg)) {
		function = callback_data->function;
	}
	else if (rrr_python3_setting_check(arg)) {
		function = callback_data->config_function;
	}

	if (function != NULL) {
		result = PyObject_CallFunctionObjArgs(function, callback_data->runtime->socket, arg, NULL);
		if (result == NULL) {
			RRR_MSG_0("Error while calling python3 function in __rrr_py_start_persistent_thread_rw_child pid %i\n",
					getpid());
			PyErr_Print();
			ret = 1;
			goto out;

		}
		if (!PyObject_IsTrue(result)) {
			RRR_MSG_0("Non-true returned from python3 function in __rrr_py_start_persistent_thread_rw_child pid %i\n",
					getpid());
			ret = 1;
			goto out;
		}
	}
	else {
		// This happens when no config-function is specified
		RRR_DBG_3("Python3 no functions defined for received message type %p, %s\n", Py_TYPE(arg), arg->ob_type->tp_name);
	}

	if (ret != 0) {
		ret = RRR_FIFO_CALLBACK_ERR | RRR_FIFO_SEARCH_STOP;
	}

	out:
	RRR_Py_XDECREF(result);
	RRR_Py_XDECREF(arg);

	return ret;
}

void __rrr_py_persistent_fork_run_source_loop (struct python3_fork_runtime *runtime, PyObject *function) {
	PyObject *result = NULL;

	int ret = 0;
	while (rrr_py_fork_running) {
		result = PyObject_CallFunctionObjArgs(function, runtime->socket, NULL);
		if (result == NULL) {
			RRR_MSG_0("Error while calling python3 function in __rrr_py_persistent_thread_source pid %i\n",
					getpid());
			PyErr_Print();
			ret = 1;
			goto out;

		}
		if (!PyObject_IsTrue(result)) {
			RRR_MSG_0("Non-true returned from python3 function in __rrr_py_persistent_thread_source pid %i\n",
					getpid());
			ret = 1;
			goto out;
		}
		RRR_Py_XDECREF(result);
	}

	out:
	RRR_Py_XDECREF(result);
	if (RRR_DEBUGLEVEL_1 || ret != 0) {
		RRR_DBG("Pytohn3 child persistent ro pid %i exiting with return value %i, fork running is %i\n",
				getpid(), ret, rrr_py_fork_running);
	}
}

static int __rrr_py_persistent_process_read_callback (const void *data, size_t data_size, void *arg) {
	const struct rrr_socket_msg *message = data;
	struct rrr_py_persistent_process_read_callback_data *callback_data = arg;

	(void)(data_size);

	int ret = 0;

	RRR_DBG_3 ("python3 receive to application in pid %i size %u\n",
			getpid(), message->msg_size
	);

	if (MSG_TOTAL_SIZE(message) != data_size) {
		RRR_BUG("Size mismatch %u<>%u in __rrr_py_persistent_thread_process_read_callback\n",
				MSG_TOTAL_SIZE(message), data_size);
	}

	rrr_u16 msg_type = message->msg_type;

	if (RRR_SOCKET_MSG_IS_CTRL(message)) {
		msg_type &= ~(RRR_SOCKET_MSG_CTRL_F_RESERVED);
		if ((msg_type & RRR_PYTHON3_SOCKET_MSG_CTRL_START_SOURCING) == RRR_PYTHON3_SOCKET_MSG_CTRL_START_SOURCING) {
			*(callback_data->start_sourcing_requested) = 1;
		}
		else {
			RRR_MSG_0("Unknown flags %u in control message in __rrr_py_persistent_thread_process\n",
					RRR_SOCKET_MSG_CTRL_FLAGS(message));
			ret = 1;
			goto out;
		}
	}
	else if (RRR_SOCKET_MSG_IS_RRR_MESSAGE_ADDR(message)) {
		callback_data->previous_addr_msg = *((struct rrr_message_addr *) message);
	}
	else {
		if (__rrr_py_persistent_process_call_application (
				message,
				&callback_data->previous_addr_msg,
				callback_data
		) != 0) {
			ret = 1;
			goto out;
		}
		message = NULL;
	}

	callback_data->message_count++;

	out:
	return ret;
}

void __rrr_py_persistent_process_loop (
		struct python3_fork_runtime *runtime,
		struct rrr_mmap_channel *channel_to_fork,
		PyObject *function,
		PyObject *config_function,
		int *start_sourcing_requested
) {
	*start_sourcing_requested = 0;

	struct rrr_py_persistent_process_read_callback_data callback_data = {
			runtime,
			function,
			config_function,
			start_sourcing_requested,
			{0},
			0
	};

	int ret = 0;

	while (rrr_py_fork_running && (*start_sourcing_requested == 0)) {
		int max = 100;
		while (rrr_py_fork_running && (--max != 0) && (*start_sourcing_requested == 0)) {
			ret = rrr_mmap_channel_read_with_callback (
					channel_to_fork,
					__rrr_py_persistent_process_read_callback,
					&callback_data
			);
			if (ret != 0) {
				if (ret == RRR_MMAP_CHANNEL_EMPTY) {
					ret = 0;
					break;
				}

				RRR_MSG_0("Error from read function in python3 __rrr_py_persistent_thread_process\n");
				goto out;
			}
		}
		rrr_posix_usleep (25000);
	}

	if (RRR_DEBUGLEVEL_1 || ret != 0) {
		RRR_DBG("Pytohn3 child persistent rw process exiting with return value %i, fork running is %i\n", ret, rrr_py_fork_running);
	}

	out:
	return;
}

static int __rrr_py_start_persistent_rw_fork_intermediate (
		struct python3_fork *fork,
		const char *module_path,
		const char *module_name,
		const char *function_name,
		const char *config_function_name
) {
	int ret = 0;

	PyObject *module = NULL;
	PyObject *module_dict = NULL;
	PyObject *function = NULL;
	PyObject *config_function = NULL;
	PyObject *py_module_name = NULL;

	struct python3_fork_runtime runtime;

	if ((ret = __rrr_py_fork_runtime_init (
			&runtime,
			fork->channel_from_fork,
			module_path
	)) != 0) {
		RRR_MSG_0("Could not initialize python3 runtime in __rrr_py_start_persistent_rw_fork_intermediate\n");
		ret = 1;
		goto out;
	}

	PyEval_RestoreThread(runtime.istate);

//	printf ("New fork main  refcount: %li\n", fork->socket_main->ob_refcnt);
//	printf ("New fork child refcount: %li\n", fork->socket_child->ob_refcnt);

	py_module_name = PyUnicode_FromString(module_name);
	module = PyImport_GetModule(py_module_name);
//	printf ("Module %s already loaded? %p\n", module_name, module);
	if (module == NULL && (module = PyImport_ImportModule(module_name)) == NULL) {
		RRR_MSG_0("Could not import module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out_cleanup_runtime;
	}
//	printf ("Module %s loaded: %p\n", module_name, module);

	if ((module_dict = PyModule_GetDict(module)) == NULL) { // Borrowed reference
		RRR_MSG_0("Could not get dictionary of module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out_cleanup_runtime;
	}

/*	if (VL_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING IMPORTED USER MODULE ===========================\n");
		rrr_py_dump_dict_entries(module_dict);
		printf ("=== PYTHON3 DUMPING IMPORTED USER MODULE END =======================\n\n");
	}*/

	if ((function = rrr_py_import_function(module_dict, function_name)) == NULL) {
		RRR_MSG_0("Could not get function %s from module %s while starting thread\n",
				function_name, module_name);
		ret = 1;
		goto out_cleanup_runtime;
	}

	if (config_function_name != NULL && *config_function_name != '\0') {
		if ((config_function = rrr_py_import_function(module_dict, config_function_name)) == NULL) {
			RRR_MSG_0("Could not get config function %s from module %s while starting thread\n",
					config_function_name, module_name);
			ret = 1;
			goto out_cleanup_runtime;
		}
	}

	int start_sourcing = 0;

	__rrr_py_persistent_process_loop (
			&runtime,
			fork->channel_to_fork,
			function,
			config_function,
			&start_sourcing
	);

	if (start_sourcing == 1) {
		__rrr_py_persistent_fork_run_source_loop (
				&runtime,
				function
		);
	}

	out_cleanup_runtime:
		RRR_Py_XDECREF(py_module_name);
		RRR_Py_XDECREF(function);
		RRR_Py_XDECREF(module);
		PyEval_SaveThread();

		__rrr_py_fork_runtime_cleanup(&runtime);

	out:
	return ret;
}

int rrr_py_start_persistent_rw_fork (
		struct python3_fork **result_fork,
		struct rrr_fork_handler *fork_handler,
		const char *module_path,
		const char *module_name,
		const char *function_name,
		const char *config_function_name
) {
	pid_t ret = 0;

	struct python3_fork *fork = NULL;

	*result_fork = NULL;

	if ((fork = __rrr_py_fork_new(fork_handler, function_name)) == NULL) {
		RRR_MSG_0("Could not start thread.\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fork(fork_handler, rrr_py_handle_sigchld, fork)) != 0) {
		if (ret < 0) {
			RRR_MSG_0("Could not fork python3: %s\n", rrr_strerror(errno));
		}
		goto out_main;
	}

	////////////////
	// CHILD CODE //
	////////////////

//	Uncomment for debugging, buy some time to attach to the fork
//	usleep(5000000);

	// This looks like it's global but each fork gets it's own copy
	rrr_py_fork_running = 1;

	struct sigaction action;
	action.sa_handler = __rrr_py_fork_signal_handler;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);

	sigaction (SIGUSR1, &action, NULL);
	sigaction (SIGPIPE, &action, NULL);

	RRR_DBG_1("Python3 child fork %i starting python3 code\n", getpid());

	ret = __rrr_py_start_persistent_rw_fork_intermediate (
			fork,
			module_path,
			module_name,
			function_name,
			config_function_name
	);

	rrr_mmap_channel_writer_free_blocks(fork->channel_from_fork);

	RRR_DBG_1("Python3 child fork %i returned %i\n", getpid(), ret);
	exit(ret);

	/////////////////
	// PARENT CODE //
	/////////////////

	out_main:
		pthread_mutex_lock(&fork_lock);
		fork->pid = ret;
		ret = 0;
		pthread_mutex_unlock(&fork_lock);

	out:
		if (ret != 0) {
			rrr_py_fork_terminate_and_destroy(fork);
		}
		else {
			*result_fork = fork;
		}
		return ret;
}

int rrr_py_persistent_process_read_from_fork (
		void **target,
		size_t *target_size,
		struct python3_fork *fork
) {
	int ret = rrr_mmap_channel_read(target, target_size, fork->channel_from_fork);

	if (ret == RRR_MMAP_CHANNEL_EMPTY) {
		ret = 0;
	}

	return ret;
}

static int __rrr_py_persistent_process_socket_msg (
		struct python3_fork *fork,
		const struct rrr_socket_msg *msg
) {
	int ret = 0;
	if ((ret = rrr_mmap_channel_write(fork->channel_to_fork, msg, MSG_TOTAL_SIZE(msg))) != 0) {
		if (ret == RRR_MMAP_CHANNEL_FULL) {
			RRR_MSG_0("Channel was full in __rrr_py_persistent_process_socket_msg\n");
			ret = 1;
		}
	}
	return ret;
}

int rrr_py_persistent_process_setting (
		struct python3_fork *fork,
		const struct rrr_setting_packed *setting
) {
	int ret = __rrr_py_persistent_process_socket_msg (fork, (const struct rrr_socket_msg *) setting);
	if (ret != 0) {
		RRR_MSG_0("Could not send python3 message to child in rrr_py_persistent_process_message\n");
	}
	return ret;
}

int rrr_py_persistent_process_message (
		struct python3_fork *fork,
		const struct rrr_ip_buffer_entry *entry
) {
	int ret = 0;

	if (fork->invalid == 1) {
		RRR_MSG_0("Fork was invalid in rrr_py_persistent_process_message, child has exited\n");
		ret = 1;
		goto out;
	}

	struct rrr_message_addr message_addr;
	rrr_message_addr_init(&message_addr);
	if (entry->addr_len > 0) {
		memcpy(&message_addr.addr, &entry->addr, entry->addr_len);
		RRR_MSG_ADDR_SET_ADDR_LEN(&message_addr, entry->addr_len);
	}

	ret = __rrr_py_persistent_process_socket_msg (fork, (const struct rrr_socket_msg *) &message_addr);
	if (ret != 0) {
		RRR_MSG_0("Could not send python3 message to child in rrr_py_persistent_process_message\n");
		goto out;
	}

	ret = __rrr_py_persistent_process_socket_msg (fork, (const struct rrr_socket_msg *) entry->message);
	if (ret != 0) {
		RRR_MSG_0("Could not send python3 message to child in rrr_py_persistent_process_message\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_py_persistent_start_sourcing (
		struct python3_fork *fork
) {
	struct rrr_socket_msg message;
	rrr_socket_msg_populate_control_msg(&message, RRR_PYTHON3_SOCKET_MSG_CTRL_START_SOURCING, 0);
	if (rrr_mmap_channel_write(fork->channel_to_fork, &message, sizeof(message)) != 0) {
		RRR_MSG_0("Error while sending control message to fork in rrr_py_persistent_start_sourcing\n");
		return 1;
	}
	return 0;
}
