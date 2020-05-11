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
#include <sys/wait.h>
#include <unistd.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "python3_socket.h"
#include "python3_common.h"
#include "python3_setting.h"
#include "python3_vl_message.h"
#include "python3_array.h"
#include "python3_module.h"
#include "settings.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "python3.h"
#include "buffer.h"
#include "rrr_strerror.h"
#include "message_addr.h"
#include "ip_buffer_entry.h"
#include "linked_list.h"
#include "fork.h"
#include "../global.h"

static pthread_mutex_t fork_lock = PTHREAD_MUTEX_INITIALIZER;
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

	RRR_DBG_4 ("Restore thread expected thread active %p actual tstate %p\n",
			tstate, current_tstate);

	if (python3_thread_ctx->tstate == NULL) {
		PyEval_RestoreThread(tstate);
		python3_thread_ctx->tstate = tstate;

		current_tstate = _PyThreadState_UncheckedGet();

		if (current_tstate != python3_thread_ctx->tstate) {
			RRR_BUG("After python3 restore thread, current actual thread does not match\n");
		}

		RRR_DBG_4 ("Restore thread complete expected thread active %p actual tstate %p\n",
				tstate, current_tstate);
		ret = 0;
	}
	else {
		if (current_tstate != python3_thread_ctx->tstate) {
			RRR_BUG("Bug: We are tagged as holding lock already in python3_swap_thread_in but python3 says we do not\n");
		}
		RRR_DBG_4 ("Restore did not run\n");
		ret = 1;
	}

	return ret;
}

int python3_swap_thread_out(struct python3_thread_state *tstate_holder) {
	int ret = 0;

	if (tstate_holder->tstate != NULL) {

		PyThreadState *current_tstate = _PyThreadState_UncheckedGet();

		RRR_DBG_4 ("Save thread expected thread active %p actual tstate %p\n",
				tstate_holder->tstate, current_tstate);

		// GIL might have switched while inside a python function and
		// pthread_cancel was called. We cannot continue execution after
		// this.
		if (current_tstate != tstate_holder->tstate) {
			RRR_MSG_ERR("Critical: Current actual tstate did not match, abort\n");
			return 1;
		}
		else if (PyEval_SaveThread() != tstate_holder->tstate) {
			RRR_BUG("Bug: tstates did not match in python3_swap_thread_out\n");
		}

		RRR_DBG_4 ("Save thread complete %p actual tstate %p\n",
				tstate_holder->tstate, current_tstate);

		tstate_holder->tstate = NULL;
	}

	return ret;
}

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
	RRR_DBG_1("Terminating/destroying fork %i tin python3 terminate fork\n", fork->pid);

	if (fork->pid > 0) {
		rrr_fork_unregister_exit_handler(fork->fork_handler, fork->pid);
		kill(fork->pid, SIGUSR1);
	}

	if (fork->socket_main != NULL) {
		if (fork->socket_main->ob_refcnt != 1) {
			RRR_BUG("Refcount was not 1 before DECREF for socket_main in rrr_py_fork_destroy_unlocked\n");
		}
		RRR_Py_XDECREF(fork->socket_main);
	}
	if (fork->socket_child != NULL) {
		if (fork->socket_child->ob_refcnt != 1) {
			RRR_BUG("Refcount was not 1 before DECREF for socket_child in rrr_py_fork_destroy_unlocked\n");
		}
		RRR_Py_XDECREF(fork->socket_child);
	}

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

static struct python3_fork *rrr_py_fork_new (
		struct rrr_fork_handler *fork_handler
) {
	struct python3_fork *ret = malloc(sizeof(*ret));
	PyObject *socket_main = NULL;
	PyObject *socket_child = NULL;

	if (ret == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_py_fork_new\n");
		return NULL;
	}

	memset(ret, '\0', sizeof(*ret));

	// Create a new socket. It will bind() and listen()
	socket_main = rrr_python3_socket_new(NULL);
	if (socket_main == NULL) {
		RRR_MSG_ERR("Could not create socket in rrr_py_fork_new\n");
		goto err;
	}

	// Create another socket. It will connect() to the first one
	socket_child = rrr_python3_socket_new(rrr_python3_socket_get_filename(socket_main));
	if (socket_child == NULL) {
		RRR_MSG_ERR("Could not create socket in rrr_py_fork_new\n");
		goto err;
	}

	// Make the main socket accept connection
	if (rrr_python3_socket_accept(socket_main) != 0) {
		RRR_MSG_ERR("Could not accept() on main socket in rrr_py_fork_new\n");
		goto err;
	}

	ret->socket_main = socket_main;
	ret->socket_child = socket_child;
	ret->fork_handler = fork_handler;

	return ret;

	err:
	RRR_Py_XDECREF(socket_main);
	RRR_Py_XDECREF(socket_child);
	RRR_FREE_IF_NOT_NULL(ret);

	return NULL;
}

PyObject *__rrr_py_socket_message_to_pyobject (struct rrr_socket_msg *message, struct rrr_message_addr *message_addr) {
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
		RRR_MSG_ERR("Unsupported socket message type %u received in __rrr_py_socket_message_to_pyobject\n", message->msg_type);
		goto out;
	}

	out:
	return ret;
}

static int rrr_py_fork_running = 1;
static void __rrr_py_fork_signal_handler (int s) {
	if (s == SIGUSR1) {
		rrr_py_fork_running = 0;
	}
	if (s == SIGPIPE) {
	        RRR_MSG_ERR("Received SIGPIPE in fork, ignoring\n");
	}
}

struct persistent_rw_child_callback_data {
	struct python3_fork *fork;
	PyObject *function;
	PyObject *config_function;
};

int __rrr_py_persistent_thread_rw_child_callback (
		struct rrr_socket_msg *message,
		struct rrr_message_addr *addr_message,
		struct persistent_rw_child_callback_data *callback_data
) {
	PyObject *result = NULL;
	PyObject *arg = NULL;

	PyObject *rrr_socket = callback_data->fork->socket_child;

	int ret = 0;

	arg = __rrr_py_socket_message_to_pyobject(message, addr_message);
	if (arg == NULL) {
		RRR_MSG_ERR("Unknown message type received in __rrr_py_start_persistent_thread_rw_child\n");
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
		result = PyObject_CallFunctionObjArgs(function, rrr_socket, arg, NULL);
		if (result == NULL) {
			RRR_MSG_ERR("Error while calling python3 function in __rrr_py_start_persistent_thread_rw_child pid %i\n",
					getpid());
			PyErr_Print();
			ret = 1;
			goto out;

		}
		if (!PyObject_IsTrue(result)) {
			RRR_MSG_ERR("Non-true returned from python3 function in __rrr_py_start_persistent_thread_rw_child pid %i\n",
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
	free(message);
	RRR_Py_XDECREF(result);
	RRR_Py_XDECREF(arg);

	return ret;
}

void __rrr_py_persistent_thread_source (PyObject *function, struct python3_fork *fork) {
	PyObject *socket = fork->socket_child;
	PyObject *result = NULL;

	int ret = 0;
	int recv_check_interval = 25;
	while (rrr_py_fork_running) {
		result = PyObject_CallFunctionObjArgs(function, socket, NULL);
		if (result == NULL) {
			RRR_MSG_ERR("Error while calling python3 function in __rrr_py_persistent_thread_source pid %i\n",
					getpid());
			PyErr_Print();
			ret = 1;
			goto out;

		}
		if (!PyObject_IsTrue(result)) {
			RRR_MSG_ERR("Non-true returned from python3 function in __rrr_py_persistent_thread_source pid %i\n",
					getpid());
			ret = 1;
			goto out;
		}
		RRR_Py_XDECREF(result);

		// TODO : Consider removing this check
		if (--recv_check_interval == 0) {
			struct rrr_socket_msg *result = NULL;
			ret = rrr_python3_socket_recv(&result, socket);
			if (ret != 0) {
				RRR_MSG_ERR("Error while checking for packets in __rrr_py_persistent_thread_source pid %i\n",
						getpid());
				goto out;
			}
			if (result != NULL) {
				RRR_BUG("Python3 received packet in read-only fork\n");
			}
			recv_check_interval = 200;
		}
	}

	out:
	RRR_Py_XDECREF(result);
	if (RRR_DEBUGLEVEL_1 || ret != 0) {
		RRR_DBG("Pytohn3 child persistent ro pid %i exiting with return value %i, fork running is %i\n",
				getpid(), ret, rrr_py_fork_running);
	}
}

void __rrr_py_persistent_thread_process (
		PyObject *function,
		PyObject *config_function,
		struct python3_fork *fork,
		int *start_sourcing_requested
) {
	struct rrr_socket_msg *message = NULL;
	PyObject *rrr_socket = fork->socket_child;

	*start_sourcing_requested = 0;

	struct rrr_message_addr previous_addr_msg = {0};

	struct persistent_rw_child_callback_data child_callback_data = {
			fork, function, config_function
	};

	int ret = 0;
	while (rrr_py_fork_running && (*start_sourcing_requested == 0)) {
		int max = 100;
		while (rrr_py_fork_running && (--max != 0) && (*start_sourcing_requested == 0)) {
			ret = fork->recv(&message, rrr_socket);
			if (ret != 0) {
				RRR_MSG_ERR("Error from socket receive function in python3 __rrr_py_persistent_thread_process\n");
				goto out;
			}
			if (message == NULL) {
				break;
			}

			if (RRR_SOCKET_MSG_IS_CTRL(message)) {
				message->msg_type &= ~(RRR_SOCKET_MSG_CTRL_F_RESERVED);
				if (RRR_SOCKET_MSG_CTRL_F_HAS(message, RRR_PYTHON3_SOCKET_MSG_CTRL_START_SOURCING)) {
					*start_sourcing_requested = 1;
				}
				else {
					RRR_MSG_ERR("Unknown flags %u in control message in __rrr_py_persistent_thread_process\n",
							RRR_SOCKET_MSG_CTRL_FLAGS(message));
					ret = 1;
					goto out;
				}

				RRR_FREE_IF_NOT_NULL(message);
			}
			else if (RRR_SOCKET_MSG_IS_RRR_MESSAGE_ADDR(message)) {
				previous_addr_msg = *((struct rrr_message_addr *) message);
			}
			else {
				if (__rrr_py_persistent_thread_rw_child_callback(message, &previous_addr_msg, &child_callback_data) != 0) {
					ret = 1;
					goto out;
				}
				message = NULL;
			}
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(message);

	if (RRR_DEBUGLEVEL_1 || ret != 0) {
		RRR_DBG("Pytohn3 child persistent rw process exiting with return value %i, fork running is %i\n", ret, rrr_py_fork_running);
	}
}

void __rrr_py_start_persistent_thread_rw_child (PyObject *function, PyObject *config_function, struct python3_fork *fork) {
	int start_sourcing = 0;

	__rrr_py_persistent_thread_process(function, config_function, fork, &start_sourcing);

	if (start_sourcing == 1) {
		__rrr_py_persistent_thread_source(function, fork);
	}
}

// This function must only be called with main thread state active and lock held
static int __fork_main_tstate_callback(void *arg, PyThreadState *tstate_orig) {
	struct python3_fork *fork_data = arg;
	PyOS_BeforeFork();

	pid_t ret = rrr_fork(fork_data->fork_handler, rrr_py_handle_sigchld, fork_data);

	if (ret == 0) {
		// PyOS_AfterFork_Child causes deadlock in 3.8.2. Workaround is to delete thread
		// states prior to calling it.
		if (tstate_orig != NULL) {
			PyInterpreterState *istate = tstate_orig->interp;
			if (istate != NULL) {
				PyInterpreterState_Clear(istate);
				PyInterpreterState_Delete(istate);
			}
		}

		PyOS_AfterFork_Child();
	}
	else {
		PyOS_AfterFork_Parent();
	}

	if (ret > 0) {
		RRR_DBG_1 ("=== FORK PID %i ========================================================================================\n", ret);
	}

	return ret;
}

static int __fork_callback(void *arg) {
	struct python3_fork *fork_data = arg;
	return rrr_py_with_global_tstate_do(__fork_main_tstate_callback, fork_data, 0);
}

static pid_t __rrr_py_fork_intermediate (
		PyObject *function,
		PyObject *config_function,
		struct python3_fork *fork_data,
		void (*child_method)(PyObject *function, PyObject *config_function, struct python3_fork *fork)
) {
	pid_t ret = 0;

	RRR_DBG_1("Before fork child socket is %i\n", rrr_python3_socket_get_connected_fd(fork_data->socket_child));
	RRR_DBG_1("Before fork main  socket is %i\n", rrr_python3_socket_get_connected_fd(fork_data->socket_main));

	ret = rrr_socket_with_lock_do(__fork_callback, fork_data);

	if (ret != 0) {
		if (ret < 0) {
			RRR_MSG_ERR("Could not fork python3: %s\n", rrr_strerror(errno));
		}
		goto out_main;
	}

	////////////////
	// CHILD CODE //
	////////////////

//	Uncomment for debugging, buy some time to attach to the fork
//	usleep(5000000);

	// Original thread state is cleared after the fork, make sure we start using main instead.
	if (PyGILState_Check()) {
		PyEval_SaveThread();
	}

	PyEval_RestoreThread(main_python_tstate);

	RRR_DBG_1("Child %i socket is %i\n", getpid(), rrr_python3_socket_get_connected_fd(fork_data->socket_child));
	RRR_DBG_1("Child closing sockets of main\n");
	RRR_Py_XDECREF(fork_data->socket_main);

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

	child_method(function, config_function, fork_data);

	RRR_DBG_1("Child %i closing sockets\n", getpid());
	rrr_socket_close_all_except(rrr_python3_socket_get_connected_fd(fork_data->socket_child));
	RRR_DBG_1("Child %i decref socket\n", getpid());
	RRR_Py_XDECREF(fork_data->socket_child);
	RRR_DBG_1("Child %i return\n", getpid());
	exit(ret);

	/////////////////
	// PARENT CODE //
	/////////////////

	out_main:

	RRR_DBG_1("Main closing sockets of child\n");
	RRR_Py_XDECREF(fork_data->socket_child);
	fork_data->socket_child = NULL;

	pthread_mutex_lock(&fork_lock);
	fork_data->pid = ret;
	pthread_mutex_unlock(&fork_lock);

	return ret;
}

static int __rrr_py_start_persistent_rw_thread_intermediate (
		PyObject *function,
		PyObject *config_function,
		struct python3_fork *fork
) {
	int ret = 0;

	fork->poll = rrr_python3_socket_poll;
	fork->send = rrr_python3_socket_send;
	fork->recv = rrr_python3_socket_recv;

	pid_t pid = __rrr_py_fork_intermediate (
			function,
			config_function,
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

static int __rrr_py_start_thread (
		struct python3_fork **result_fork,
		struct rrr_fork_handler *fork_handler,
		const char *module_name,
		const char *function_name,
		const char *config_function_name,
		int (*start_method)(PyObject *function, PyObject *config_function, struct python3_fork *fork)
) {
	int ret = 0;

	PyObject *module = NULL;
	PyObject *module_dict = NULL;
	PyObject *function = NULL;
	PyObject *config_function = NULL;
	PyObject *py_module_name = NULL;
	struct python3_fork *fork = NULL;

	*result_fork = NULL;
	RRR_DBG_3("Start thread of module %s function %s config function %s\n",
			module_name, function_name, config_function_name);

	fork = rrr_py_fork_new(fork_handler);
	if (fork == NULL) {
		RRR_MSG_ERR("Could not start thread.\n");
		ret = 1;
		goto out;
	}

//	printf ("New fork main  refcount: %li\n", fork->socket_main->ob_refcnt);
//	printf ("New fork child refcount: %li\n", fork->socket_child->ob_refcnt);

	py_module_name = PyUnicode_FromString(module_name);
	module = PyImport_GetModule(py_module_name);
//	printf ("Module %s already loaded? %p\n", module_name, module);
	if (module == NULL && (module = PyImport_ImportModule(module_name)) == NULL) {
		RRR_MSG_ERR("Could not import module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out;
	}
//	printf ("Module %s loaded: %p\n", module_name, module);

	if ((module_dict = PyModule_GetDict(module)) == NULL) { // Borrowed reference
		RRR_MSG_ERR("Could not get dictionary of module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out;
	}

/*	if (VL_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING IMPORTED USER MODULE ===========================\n");
		rrr_py_dump_dict_entries(module_dict);
		printf ("=== PYTHON3 DUMPING IMPORTED USER MODULE END =======================\n\n");
	}*/

	if ((function = rrr_py_import_function(module_dict, function_name)) == NULL) {
		RRR_MSG_ERR("Could not get function %s from module %s while starting thread\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	if (config_function_name != NULL && *config_function_name != '\0') {
		if ((config_function = rrr_py_import_function(module_dict, config_function_name)) == NULL) {
			RRR_MSG_ERR("Could not get config function %s from module %s while starting thread\n",
					config_function_name, module_name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = start_method(function, config_function, fork)) != 0) {
		RRR_MSG_ERR("Could not fork python3 with function %s config function %s from %s. Return value: %i\n",
				function_name, config_function_name, module_name, ret);
		ret = 1;
		goto out;
	}

	*result_fork = fork;

	out:
	RRR_Py_XDECREF(py_module_name);
	RRR_Py_XDECREF(function);
	RRR_Py_XDECREF(module);
	if (ret != 0) {
		rrr_py_fork_terminate_and_destroy(fork);
	}
	return ret;
}

int rrr_py_start_persistent_rw_thread (
		struct python3_fork **result_fork,
		struct rrr_fork_handler *fork_handler,
		const char *module_name,
		const char *function_name,
		const char *config_function_name
) {
	return __rrr_py_start_thread (
			result_fork,
			fork_handler,
			module_name,
			function_name,
			config_function_name,
			__rrr_py_start_persistent_rw_thread_intermediate
	);
}

int rrr_py_persistent_process_message (
		struct python3_fork *fork,
		struct rrr_ip_buffer_entry *entry
) {
	int ret = 0;

	if (fork->invalid == 1) {
		RRR_MSG_ERR("Fork was invalid in rrr_py_persistent_process_message, child has exited\n");
		ret = 1;
		goto out;
	}

	struct rrr_message_addr message_addr;
	rrr_message_addr_init(&message_addr);
	if (entry->addr_len > 0) {
		memcpy(&message_addr.addr, &entry->addr, entry->addr_len);
		RRR_MSG_ADDR_SET_ADDR_LEN(&message_addr, entry->addr_len);
	}

	ret = fork->send(fork->socket_main, (struct rrr_socket_msg *) &message_addr);
	if (ret != 0) {
		RRR_MSG_ERR("Could not process new python3 message object in rrr_py_persistent_process_message\n");
		goto out;
	}

	ret = fork->send(fork->socket_main, entry->message);
	if (ret != 0) {
		RRR_MSG_ERR("Could not process new python3 message object in rrr_py_persistent_process_message\n");
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
	if (fork->send(fork->socket_main, &message) != 0) {
		RRR_MSG_ERR("Error while sending control message to fork in rrr_py_persistent_start_sourcing\n");
		return 1;
	}
	return 0;
}

int __rrr_py_import_function_or_print_error(PyObject **target, PyObject *dictionary, const char *name) {
	*target = NULL;
	PyObject *res = rrr_py_import_function(dictionary, name);
	if (res == NULL) {
		RRR_MSG_ERR("Could not find %s function: \n", name);
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
		RRR_MSG_ERR("Could not add rrr_helper module to current thread state dict:\n");
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
		RRR_MSG_ERR("Could not run initial python3 code to set up RRR environment: \n");
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
			RRR_MSG_ERR("Could not append python3 rrr_helper module to inittab before initializing\n");
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

int rrr_py_with_global_tstate_do (
		int (*callback)(void *arg, PyThreadState *tstate_orig), void *arg, int force_gil_release
) {
	int ret = 0;

	// XXX    Feel free to read through this and check if it's correct. The
	//        goal here is that this function may be called from any context
	//        and switch to main thread state. If another thread state was
	//        already active, it is saved and then restored again after the work
	//        is complete

	PyThreadState *state_orig = NULL;

	if (PyGILState_Check()) {
			if (force_gil_release) {
				// We can end up here when killing a thread holding current tstate.
				// We are usually called through the cancel function and from the
				// watchdog thread.
				// Might happen if a thread has not been properly cancelled before
				// we enter this function.
				if (PyGILState_GetThisThreadState() == NULL) {
					RRR_BUG("Abort: Another thread still holding GIL while attempting to acquire global tstate in rrr_py_with_global_tstate_do\n");
				}
			}
			state_orig = PyEval_SaveThread();
	}

	PyEval_RestoreThread(main_python_tstate);
	ret = callback(arg, state_orig);
	PyEval_SaveThread();

	if (state_orig != NULL) {
		PyEval_RestoreThread(state_orig);
	}

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
