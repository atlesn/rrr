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
#include "../global.h"

struct python3_fork_zombie {
	struct python3_fork_zombie *next;
	pid_t pid;
};

static struct python3_fork_zombie *first_zombie = NULL;
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

void rrr_py_handle_sigchld (void (*child_exit_callback)(pid_t pid, void *callback_arg), void *callback_arg) {
	struct python3_fork_zombie *zombie = NULL;
	struct python3_fork_zombie *prev = NULL;

	pthread_mutex_lock (&fork_lock);

	prev = NULL;
	zombie = first_zombie;
	while (zombie != NULL) {
		struct python3_fork_zombie *next = zombie->next;

		int wstatus;
		pid_t res = waitpid(zombie->pid, &wstatus, WNOHANG);
		if (res == 0) {
			// No state change
		}
		else if (res > 0) {
			if (WIFSIGNALED(wstatus)) {
				int signal = WTERMSIG(wstatus);
				VL_DEBUG_MSG_1("python3 child %i has was terminated by signal %i\n", res, signal);

				goto remove_and_next;
			}

			if (WIFEXITED(wstatus)) {
				int child_status = WEXITSTATUS(wstatus);
				VL_DEBUG_MSG_1("python3 child %i has exited with status %i\n", res, child_status);

				goto remove_and_next;
			}
		}
		else if (errno == ECHILD) {
			VL_MSG_ERR("Warning: ECHILD while waiting for python3 fork pid %i, already waited for? removing it.\n", zombie->pid);
			goto remove_and_next;
		}
		else {
			VL_MSG_ERR("Warning: python3 waitpid error for fork %i: %s\n", zombie->pid, strerror(errno));
		}

		goto next;

		remove_and_next:
			if (prev == NULL) {
				first_zombie = next;
			}
			else {
				prev->next = next;
			}

			child_exit_callback(zombie->pid, callback_arg);

			free(zombie);

			zombie = next;
			continue; // <--- IMPORTANT

		next:
			prev = zombie;
			zombie = next;
	}

	pthread_mutex_unlock (&fork_lock);
}

static void __rrr_py_push_zombie_unlocked (pid_t pid) {
	struct python3_fork_zombie *zombie = malloc(sizeof(*zombie));
	zombie->pid = pid;
	zombie->next = first_zombie;
	first_zombie = zombie;
}

static void __rrr_py_fork_destroy_unlocked (struct python3_rrr_objects *rrr_objects, struct python3_fork *fork) {
	if (fork->pid > 0) {
		kill(fork->pid, SIGTERM);
	}

	if (fork->socket_main != NULL) {
		if (fork->socket_main->ob_refcnt != 1) {
			VL_BUG("Refcount was not 1 before DECREF for socket_main in rrr_py_fork_destroy_unlocked\n");
		}
		RRR_Py_XDECREF(fork->socket_main);
	}
	if (fork->socket_child != NULL) {
		if (fork->socket_child->ob_refcnt != 1) {
			VL_BUG("Refcount was not 1 before DECREF for socket_child in rrr_py_fork_destroy_unlocked\n");
		}
		RRR_Py_XDECREF(fork->socket_child);
	}

	int found = 0;
	if (rrr_objects->first_fork == fork) {
		rrr_objects->first_fork = fork->next;
		found = 1;
	}
	else {
		for (struct python3_fork *test = rrr_objects->first_fork; test != NULL; test = test->next) {
			if (test->next == fork) {
				test->next = fork->next;
				found = 1;
				break;
			}
		}
	}

	if (found == 0) {
		VL_BUG("Bug: Fork not found in rrr_py_fork_destroy\n");
	}

	free(fork);
}

static void rrr_py_fork_destroy (struct python3_rrr_objects *rrr_objects, struct python3_fork *fork) {
	if (fork == NULL) {
		return;
	}

	pthread_mutex_lock (&fork_lock);
	VL_DEBUG_MSG_1 ("Python3 terminate fork %p pid %i (while terminating single fork)\n", fork, fork->pid);
	__rrr_py_fork_destroy_unlocked(rrr_objects, fork);
	pthread_mutex_unlock (&fork_lock);
}

int rrr_py_invalidate_fork_unlocked (struct python3_rrr_objects *rrr_objects, pid_t pid) {
	int ret = 1;

	for (struct python3_fork *test = rrr_objects->first_fork; test != NULL; test = test->next) {
		if (test->pid == pid) {
			VL_DEBUG_MSG_1 ("Python3 invalidate fork %p pid %i\n", test, pid);
			test->invalid = 1;
			ret = 0;
			break;
		}
	}

	return ret;
}

void rrr_py_terminate_threads (struct python3_rrr_objects *rrr_objects) {
	int count = 0;

	struct python3_fork *fork = NULL;

	// First, send soft signal (child may stop voluntarily)
	pthread_mutex_lock (&fork_lock);
	fork = rrr_objects->first_fork;
	while (fork != NULL) {
		if (fork->pid > 0) {
			kill(fork->pid, SIGUSR1);
		}
		fork = fork->next;
	}
	pthread_mutex_unlock (&fork_lock);
	usleep(500000);

	// Then, send kill signal
	pthread_mutex_lock (&fork_lock);
	fork = rrr_objects->first_fork;
	while (fork != NULL) {
// TODO : Enable?
//		kill(fork->pid, SIGKILL);
		fork = fork->next;
	}
	pthread_mutex_unlock (&fork_lock);
	usleep(100000);

	pthread_mutex_lock (&fork_lock);
	fork = rrr_objects->first_fork;
	while (fork != NULL) {
		struct python3_fork *next = fork->next;

		VL_DEBUG_MSG_1("Python3 terminate fork %p pid %i (while terminating all)\n", fork, fork->pid);
		__rrr_py_fork_destroy_unlocked(rrr_objects, fork);

		fork = next;
		count++;
	}

	if (rrr_objects->first_fork != NULL) {
		VL_BUG("Not all forks went away in rrr_py_terminate_threads");
	}
	pthread_mutex_unlock (&fork_lock);

	VL_DEBUG_MSG_1("Terminated %i threads in python3 terminate threads\n", count);
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

	// Create a new socket. It will bind() and listen()
	socket_main = rrr_python3_socket_new(NULL);
	if (socket_main == NULL) {
		VL_MSG_ERR("Could not create socket in rrr_py_fork_new\n");
		goto err;
	}

	// Create another socket. It will connect() to the first one
	socket_child = rrr_python3_socket_new(rrr_python3_socket_get_filename(socket_main));
	if (socket_child == NULL) {
		VL_MSG_ERR("Could not create socket in rrr_py_fork_new\n");
		goto err;
	}

	// Make the main socket accept connection
	if (rrr_python3_socket_accept(socket_main) != 0) {
		VL_MSG_ERR("Could not accept() on main socket in rrr_py_fork_new\n");
		goto err;
	}

	ret->socket_main = socket_main;
	ret->socket_child = socket_child;

	pthread_mutex_lock (&fork_lock);
	if (rrr_objects->first_fork == NULL) {
		rrr_objects->first_fork = ret;
	}
	else {
		ret->next = rrr_objects->first_fork;
		rrr_objects->first_fork = ret;
	}

	pthread_mutex_unlock (&fork_lock);

	return ret;

	err:
	RRR_Py_XDECREF(socket_main);
	RRR_Py_XDECREF(socket_child);
	RRR_FREE_IF_NOT_NULL(ret);

	return NULL;
}

PyObject *__rrr_py_socket_message_to_pyobject (struct rrr_socket_msg *message) {
	PyObject *ret = NULL;
	if (RRR_SOCKET_MSG_IS_VL_MESSAGE(message)) {
		ret = rrr_python3_vl_message_new_from_message (message);
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
		VL_MSG_ERR("Unsupported socket message type %u received in __rrr_py_socket_message_to_pyobject\n", message->msg_type);
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
	        VL_MSG_ERR("Received SIGPIPE in fork, ignoring\n");
	}
}

struct persistent_rw_child_callback_data {
	struct python3_fork *fork;
	PyObject *function;
	PyObject *config_function;
};

int __rrr_py_persistent_thread_rw_child_callback (struct fifo_callback_args *fifo_callback_data, char *data, unsigned long int size) {
	PyObject *result = NULL;
	PyObject *arg = NULL;

	struct persistent_rw_child_callback_data *callback_data = fifo_callback_data->private_data;
	PyObject *rrr_socket = callback_data->fork->socket_child;
	struct rrr_socket_msg *message = (struct rrr_socket_msg *) data;

	int ret = 0;

	if (size != message->msg_size) {
		VL_BUG("Size mismatch in __rrr_py_persistent_thread_rw_child_callback\n");
	}

	arg = __rrr_py_socket_message_to_pyobject(message);
	if (arg == NULL) {
		VL_MSG_ERR("Unknown message type received in __rrr_py_start_persistent_thread_rw_child\n");
		ret = 1;
		goto out;
	}

	PyObject *function = NULL;

	if (rrr_python3_vl_message_check(arg)) {
		function = callback_data->function;
	}
	else if (rrr_python3_setting_check(arg)) {
		function = callback_data->config_function;
	}

	if (function != NULL) {
		result = PyObject_CallFunctionObjArgs(function, rrr_socket, arg, NULL);
		if (result == NULL) {
			VL_MSG_ERR("Error while calling python3 function in __rrr_py_start_persistent_thread_rw_child pid %i\n",
					getpid());
			PyErr_Print();
			ret = 1;
			goto out;

		}
		if (!PyObject_IsTrue(result)) {
			VL_MSG_ERR("Non-true returned from python3 function in __rrr_py_start_persistent_thread_rw_child pid %i\n",
					getpid());
			ret = 1;
			goto out;
		}
	}
	else {
		VL_DEBUG_MSG_3("Python3 no functions define for received message type\n");
	}

	if (ret != 0) {
		ret = FIFO_CALLBACK_ERR | FIFO_SEARCH_STOP;
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
			VL_MSG_ERR("Error while calling python3 function in __rrr_py_start_persistent_thread_ro_child pid %i\n",
					getpid());
			PyErr_Print();
			ret = 1;
			goto out;

		}
		if (!PyObject_IsTrue(result)) {
			VL_MSG_ERR("Non-true returned from python3 function in __rrr_py_start_persistent_thread_ro_child pid %i\n",
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
				VL_MSG_ERR("Error while checking for packets in __rrr_py_start_persistent_thread_ro_child pid %i\n",
						getpid());
			}
			if (result != NULL) {
				VL_BUG("Python3 received packet in read-only fork\n");
			}
			recv_check_interval = 200;
		}
	}

	out:
	RRR_Py_XDECREF(result);
	if (VL_DEBUGLEVEL_1 || ret != 0) {
		VL_DEBUG_MSG("Pytohn3 child persistent ro pid %i exiting with return value %i, fork running is %i\n",
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
	struct fifo_buffer receive_buffer;
	PyObject *rrr_socket = fork->socket_child;

	*start_sourcing_requested = 0;

	if (fifo_buffer_init(&receive_buffer) != 0) {
		VL_MSG_ERR("Could not initialize fifo buffer in __rrr_py_start_persistent_thread_rw_child\n");
		goto out;
	}

	struct persistent_rw_child_callback_data child_callback_data = {
			fork, function, config_function
	};
	struct fifo_callback_args fifo_callback_args = {
			NULL, &child_callback_data, 0
	};

	int ret = 0;
	while (rrr_py_fork_running && (*start_sourcing_requested == 0)) {
		int max = 100;
		while (rrr_py_fork_running && (--max != 0)) {
			ret = fork->recv(&message, rrr_socket);
			if (ret != 0) {
				VL_MSG_ERR("Error from socket receive function in python3 persistent rw child process\n");
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
					VL_MSG_ERR("Unknown flags %u in control message in __rrr_py_start_persistent_thread_rw_child\n",
							RRR_SOCKET_MSG_CTRL_FLAGS(message));
					ret = 1;
					goto out;
				}

				RRR_FREE_IF_NOT_NULL(message);
			}
			else {
				fifo_buffer_write(&receive_buffer, (char*) message, message->msg_size);
				message = NULL;
			}
		}

		ret = fifo_read_clear_forward(&receive_buffer, NULL, __rrr_py_persistent_thread_rw_child_callback, &fifo_callback_args, 30);
		if (ret != 0) {
			VL_MSG_ERR("Error from fifo buffer in python3 persistent rw child process\n");
			break;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(message);
	fifo_buffer_invalidate(&receive_buffer);

	if (VL_DEBUGLEVEL_1 || ret != 0) {
		VL_DEBUG_MSG("Pytohn3 child persistent rw process exiting with return value %i, fork running is %i\n", ret, rrr_py_fork_running);
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
	(void)(arg);
	PyOS_BeforeFork();

	int ret = fork();

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
		printf ("=== FORK PID %i ========================================================================================\n", ret);
	}

	return ret;
}

static int __fork_callback(void *arg) {
	return rrr_py_with_global_tstate_do(__fork_main_tstate_callback, arg);
}

static pid_t __rrr_py_fork_intermediate (
		PyObject *function,
		PyObject *config_function,
		struct python3_fork *fork_data,
		void (*child_method)(PyObject *function, PyObject *config_function, struct python3_fork *fork)
) {
	pid_t ret = 0;

	VL_DEBUG_MSG_1("Before fork child socket is %i\n", rrr_python3_socket_get_connected_fd(fork_data->socket_child));
	VL_DEBUG_MSG_1("Before fork main  socket is %i\n", rrr_python3_socket_get_connected_fd(fork_data->socket_main));

	ret = rrr_socket_with_lock_do(__fork_callback, NULL);

	if (ret != 0) {
		if (ret < 0) {
			VL_MSG_ERR("Could not fork python3: %s\n", strerror(errno));
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

	VL_DEBUG_MSG_1("Child %i socket is %i\n", getpid(), rrr_python3_socket_get_connected_fd(fork_data->socket_child));
	VL_DEBUG_MSG_1("Child closing sockets of main\n");
	RRR_Py_XDECREF(fork_data->socket_main);

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

	VL_DEBUG_MSG_1("Child %i closing sockets\n", getpid());
	rrr_socket_close_all_except(rrr_python3_socket_get_connected_fd(fork_data->socket_child));
	VL_DEBUG_MSG_1("Child %i decref socket\n", getpid());
	RRR_Py_XDECREF(fork_data->socket_child);
	VL_DEBUG_MSG_1("Child %i return\n", getpid());
	exit(ret);

	/////////////////
	// PARENT CODE //
	/////////////////

	out_main:

	VL_DEBUG_MSG_1("Main closing sockets of child\n");
	RRR_Py_XDECREF(fork_data->socket_child);
	fork_data->socket_child = NULL;

	pthread_mutex_lock(&fork_lock);
	fork_data->pid = ret;

	// Prepare to accept SIGCHLD when this fork exits
	__rrr_py_push_zombie_unlocked(ret);
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
		struct python3_rrr_objects *rrr_objects,
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
	VL_DEBUG_MSG_3("Start thread of module %s function %s config function %s\n",
			module_name, function_name, config_function_name);

	fork = rrr_py_fork_new(rrr_objects);
	if (fork == NULL) {
		VL_MSG_ERR("Could not start thread.\n");
		ret = 1;
		goto out;
	}

//	printf ("New fork main  refcount: %li\n", fork->socket_main->ob_refcnt);
//	printf ("New fork child refcount: %li\n", fork->socket_child->ob_refcnt);

	py_module_name = PyUnicode_FromString(module_name);
	module = PyImport_GetModule(py_module_name);
//	printf ("Module %s already loaded? %p\n", module_name, module);
	if (module == NULL && (module = PyImport_ImportModule(module_name)) == NULL) {
		VL_MSG_ERR("Could not import module %s while starting thread:\n", module_name);
		PyErr_Print();
		ret = 1;
		goto out;
	}
//	printf ("Module %s loaded: %p\n", module_name, module);

	if ((module_dict = PyModule_GetDict(module)) == NULL) { // Borrowed reference
		VL_MSG_ERR("Could not get dictionary of module %s while starting thread:\n", module_name);
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
		VL_MSG_ERR("Could not get function %s from module %s while starting thread\n",
				function_name, module_name);
		ret = 1;
		goto out;
	}

	if (config_function_name != NULL && *config_function_name != '\0') {
		if ((config_function = rrr_py_import_function(module_dict, config_function_name)) == NULL) {
			VL_MSG_ERR("Could not get config function %s from module %s while starting thread\n",
					config_function_name, module_name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = start_method(function, config_function, fork)) != 0) {
		VL_MSG_ERR("Could not fork python3 with function %s config function %s from %s. Return value: %i\n",
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
		rrr_py_fork_destroy(rrr_objects, fork);
	}
	return ret;
}

int rrr_py_start_persistent_rw_thread (
		struct python3_fork **result_fork,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		const char *config_function_name
) {
	return __rrr_py_start_thread (
			result_fork,
			rrr_objects,
			module_name,
			function_name,
			config_function_name,
			__rrr_py_start_persistent_rw_thread_intermediate
	);
}

int rrr_py_persistent_receive_message (
		struct python3_fork *fork,
		int (*callback)(struct rrr_socket_msg *message, void *arg),
		void *callback_arg
) {
	int ret = 0;
	struct rrr_socket_msg *message = NULL;

	int counter = 0;
	while (++counter <= 500) {
		if (fork->invalid == 1) {
			VL_MSG_ERR("Fork was invalid in rrr_py_persistent_receive_message, child has exited\n");
			ret = 1;
			break;
		}
		ret = fork->recv(&message, fork->socket_main);
		if (ret != 0) {
			VL_MSG_ERR("Error while receiving message from python3 child\n");
			ret = 1;
			goto out;
		}

		if (message == NULL) {
			break;
		}

		VL_DEBUG_MSG_3("rrr_py_persistent_receive_message got a message\n");

		// If ret == 0, callback has taken control of memory
		// If ret != 0, there is an error and we must free memory
		ret = callback(message, callback_arg);
		if (ret != 0) {
			VL_MSG_ERR("Error from callback function while receiving message from python3 child\n");
			ret = 1;
			goto out;
		}

		message = NULL;
	}

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int rrr_py_persistent_process_message (
		struct python3_fork *fork,
		struct rrr_socket_msg *message
) {
	int ret = 0;

	VL_DEBUG_MSG_3("rrr_py_persistent_process_message processing message\n");

	if (fork->invalid == 1) {
		VL_MSG_ERR("Fork was invalid in rrr_py_persistent_process_message, child has exited\n");
		ret = 1;
		goto out;
	}

	ret = fork->send(fork->socket_main, message);
	if (ret != 0) {
		VL_MSG_ERR("Could not process new python3 message object in rrr_py_persistent_process_message\n");
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
		VL_MSG_ERR("Error while sending control message to fork in rrr_py_persistent_start_sourcing\n");
		return 1;
	}
	return 0;
}

void rrr_py_destroy_rrr_objects (struct python3_rrr_objects *rrr_objects) {
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
		VL_MSG_ERR("Could not add rrr_helper module to current thread state dict:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	printf ("RRR helper module: %p refcount %li\n", rrr_helper_module, rrr_helper_module->ob_refcnt);
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

	memset (target, '\0', sizeof(*target));

	res = PyRun_String(rrr_py_import_final, Py_file_input, dictionary, dictionary);
	if (res == NULL) {
		VL_MSG_ERR("Could not run initial python3 code to set up RRR environment: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	RRR_Py_XDECREF(res);

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

	out:
	RRR_FREE_IF_NOT_NULL(rrr_py_import_final);
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
		VL_DEBUG_MSG_1 ("python3 finalize\n");
		PyEval_RestoreThread(main_python_tstate);
		Py_Finalize();
		main_python_tstate = NULL;
	}
	__rrr_py_global_unlock(NULL);
}

int rrr_py_with_global_tstate_do(int (*callback)(void *arg, PyThreadState *tstate_orig), void *arg) {
	int ret = 0;

	// XXX    Feel free to read through this and check if it's correct. The
	//        goal here is that this function may be called from any context
	//        and switch to main thread state. If another thread state was
	//        already active, it is saved and then restored again after the work
	//        is complete

	PyThreadState *state_orig = NULL;

	if (PyGILState_Check()) {
			state_orig = PyEval_SaveThread();
	}

	PyEval_RestoreThread(main_python_tstate);
	ret = callback(arg, state_orig);
	PyEval_SaveThread();

	if (state_orig != 0) {
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
