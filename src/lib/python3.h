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

#define PY_SSIZE_T_CLEAN

#include <sys/types.h>
#include <pthread.h>

#include <Python.h>

#include "../../build_directory.h"

struct rrr_socket_msg;

#define RRR_PYTHON3_OBJECT_CACHE_FULL 2
#define RRR_PYTHON3_OBJECT_CACHE_ERR 1
#define RRR_PYTHON3_OBJECT_CACHE_OK 0

#define RRR_PYTHON3_PERSISTENT_PROCESS_INPUT_MAX 12
#define RRR_PYTHON3_EXTRA_SYS_PATH RRR_BUILD_DIR

#define RRR_PY_PASTE(a,b,c) a ## b ## v

struct python3_thread_state {
	PyThreadState *tstate;
};

struct python3_fork {
	struct python3_fork *next;
	PyObject *socket_main;
	PyObject *socket_child;
	pid_t pid;
	int invalid;

	int (*poll)(PyObject *socket, int timeout);
	int (*recv)(struct rrr_socket_msg **result, PyObject *socket);
	int (*send)(PyObject *socket, struct rrr_socket_msg *message);
};

struct python3_rrr_objects {
	struct python3_fork *first_fork;
};

/* GIL functions */
int python3_swap_thread_in(struct python3_thread_state *python3_thread_ctx, PyThreadState *tstate);
int python3_swap_thread_out(struct python3_thread_state *tstate_holder);

/* Asynchronous functions */
int rrr_py_invalidate_fork_unlocked (struct python3_rrr_objects *rrr_objects, pid_t pid);
void rrr_py_handle_sigchld(void (*child_exit_callback)(pid_t pid, void *callback_arg), void *callback_arg);
void rrr_py_terminate_threads (struct python3_rrr_objects *rrr_objects);
int rrr_py_start_persistent_rw_thread (
		struct python3_fork **result_fork,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
);
int rrr_py_start_persistent_ro_thread (
		struct python3_fork **result_fork,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
);
int rrr_py_start_onetime_rw_thread (
		struct rrr_socket_msg **result,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		struct rrr_socket_msg *arg
);

/* Message handling functions */
int rrr_py_persistent_receive_message (
		struct python3_fork *fork,
		int (*callback)(struct rrr_socket_msg *message, void *arg),
		void *callback_arg
);
int rrr_py_persistent_process_message (
		struct python3_fork *fork,
		struct rrr_socket_msg *message
);

/* State holder functions */
void rrr_py_destroy_rrr_objects (struct python3_rrr_objects *message_maker);
//void rrr_py_dump_dict_entries (PyObject *dict);
int rrr_py_get_rrr_objects (
		struct python3_rrr_objects *target,
		PyObject *dictionary,
		const char **extra_module_paths,
		int module_paths_length
);
int rrr_py_with_global_tstate_do(int (*callback)(void *arg, PyThreadState *tstate_orig), void *arg);
void rrr_py_destroy_thread_state(PyThreadState *tstate);
PyThreadState *rrr_py_new_thread_state(void);
