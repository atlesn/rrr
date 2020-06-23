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

#ifndef RRR_PYTHON3_H
#define RRR_PYTHON3_H

#define PY_SSIZE_T_CLEAN

#include <sys/types.h>
#include <pthread.h>

#include <Python.h>

#include "../linked_list.h"
#include "../../../build_directory.h"

struct rrr_socket_msg;
struct rrr_setting_packed;
struct rrr_ip_buffer_entry;
struct rrr_fork_handler;

#define RRR_PYTHON3_OBJECT_CACHE_FULL 2
#define RRR_PYTHON3_OBJECT_CACHE_ERR 1
#define RRR_PYTHON3_OBJECT_CACHE_OK 0

#define RRR_PYTHON3_PERSISTENT_PROCESS_INPUT_MAX 12
#define RRR_PYTHON3_EXTRA_SYS_PATH RRR_BUILD_DIR

#define RRR_PY_PASTE(a,b,c) a ## b ## v

struct python3_fork_runtime;

struct python3_fork {
	RRR_LL_NODE(struct python3_fork);
	pid_t pid;
	int invalid;

	struct rrr_fork_handler *fork_handler;

	struct rrr_mmap *mmap;
	struct rrr_mmap_channel *channel_to_fork;
	struct rrr_mmap_channel *channel_from_fork;
};

/* GIL functions */
/*int python3_swap_thread_in (
		struct python3_thread_state *python3_thread_ctx,
		PyThreadState *tstate
);
int python3_swap_thread_out (
		struct python3_thread_state *tstate_holder
);*/

/* Asynchronous functions */
void rrr_py_handle_sigchld (
		pid_t pid,
		void *exit_notify_arg
);
void rrr_py_call_fork_notifications_if_needed (
		struct rrr_fork_handler *handler
);
void rrr_py_fork_terminate_and_destroy (
		struct python3_fork *fork
);
int rrr_py_start_persistent_rw_fork (
		struct python3_fork **result_fork,
		struct rrr_fork_handler *fork_handler,
		const char *module_path,
		const char *module_name,
		const char *function_name,
		const char *config_function_name
);
/*
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
*/
/* Message handling functions */
int rrr_py_persistent_receive_message (
		struct python3_fork *fork,
		int (*callback)(struct rrr_socket_msg *message, void *arg),
		void *callback_arg
);
int rrr_py_persistent_process_read_from_fork (
		void **target,
		size_t *target_size,
		struct python3_fork *fork
);
int rrr_py_persistent_process_setting (
		struct python3_fork *fork,
		const struct rrr_setting_packed *setting
);
int rrr_py_persistent_process_message (
		struct python3_fork *fork,
		const struct rrr_ip_buffer_entry *entry
);
// Stop sending data to the fork and call the function continuously
int rrr_py_persistent_start_sourcing (
		struct python3_fork *fork
);

/* State holder functions */
/*int rrr_py_get_rrr_objects (
		PyObject *dictionary,
		const char **extra_module_paths,
		int module_paths_length
);
int rrr_py_with_global_tstate_do (
		int (*callback)(void *arg, PyThreadState *tstate_orig), void *arg, int force_gil_release
);
void rrr_py_destroy_thread_state (
		PyThreadState *tstate
);
PyThreadState *rrr_py_new_thread_state(void);*/

#endif /* RRR_PYTHON3_H */
