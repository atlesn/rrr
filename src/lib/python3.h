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
#include <Python.h>

#include "../../build_directory.h"

struct vl_message;

struct python3_thread_state {
	PyThreadState *tstate;
};

#define RRR_PYTHON3_OBJECT_CACHE_FULL 2
#define RRR_PYTHON3_OBJECT_CACHE_ERR 1
#define RRR_PYTHON3_OBJECT_CACHE_OK 0

#define RRR_PYTHON3_PERSISTENT_PROCESS_INPUT_MAX 12
#define RRR_PYTHON3_EXTRA_SYS_PATH RRR_BUILD_DIR

struct python3_object_cache_entry {
	struct python3_object_cache_entry *next;
	PyObject *object;
};

struct python3_object_cache {
	struct python3_object_cache_entry *begin;
	pthread_mutex_t lock;
	unsigned int max;
	unsigned int entries;
	int initialized;
};

#define PASTE(a,b,c) a ## b ## v

#define PYTHON3_PROFILING

#ifdef PYTHON3_PROFILING
#include "vl_time.h"
#define PYTHON3_PROFILE_START(name, target) do { \
		uint64_t profile_##name##_ = time_get_64();\
		uint64_t *profile_##name##_target = &(target)
#define PYTHON3_PROFILE_STOP(name) \
	*(profile_##name##_target) = time_get_64() - profile_##name##_; \
	} while (0)
#else
#define PYTHON3_PROFILE_START(a,b) do {
#define PYTHON3_PROFILE_STOP(a) } while(0)
#endif /* PYTHON3_PROFILING */

struct python3_rrr_objects {
	PyObject *rrr_settings_class;
	PyObject *rrr_settings_get;
	PyObject *rrr_settings_set;
	PyObject *rrr_settings_check_used;
	PyObject *rrr_settings_new;

	PyObject *rrr_global_process_dict;

	PyObject *rrr_onetime_thread_start;
	PyObject *rrr_persistent_thread_start;
	PyObject *rrr_persistent_thread_readonly_start;
	PyObject *rrr_persistent_thread_send_data;
	PyObject *rrr_persistent_thread_send_new_vl_message;
	PyObject *rrr_persistent_thread_recv_data;
	PyObject *rrr_persistent_thread_recv_data_nonblock;
	PyObject *rrr_thread_terminate_all;

	PyObject *vl_message_class;
	PyObject *vl_message_new;

#ifdef PYTHON3_PROFILING
	uint64_t accumulated_time_recv_message_nonblock;
#endif /* PYTHON3_PROFILING */
};

int python3_swap_thread_in(struct python3_thread_state *python3_thread_ctx, PyThreadState *tstate);
int python3_swap_thread_out(struct python3_thread_state *tstate_holder);

/* Cache functions */
int rrr_py_object_cache_init (struct python3_object_cache *cache, unsigned int max);
void rrr_py_object_cache_destroy (struct python3_object_cache *cache);
int rrr_py_object_cache_push (struct python3_object_cache *cache, PyObject *object);
PyObject *rrr_py_object_cache_pop(struct python3_object_cache *cache);

/* General functions */
PyObject *rrr_py_import_object (PyObject *dictionary, const char *symbol);
PyObject *rrr_py_import_function (PyObject *dictionary, const char *symbol);
PyObject *rrr_py_call_function_no_args(PyObject *function);
PyObject *rrr_py_import_and_call_function_no_args(PyObject *dictionary, const char *symbol);

/* Asynchronous functions */
int rrr_py_terminate_threads (struct python3_rrr_objects *rrr_objects);
int rrr_py_start_persistent_thread (
		PyObject **result_process_pipe,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
);
int rrr_py_start_persistent_readonly_thread (
		PyObject **result_process_pipe,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name
);
int rrr_py_call_object_async (
		PyObject **result,
		struct python3_rrr_objects *rrr_objects,
		const char *module_name,
		const char *function_name,
		PyObject *arg
);

/* Message and settings handling functions */
PyObject *rrr_py_new_settings(struct python3_rrr_objects *rrr_objects, struct rrr_instance_settings *settings);
int rrr_py_settings_update_used (
		struct python3_rrr_objects *rrr_objects,
		struct rrr_instance_settings *settings,
		PyObject *py_rrr_settings
);

PyObject *rrr_py_new_empty_message(struct python3_rrr_objects *rrr_objects);
PyObject *rrr_py_new_message(struct python3_rrr_objects *message_maker, const struct vl_message *message);
int rrr_py_message_to_internal(struct vl_message **target, PyObject *py_message);
int rrr_py_persistent_receive_message (
		int *pending_counter,
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		int (*callback)(PyObject *message, void *arg),
		void *callback_arg
);
int rrr_py_persistent_readonly_send_counter (
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		int count
);
int rrr_py_persistent_process_message (
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		PyObject *message
);
int rrr_py_persistent_process_new_messages (
		struct python3_rrr_objects *rrr_objects,
		PyObject *processor_pipe,
		struct vl_message *messages[RRR_PYTHON3_PERSISTENT_PROCESS_INPUT_MAX],
		int count
);
void rrr_py_destroy_rrr_objects (struct python3_rrr_objects *message_maker);
int rrr_py_get_rrr_objects (
		struct python3_rrr_objects *target,
		PyObject *dictionary,
		const char **extra_module_paths,
		int module_paths_length
);
