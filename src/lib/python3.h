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

struct vl_message;

struct python3_thread_state {
	PyThreadState *tstate;
	int *condition;
};

struct python3_message_maker {
	PyObject *vl_message_class;
	PyObject *vl_message_new;
};

struct python3_thread_state python3_swap_thread_in(PyThreadState *tstate, int *condition);
void python3_swap_thread_out(struct python3_thread_state *tstate_holder);
void python3_swap_thread_out_void(void *arg) {
	python3_swap_thread_out(arg);
}

#define PYTHON3_THREAD_IN(istate,release_condition) \
	do { struct python3_thread_state python3_thread_ctx = python3_swap_thread_in(istate,release_condition); \
	pthread_cleanup_push(python3_swap_thread_out_void, &python3_thread_ctx);

#define PYTHON3_THREAD_OK() \
	(python3_thread_ctx.tstate != NULL)

#define PYTHON3_THREAD_OUT() \
	pthread_cleanup_pop(1); } while (0);

/* General functions */
PyObject *rrr_py_import_object (PyObject *dictionary, const char *symbol);
PyObject *rrr_py_import_function (PyObject *dictionary, const char *symbol);
PyObject *rrr_py_call_function_no_args(PyObject *function);
PyObject *rrr_py_import_and_call_function_no_args(PyObject *dictionary, const char *symbol);

/* Message handling functions */
PyObject *rrr_py_new_message(struct python3_message_maker *message_maker, const struct vl_message *message);
int rrr_py_message_to_internal(struct vl_message **target, PyObject *py_message);
int rrr_py_process_message(PyObject **result, PyObject *process_function, PyObject *message);
void rrr_py_destroy_message_struct (struct python3_message_maker *message_maker);
int rrr_py_get_message_struct (struct python3_message_maker *target, PyObject *dictionary);
