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

#ifndef RRR_PYTHON3_COMMON_H
#define RRR_PYTHON3_COMMON_H

// #define RRR_PYTHON3_DEBUG_REFCOUNT

#include <Python.h>

static inline void RRR_Py_XDECREF (PyObject *obj) {
	if ((obj) != NULL && (obj)->ob_refcnt == 0) {
		VL_BUG("RRR_Py_XDECREF called with refcount being 0\n");
	}
#ifdef RRR_PYTHON3_DEBUG_REFCOUNT
	VL_DEBUG_MSG("Py_XDECREF %p refcount %li\n", (obj), (obj) == NULL ? 0 : (obj)->ob_refcnt);
#endif
	Py_XDECREF(obj);
}

static inline void RRR_Py_INCREF (PyObject *obj) {
	if ((obj) == NULL) {
		VL_BUG("RRR_Py_INCREF called with NULL obj\n");
	}
#ifdef RRR_PYTHON3_DEBUG_REFCOUNT
	VL_DEBUG_MSG("Py_INCREF %p refcount %li\n", (obj), (obj)->ob_refcnt);
#endif
	Py_INCREF(obj);
}

static inline void RRR_Py_DECREF (PyObject *obj) {
	if ((obj) == NULL || (obj)->ob_refcnt == 0) {
		VL_BUG("RRR_Py_DECREF called with NULL obj or refcount being 0\n");
	}
#ifdef RRR_PYTHON3_DEBUG_REFCOUNT
	VL_DEBUG_MSG("Py_DECREF %p refcount %li\n", (obj), (obj)->ob_refcnt);
#endif
	Py_DECREF(obj);
}

void rrr_py_dump_global_modules(void);
void rrr_py_dump_dict_entries (PyObject *dict);

/* General functions */
PyObject *rrr_py_import_object (PyObject *dictionary, const char *symbol);
PyObject *rrr_py_import_function (PyObject *dictionary, const char *symbol);
PyObject *rrr_py_call_function_no_args(PyObject *function);
PyObject *rrr_py_import_and_call_function_no_args(PyObject *dictionary, const char *symbol);

#endif /* RRR_PYTHON3_COMMON_H */
