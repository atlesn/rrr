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

#include <stddef.h>
#include <Python.h>

#include "python3_common.h"
#include "../global.h"

PyObject *rrr_py_import_object (PyObject *dictionary, const char *symbol) {
	PyObject *res = PyDict_GetItemString(dictionary, symbol);
	Py_XINCREF(res);
	return res;
}

PyObject *rrr_py_import_function (PyObject *dictionary, const char *symbol) {
	PyObject *ret = rrr_py_import_object(dictionary, symbol);

	if (ret == NULL) {
		RRR_MSG_ERR("Could not load %s function\n", symbol);
		goto out_err;
	}

	if (!PyCallable_Check(ret)) {
	        RRR_MSG_ERR("%s was not a callable\n", symbol);
        	goto out_err_cleanup;
	}

	return ret;

	out_err_cleanup:
	RRR_Py_XDECREF(ret);

	out_err:
	return NULL;
}

PyObject *rrr_py_call_function_no_args(PyObject *function) {
	PyObject *args = PyTuple_New(0);
	PyObject *result = PyEval_CallObject(function, args);
	RRR_Py_XDECREF(args);
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
	RRR_Py_XDECREF(args);
	if (result == NULL) {
		RRR_MSG_ERR("NULL result from function %s\n", symbol);
		PyErr_Print();
		goto out_cleanup;
	}

	out_cleanup:
	RRR_Py_XDECREF(function);

	return result;
}

void rrr_py_dump_global_modules(void) {
#if PY_VERSION_HEX >= 0x03080000
	printf("Module dumping not possible in Python >= 3.8\n");
#else
	// Hack to get tstate
	PyThreadState *tstate = PyEval_SaveThread();
	PyEval_RestoreThread(tstate);
	PyInterpreterState *state = tstate->interp;

	PyObject *obj;
	int max = PyList_GET_SIZE(state->modules_by_index);
	for (int i = 0; i < max && (obj = PyList_GetItem(state->modules_by_index, i)) != NULL; i++) {
		if (strcmp(obj->ob_type->tp_name, "module") == 0) {
			PyObject *name_obj  = PyObject_GetAttrString(obj, "__name__");
			if (name_obj == NULL) {
				RRR_MSG_ERR("Could not get name of object %s:\n",obj->ob_type->tp_name );
				PyErr_Print();
				continue;
			}

			const char *name = PyUnicode_AsUTF8(name_obj);
			if (name != NULL) {
				printf ("-> [%i]: %s\n", i, name);
			}
			else {
				RRR_MSG_ERR ("Warning: __name__ not found in module object with index %i\n", i);
			}

			RRR_Py_XDECREF(name_obj);
		}
	}
#endif
}

void rrr_py_dump_dict_entries (PyObject *dict) {
	if (!PyDict_CheckExact(dict)) {
		RRR_BUG("Bug: Non-PyDict object given to __rrr_py_dump_dict_entries\n");
	}

    PyObject *keys = PyDict_Keys(dict);
    int n = PyList_Size(keys);

    for (int i = 0; i < n; i++) {
    	PyObject *obj = PyList_GetItem(keys, i);
    	const char *key = PyUnicode_AsUTF8(obj);
		printf ("-> [%i]: %s\n", i, key);
    }

    RRR_Py_XDECREF(keys);
}
