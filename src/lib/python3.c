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
#include <stddef.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "python3.h"
#include "../global.h"

PyObject *rrr_py_import_object (PyObject *main_module, const char *symbol) {
	return PyObject_GetAttrString(main_module, symbol);
}

PyObject *rrr_py_import_function (PyObject *main_module, const char *symbol) {
	PyObject *ret = rrr_py_import_object(main_module, symbol);

	if (ret == NULL) {
		VL_MSG_ERR("Could not load %s function\n", symbol);
		goto out_err;
	}

	if (!PyCallable_Check(ret)) {
	        VL_MSG_ERR("%s was not a callable\n", symbol);
        	goto out_err_cleanup;
	}

	return ret;

	out_err_cleanup:
	Py_XDECREF(ret);

	out_err:
	return NULL;
}

PyObject *rrr_py_call_function_no_args(PyObject *function) {
	PyObject *args = PyTuple_New(0);
	PyObject *result = PyEval_CallObject(function, args);
	Py_XDECREF(args);
	if (result == NULL) {
		PyErr_Print();
	}
	return result;
}

PyObject *rrr_py_import_and_call_function_no_args(PyObject *main_module, const char *symbol) {
	PyObject *result = NULL;

	PyObject *function = rrr_py_import_function(main_module, symbol);
	if (function == NULL) {
		goto out_cleanup;
	}

	PyObject *args = PyTuple_New(0);
	result = PyEval_CallObject(function, args);
	Py_XDECREF(args);
	if (result == NULL) {
		VL_MSG_ERR("NULL result from function %s\n", symbol);
		PyErr_Print();
		goto out_cleanup;
	}

	out_cleanup:
	Py_XDECREF(function);

	return result;
}
