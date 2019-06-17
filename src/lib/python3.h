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

PyObject *rrr_py_import_object (PyObject *main_module, const char *symbol);
PyObject *rrr_py_import_function (PyObject *main_module, const char *symbol);
PyObject *rrr_py_call_function_no_args(PyObject *function);
PyObject *rrr_py_import_and_call_function_no_args(PyObject *main_module, const char *symbol);
