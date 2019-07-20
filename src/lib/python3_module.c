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

#include "python3_module.h"
#include "python3.h"

struct rrr_python3_socket_data {
	int dummy;
};

static int rrr_python3_module_socket_init (PyObject *self, PyObject *args, PyObject *kwds) {
	(void)(self);
	(void)(args);
	(void)(kwds);
	return 0;
}

static PyObject *rrr_python3_module_f_socket_test (PyObject *self, PyObject *args, PyObject *kwds) {
	PyObject *ret = Py_None;
	char *valid_keys[] = {"arg1", "arg2", NULL};

	(void)(self);

	int arg1 = 0;
	char *arg2 = NULL; // Python manages memory
	static char *arg2_default = "default argument 2";

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|s", valid_keys, &arg1, &arg2)) {
		ret = NULL;
		goto out;
	}

	if (arg2 == NULL) {
		arg2 = arg2_default;
	}

	printf ("rrr_python3_module_f_test called: arg1: %i, arg2: %s\n", arg1, arg2);

	out:
	Py_INCREF(ret); // <-- Yes, INC is correct
	return ret;
}

void rrr_python3_socket_dealloc (PyObject *self) {
	PyObject_Del(self);
}

void rrr_python3_socket_finalize (PyObject *self) {
	(void)(self);
}

PyObject *rrr_python3_socket_iternext (PyObject *self) {
	(void)(self);
	return NULL;
}

static PyMethodDef socket_methods[] = {
		{
				ml_name:	"test",
				ml_meth:	(PyCFunction) rrr_python3_module_f_socket_test,
				ml_flags:	METH_VARARGS | METH_KEYWORDS,
				ml_doc:		"Tests that basics for socket works"
		},
		{ 0 }
};

static PyTypeObject rrr_python3_socket_type = {
		ob_base:			PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    tp_name:			RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_SOCKET_TYPE_NAME,
	    tp_basicsize:		sizeof(struct rrr_python3_socket_data),
		tp_itemsize:		0,
	    tp_dealloc:			(destructor) rrr_python3_socket_dealloc,
	    tp_print:			NULL,
	    tp_getattr:			NULL,
	    tp_setattr:			NULL,
	    tp_as_async:		NULL,
	    tp_repr:			NULL,
	    tp_as_number:		NULL,
	    tp_as_sequence:		NULL,
	    tp_as_mapping:		NULL,
	    tp_hash:			NULL,
	    tp_call:			NULL,
	    tp_str:				NULL,
	    tp_getattro:		NULL,
	    tp_setattro:		NULL,
	    tp_as_buffer:		NULL,
	    tp_flags:			Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_FINALIZE,
	    tp_doc:				"ReadRouteRecord type for UNIX socket IPC",
	    tp_traverse:		NULL,
	    tp_clear:			NULL,
	    tp_richcompare:		NULL,
	    tp_weaklistoffset:	0,
	    tp_iter:			PyObject_SelfIter,
	    tp_iternext:		(iternextfunc) rrr_python3_socket_iternext,
	    tp_methods:			socket_methods,
	    tp_members:			NULL,
	    tp_getset:			NULL,
	    tp_base:			NULL,
	    tp_dict:			NULL,
	    tp_descr_get:		NULL,
	    tp_descr_set:		NULL,
	    tp_dictoffset:		0,
	    tp_init:			rrr_python3_module_socket_init,
	    tp_alloc:			PyType_GenericAlloc,
	    tp_new:				PyType_GenericNew,
	    tp_free:			NULL,
	    tp_is_gc:			NULL,
	    tp_bases:			NULL,
	    tp_mro:				NULL,
	    tp_cache:			NULL,
	    tp_subclasses:		NULL,
	    tp_weaklist:		NULL,
	    tp_del:				NULL,
	    tp_version_tag:		0,
	    tp_finalize:		(destructor) rrr_python3_socket_finalize
};

static PyObject *rrr_python3_module_f_test (PyObject *self, PyObject *args, PyObject *kwds) {
	PyObject *ret = Py_None;
	char *valid_keys[] = {"arg1", "arg2", NULL};

	(void)(self);

	int arg1 = 0;
	char *arg2 = NULL; // Python manages memory
	static char *arg2_default = "default argument 2";

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|s", valid_keys, &arg1, &arg2)) {
		ret = NULL;
		goto out;
	}

	if (arg2 == NULL) {
		arg2 = arg2_default;
	}

	printf ("rrr_python3_module_f_test called: arg1: %i, arg2: %s\n", arg1, arg2);

	out:
	Py_INCREF(ret); // <-- Yes, INC is correct
	return ret;
}

static PyMethodDef module_methods[] = {
		{
				ml_name:	"test",
				ml_meth:	(PyCFunction) rrr_python3_module_f_test,
				ml_flags:	METH_VARARGS | METH_KEYWORDS,
				ml_doc:		"Tests that basics works"
		},
		{ 0 }
};

static PyModuleDef module_definition = {
		m_base:		PyModuleDef_HEAD_INIT,
		m_name:		"rrr_helper",
		m_doc:		"ReadRouteRecord helper module for C<->Python integration",
		m_size:		-1,
		m_methods:	module_methods,
		m_slots:	NULL,
		m_traverse:	NULL,
		m_clear:	NULL,
		m_free:		NULL
};

static pthread_mutex_t rrr_python3_module_create_lock = PTHREAD_MUTEX_INITIALIZER;

PyMODINIT_FUNC __rrr_python3_module_create_or_get (void) {
	int err = 0;

	pthread_mutex_lock(&rrr_python3_module_create_lock);

	static PyObject *rrr_python3_module = NULL;

	if (rrr_python3_module == NULL) {
		if (PyType_Ready(&rrr_python3_socket_type) != 0) {
			VL_MSG_ERR("PyType_Ready for python3 socket type failed:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}

		if ((rrr_python3_module = PyModule_Create(&module_definition)) == NULL) {
			VL_MSG_ERR("Could create python3 module from definition:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		Py_INCREF(rrr_python3_module);

		Py_INCREF((PyObject *) &rrr_python3_socket_type);
		if (PyModule_AddObject(rrr_python3_module, RRR_PYTHON3_SOCKET_TYPE_NAME, (PyObject *) &rrr_python3_socket_type) != 0) {
			Py_DECREF((PyObject *) &rrr_python3_socket_type);
			VL_MSG_ERR("Could no add python3 socket type to module:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
	}
	else {
		Py_INCREF(rrr_python3_module);
	}

	out:
	if (err != 0) {
		Py_XDECREF(rrr_python3_module);
	}

	pthread_mutex_unlock(&rrr_python3_module_create_lock);
	return rrr_python3_module;
}

int rrr_python3_module_append_inittab() {
	int ret = 0;

	if (PyImport_AppendInittab(RRR_PYTHON3_MODULE_NAME, __rrr_python3_module_create_or_get) != 0) {
		VL_MSG_ERR("Could not append rrr helper module to Python3 inittab:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

void rrr_python3_module_dump_dict_keys(void) {
	PyObject *module = PyState_FindModule(&module_definition);
	if (module == NULL) {
		PyErr_Print();
		VL_BUG("Could not dump rrr helper module keys: Module not found\n");
	}
	rrr_py_dump_dict_entries(PyModule_GetDict(PyState_FindModule(&module_definition)));
}
