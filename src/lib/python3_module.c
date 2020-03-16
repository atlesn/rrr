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

#include <Python.h>

#include "python3_common.h"
#include "python3_module.h"
#include "python3_module_common.h"
#include "../global.h"

static PyMethodDef module_methods[] = {
		{ NULL, NULL, 0, NULL }
};

static PyModuleDef module_definition = {
		.m_base		= PyModuleDef_HEAD_INIT,
		.m_name		= "rrr_helper",
		.m_doc		= "ReadRouteRecord helper module for C<->Python integration",
		.m_size		= 0,
		.m_methods	= module_methods,
		.m_slots	= NULL,
		.m_traverse	= NULL,
		.m_clear	= NULL,
		.m_free		= NULL
};

/*
 * We need a lock because these methods are called before Py_Initialzie(), hence
 * there are no python locking.
 */
static pthread_mutex_t rrr_python3_module_create_lock = PTHREAD_MUTEX_INITIALIZER;

PyMODINIT_FUNC __rrr_python3_module_create_or_get (void) {
	int err = 0;

	PyObject *rrr_python3_module = NULL;

//	if (rrr_python3_module == NULL) {
		if (PyType_Ready(&rrr_python3_socket_type) < 0) {
			RRR_MSG_ERR("PyType_Ready for python3 socket type failed:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		if (PyType_Ready(&rrr_python3_rrr_message_type) < 0) {
			RRR_MSG_ERR("PyType_Ready for python3 rrr_message type failed:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		if (PyType_Ready(&rrr_python3_array_type) < 0) {
			RRR_MSG_ERR("PyType_Ready for python3 array type failed:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		if (PyType_Ready(&rrr_python3_array_value_type) < 0) {
			RRR_MSG_ERR("PyType_Ready for python3 array value type failed:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		printf ("python3 setting type flags 1: %lu", rrr_python3_setting_type.tp_flags);
		if (PyType_Ready(&rrr_python3_setting_type) < 0) {
			RRR_MSG_ERR("PyType_Ready for python3 setting type failed:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		printf ("python3 setting type flags 2: %lu", rrr_python3_setting_type.tp_flags);

		if ((rrr_python3_module = PyModule_Create(&module_definition)) == NULL) {
			RRR_MSG_ERR("Could create python3 module from definition:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}

		Py_INCREF((PyObject *) &rrr_python3_socket_type);
		if (PyModule_AddObject(rrr_python3_module, RRR_PYTHON3_SOCKET_TYPE_NAME, (PyObject *) &rrr_python3_socket_type) != 0) {
			RRR_MSG_ERR("Could not add python3 socket type to module:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		Py_INCREF((PyObject *) &rrr_python3_rrr_message_type);
		if (PyModule_AddObject(rrr_python3_module, RRR_PYTHON3_RRR_MESSAGE_TYPE_NAME, (PyObject *) &rrr_python3_rrr_message_type) != 0) {
			RRR_MSG_ERR("Could not add python3 rrr_message type to module:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		Py_INCREF((PyObject *) &rrr_python3_array_type);
		if (PyModule_AddObject(rrr_python3_module, RRR_PYTHON3_ARRAY_TYPE_NAME, (PyObject *) &rrr_python3_array_type) != 0) {
			RRR_MSG_ERR("Could not add python3 array type to module:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		Py_INCREF((PyObject *) &rrr_python3_array_value_type);
		if (PyModule_AddObject(rrr_python3_module, RRR_PYTHON3_ARRAY_VALUE_TYPE_NAME, (PyObject *) &rrr_python3_array_value_type) != 0) {
			RRR_MSG_ERR("Could not add python3 array type to module:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
		Py_INCREF((PyObject *) &rrr_python3_setting_type);
		if (PyModule_AddObject(rrr_python3_module, RRR_PYTHON3_SETTING_TYPE_NAME, (PyObject *) &rrr_python3_setting_type) != 0) {
			RRR_MSG_ERR("Could not add python3 setting type to module:\n");
			PyErr_Print();
			err = 1;
			goto out;
		}
//	}

//	RRR_Py_INCREF(rrr_python3_module);

	out:
	if (err) {
		RRR_Py_XDECREF(rrr_python3_module);
	}
	return rrr_python3_module;
}

int rrr_python3_module_append_inittab() {
	int ret = 0;

	pthread_mutex_lock(&rrr_python3_module_create_lock);

	static int append_inittab_done = 0;

	if (append_inittab_done == 1) {
		goto out;
	}

	if (PyImport_AppendInittab(RRR_PYTHON3_MODULE_NAME, __rrr_python3_module_create_or_get) != 0) {
		RRR_MSG_ERR("Could not append rrr helper module to Python3 inittab:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	append_inittab_done = 1;

	out:
	pthread_mutex_unlock(&rrr_python3_module_create_lock);
	return ret;
}

void rrr_python3_module_dump_dict_keys(void) {
	PyObject *module = PyState_FindModule(&module_definition);
	if (module == NULL) {
		PyErr_Print();
		RRR_BUG("Could not dump rrr helper module keys: Module not found\n");
	}
	rrr_py_dump_dict_entries(PyModule_GetDict(module));
}

