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

#include <Python.h>

#include "settings.h"
#include "python3_module_common.h"

/*
 struct rrr_setting_packed {
	RRR_SOCKET_MSG_HEAD;
	char name[RRR_SETTINGS_MAX_NAME_SIZE];
	vl_u32 type;
	vl_u32 was_used;
	vl_u32 data_size;
	char var_data[1];
} __attribute((packed));
 */

struct rrr_python3_setting_data {
	PyObject_HEAD
	struct rrr_setting_packed setting;
};

static PyMethodDef setting_methods[] = {
		{
				ml_name:	"set",
				ml_meth:	(PyCFunction) rrr_python3_setting_f_set,
				ml_flags:	METH_FASTCALL,
				ml_doc:		"Set all parameters"
		},
		{
				ml_name:	"set_data",
				ml_meth:	(PyCFunction) rrr_python3_setting_f_set_data,
				ml_flags:	METH_O,
				ml_doc:		"Set data parameter"
		},
		{
				ml_name:	"get_data",
				ml_meth:	(PyCFunction) rrr_python3_setting_f_get_data,
				ml_flags:	METH_NOARGS,
				ml_doc:		"Get data parameter from message as byte array"
		},
		{ NULL, NULL, 0, NULL }
};

static PyMemberDef setting_members[] = {
		{ NULL, 0, 0, 0, NULL}
};

PyTypeObject rrr_python3_setting_type = {
		ob_base:			PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    tp_name:			RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_SETTING_TYPE_NAME,
	    tp_basicsize:		sizeof(struct rrr_python3_setting_data),
		tp_itemsize:		0,
	    tp_dealloc:			(destructor) rrr_python3_setting_f_dealloc,
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
	    tp_flags:			Py_TPFLAGS_DEFAULT,
	    tp_doc:				"ReadRouteRecord type for VL Message structure",
	    tp_traverse:		NULL,
	    tp_clear:			NULL,
	    tp_richcompare:		NULL,
	    tp_weaklistoffset:	0,
	    tp_iter:			NULL,
	    tp_iternext:		NULL,
	    tp_methods:			setting_methods,
	    tp_members:			setting_members,
	    tp_getset:			NULL,
	    tp_base:			NULL,
	    tp_dict:			NULL,
	    tp_descr_get:		NULL,
	    tp_descr_set:		NULL,
	    tp_dictoffset:		0,
	    tp_init:			rrr_python3_setting_f_init,
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
	    tp_finalize:		NULL
};

struct rrr_setting_packed *rrr_python3_setting_get_setting (PyObject *self) {
	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;
	return &data->setting;
}

PyObject *rrr_python3_setting_new_from_setting (struct rrr_socket_msg *msg) {
	struct rrr_python3_setting_data *ret = NULL;

	if (msg->msg_size != sizeof(ret->message)) {
		VL_BUG("Received object of wrong size in rrr_python3_setting_new_from_message\n");
	}

	ret = PyObject_New(struct rrr_python3_setting_data, &rrr_python3_setting_type);
	if (ret) {
		memcpy(&ret->message, msg, sizeof(ret->message));
	}

	return (PyObject *) ret;
}
