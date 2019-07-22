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

#include "messages.h"
#include "python3_vl_message.h"
#include "python3_module_common.h"

struct rrr_python3_vl_message_data {
	PyObject_HEAD
	struct vl_message message;
};


static int rrr_python3_vl_message_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	return 0;
}

void rrr_python3_vl_message_f_dealloc (PyObject *self) {
	PyObject_Del(self);
}

static PyObject *rrr_python3_vl_message_f_get_timestamp_from (PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);
	return PyLong_FromLong(data->message.timestamp_from);
}

static PyMethodDef vl_message_methods[] = {
		{
				ml_name:	"get_filename",
				ml_meth:	(PyCFunction) rrr_python3_vl_message_f_get_timestamp_from,
				ml_flags:	METH_NOARGS,
				ml_doc:		"Get parameter 'Timestamp from'"
		},
		{ NULL, NULL, 0, NULL }
};

PyTypeObject rrr_python3_vl_message_type = {
		ob_base:			PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    tp_name:			RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_VL_MESSAGE_TYPE_NAME,
	    tp_basicsize:		sizeof(struct rrr_python3_vl_message_data),
		tp_itemsize:		0,
	    tp_dealloc:			(destructor) rrr_python3_vl_message_f_dealloc,
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
	    tp_methods:			vl_message_methods,
	    tp_members:			NULL,
	    tp_getset:			NULL,
	    tp_base:			NULL,
	    tp_dict:			NULL,
	    tp_descr_get:		NULL,
	    tp_descr_set:		NULL,
	    tp_dictoffset:		0,
	    tp_init:			rrr_python3_vl_message_f_init,
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
