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
#include <structmember.h>

#include "python3_module_common.h"
#include "python3_vl_message.h"
#include "rrr_socket.h"
#include "messages.h"

//static const unsigned long int max_8 = 0xff;
//static const unsigned long int max_16 = 0xffff;
static const unsigned long int max_32 = 0xffffffff;
static const unsigned long int max_64 = 0xffffffffffffffff;

struct rrr_python3_vl_message_data {
	PyObject_HEAD
	struct vl_message message;
};

int __rrr_python3_vl_message_set_data (PyObject *self, PyObject *byte_data) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	int ret = 0;

	const char *str;
	Py_ssize_t len;
	if (PyByteArray_Check(byte_data)) {
		len = PyByteArray_Size(byte_data);
		str = PyByteArray_AsString(byte_data);
	}
	else if (PyUnicode_Check(byte_data)) {
		str = PyUnicode_AsUTF8AndSize(byte_data, &len);
	}
	else {
		VL_MSG_ERR("Unknown data type to vl_message.set(), must be Bytearray or Unicode\n");
		ret = 1;
		goto out;
	}

	if (len > MSG_DATA_MAX_LENGTH) {
		VL_MSG_ERR("Specified length of data to vl_message.set() exceeds maximum of %i\n", MSG_DATA_MAX_LENGTH);
		ret = 1;
		goto out;
	}

	memcpy(data->message.data, str, len);
	data->message.length = len;

	out:
	return ret;
}

static PyObject *rrr_python3_vl_message_f_set_data (PyObject *self, PyObject *args) {
	if (__rrr_python3_vl_message_set_data (self, args) != 0) {
		Py_INCREF(Py_False);
		return Py_False;
	}
	Py_INCREF(Py_True);
	return Py_True;
}

static PyObject *rrr_python3_vl_message_f_set (PyObject *self, PyObject **args, Py_ssize_t arg_length) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	int ret = 0;

	if (arg_length != 6) {
		VL_MSG_ERR("Wrong number of parameters to rrr_python3_vl_message_f_set. Got %li but expected 6.\n", arg_length);
	}

	RRR_PY_DECLARE_GET_TEST_32(0,type);
	RRR_PY_DECLARE_GET_TEST_32(1,class);
	RRR_PY_DECLARE_GET_TEST_64(2,timestamp_from);
	RRR_PY_DECLARE_GET_TEST_64(3,timestamp_to);
	RRR_PY_DECLARE_GET_TEST_64(4,data_numeric);

	if (ret != 0) {
		goto out;
	}

	if (__rrr_python3_vl_message_set_data (self, args[5]) != 0) {
		ret = 1;
		goto out;
	}

	data->message.type = type;
	data->message.class = class;
	data->message.timestamp_from = timestamp_from;
	data->message.timestamp_to = timestamp_to;
	data->message.data_numeric = data_numeric;

	out:
	if (ret) {
		Py_INCREF(Py_False);
		return Py_False;
	}
	Py_INCREF(Py_True);
	return Py_True;
}

// TODO : Check that args/kwds are empty
static int rrr_python3_vl_message_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);
	(void)(kwds);
	memset (&data->message, '\0', sizeof(data->message));
	return 0;
}

static void rrr_python3_vl_message_f_dealloc (PyObject *self) {
	PyObject_Del(self);
}

static PyObject *rrr_python3_vl_message_f_get_data(PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);
	return PyByteArray_FromStringAndSize(data->message.data, data->message.length);
}

static PyMethodDef vl_message_methods[] = {
		{
				ml_name:	"set",
				ml_meth:	(PyCFunction) rrr_python3_vl_message_f_set,
				ml_flags:	METH_FASTCALL,
				ml_doc:		"Set all parameters"
		},
		{
				ml_name:	"set_data",
				ml_meth:	(PyCFunction) rrr_python3_vl_message_f_set_data,
				ml_flags:	METH_O,
				ml_doc:		"Set data parameter"
		},
		{
				ml_name:	"get_data",
				ml_meth:	(PyCFunction) rrr_python3_vl_message_f_get_data,
				ml_flags:	METH_NOARGS,
				ml_doc:		"Get data parameter from message as byte array"
		},
		{ NULL, NULL, 0, NULL }
};

static PyMemberDef vl_message_members[] = {
		{"endian_two",		RRR_PY_16,	RRR_PY_VL_MESSAGE_OFFSET(endian_two),		0, "Both endian bytes"},
		{"endian_one",		RRR_PY_8,	RRR_PY_VL_MESSAGE_OFFSET(endian_one),		0, "First endian byte"},
		{"type",			RRR_PY_32,	RRR_PY_VL_MESSAGE_OFFSET(type),				0, "Type"},
		{"class",			RRR_PY_32,	RRR_PY_VL_MESSAGE_OFFSET(class),			0, "Class"},
		{"timestamp_from",	RRR_PY_64,	RRR_PY_VL_MESSAGE_OFFSET(timestamp_from),	0, "From timestamp"},
		{"timestamp_to",	RRR_PY_64,	RRR_PY_VL_MESSAGE_OFFSET(timestamp_to),		0, "To timestamp"},
		{"length",			RRR_PY_32,	RRR_PY_VL_MESSAGE_OFFSET(length),			0, "Length of data field"},
		{"data_numeric",	RRR_PY_64, 	RRR_PY_VL_MESSAGE_OFFSET(data_numeric),		0, "Numeric data"},
		{ NULL, 0, 0, 0, NULL}
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
	    tp_members:			vl_message_members,
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

struct vl_message *rrr_python3_vl_message_get_message (PyObject *self) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	return &data->message;
}

PyObject *rrr_python3_vl_message_new (void) {
	struct rrr_python3_vl_message_data *ret = PyObject_New(struct rrr_python3_vl_message_data, &rrr_python3_vl_message_type);
	if (ret) {
		memset(&ret->message, '\0', sizeof(ret->message));
	}
	return (PyObject *) ret;
}

PyObject *rrr_python3_vl_message_new_from_message (struct rrr_socket_msg *msg) {
	struct rrr_python3_vl_message_data *ret = NULL;

	if (msg->msg_size != sizeof(ret->message)) {
		VL_BUG("Received object of wrong size in rrr_python3_vl_message_new_from_message\n");
	}

	ret = PyObject_New(struct rrr_python3_vl_message_data, &rrr_python3_vl_message_type);
	if (ret) {
		memcpy(&ret->message, msg, sizeof(ret->message));
	}

	return (PyObject *) ret;
}
