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
#include "rrr_socket_msg.h"
#include "messages.h"
#include "../global.h"

//static const unsigned long int max_8 = 0xff;
//static const unsigned long int max_16 = 0xffff;
static const unsigned long int max_32 = 0xffffffff;
static const unsigned long int max_64 = 0xffffffffffffffff;

struct rrr_python3_vl_message_data {
	PyObject_HEAD
	struct vl_message message_static;
	struct vl_message *message_dynamic;
};

static int __rrr_python3_vl_message_set_topic_and_data (
		struct rrr_python3_vl_message_data *data,
		const char *topic_str,
		Py_ssize_t topic_length,
		const char *data_str,
		Py_ssize_t data_length
) {
	int ret = 0;

	struct vl_message *new_message = message_duplicate_no_data_with_size(data->message_dynamic, topic_length, data_length);
	if (new_message == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_python3_vl_message_set_topic_and_data\n");
		ret = 1;
		goto out;
	}

	memcpy(MSG_TOPIC_PTR(new_message), topic_str, topic_length);
	memcpy(MSG_DATA_PTR(new_message), data_str, data_length);

	free(data->message_dynamic);
	data->message_dynamic = new_message;

	out:
	return ret;
}

static PyObject *rrr_python3_vl_message_f_set_data (PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;

	const char *str;
	Py_ssize_t len;
	if (PyByteArray_Check(args)) {
		len = PyByteArray_Size(args);
		str = PyByteArray_AsString(args);
	}
	else if (PyUnicode_Check(args)) {
		str = PyUnicode_AsUTF8AndSize(args, &len);
	}
	else {
		VL_MSG_ERR("Unknown data type to vl_message.set_data(), must be Bytearray or Unicode\n");
		Py_RETURN_FALSE;
	}

	if (__rrr_python3_vl_message_set_topic_and_data (
			data,
			MSG_TOPIC_PTR(data->message_dynamic),
			MSG_TOPIC_LENGTH(data->message_dynamic),
			str,
			len
	) != 0) {
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_vl_message_f_set_topic (PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;

	const char *str;
	Py_ssize_t len;
	if (PyUnicode_Check(args)) {
		str = PyUnicode_AsUTF8AndSize(args, &len);
	}
	else {
		VL_MSG_ERR("Unknown data type to vl_message.set_data(), must be Bytearray or Unicode\n");
		Py_RETURN_FALSE;
	}

	if (__rrr_python3_vl_message_set_topic_and_data (
			data,
			str,
			len,
			MSG_DATA_PTR(data->message_dynamic),
			MSG_DATA_LENGTH(data->message_dynamic)
	) != 0) {
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_vl_message_f_set (PyObject *self, PyObject **args, Py_ssize_t arg_length) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	int ret = 0;

	if (arg_length != 5) {
		VL_MSG_ERR("Wrong number of parameters to rrr_python3_vl_message_f_set. Got %li but expected 5.\n", arg_length);
		ret = 1;
		goto out;
	}

	RRR_PY_DECLARE_GET_TEST_32(0,type);
	RRR_PY_DECLARE_GET_TEST_32(1,class);
	RRR_PY_DECLARE_GET_TEST_64(2,timestamp_from);
	RRR_PY_DECLARE_GET_TEST_64(3,timestamp_to);
	RRR_PY_DECLARE_GET_TEST_64(4,data_numeric);

	if (ret != 0) {
		goto out;
	}

	data->message_dynamic->type = type;
	data->message_dynamic->class = class;
	data->message_dynamic->timestamp_from = timestamp_from;
	data->message_dynamic->timestamp_to = timestamp_to;
	data->message_dynamic->data_numeric = data_numeric;

	memcpy(&data->message_static, data->message_dynamic, sizeof(data->message_static) - 1);

	out:
	if (ret) {
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_vl_message_f_new (PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyObject *self = PyType_GenericNew(type, args, kwds);
	if (self == NULL) {
		return NULL;
	}

	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;

	data->message_dynamic = malloc(sizeof(*(data->message_dynamic)) - 1);
	if (data->message_dynamic == NULL) {
		VL_MSG_ERR("Could not allocate memory for message in rrr_python3_vl_message_f_new\n");
		return NULL;
	}

	memset (data->message_dynamic, '\0', sizeof(*(data->message_dynamic)) - 1);
	memset (&data->message_static, '\0', sizeof(data->message_static));

	return self;
}

// TODO : Check that args/kwds are empty
static int rrr_python3_vl_message_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;

	memset (&data->message_static, '\0', sizeof(data->message_static));
	memset (data->message_dynamic, '\0', sizeof(*(data->message_dynamic)) - 1);

	if (kwds != NULL && PyDict_Size(kwds) != 0) {
		VL_MSG_ERR("Keywords not supported in vl_message init\n");
		return 1;
	}

	Py_ssize_t argc = PyTuple_Size(args);
	if (argc != 0) {
		if (argc != 5) {
			VL_MSG_ERR("Wrong number of parameters to vl_messag init. Got %li but expected 5 or 0.\n", argc);
			return 1;
		}

		PyObject *args_new[5] = {
				PyTuple_GetItem(args, 0),
				PyTuple_GetItem(args, 1),
				PyTuple_GetItem(args, 2),
				PyTuple_GetItem(args, 3),
				PyTuple_GetItem(args, 4)
		};

		PyObject *res = rrr_python3_vl_message_f_set(self, args_new, 5);
		if (res == NULL || !PyObject_IsTrue(res)) {
			VL_MSG_ERR("Error from set function in vl_message init\n");
			Py_XDECREF(res);
			return 1;
		}
		Py_XDECREF(res);
	}

	return 0;
}

static void rrr_python3_vl_message_f_dealloc (PyObject *self) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	free(data->message_dynamic);
	PyObject_Del(self);
}

static PyObject *rrr_python3_vl_message_f_get_data(PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);

	PyObject *ret = PyByteArray_FromStringAndSize(MSG_DATA_PTR(data->message_dynamic), MSG_DATA_LENGTH(data->message_dynamic));

	if (ret == NULL) {
		VL_MSG_ERR("Could not create bytearray object for topic in rrr_python3_vl_message_f_get_data\n");
		PyErr_Print();
		Py_RETURN_FALSE;
	}

	return ret;
}


static PyObject *rrr_python3_vl_message_f_get_topic(PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);

	PyObject *ret = NULL;
	if (MSG_TOPIC_LENGTH(data->message_dynamic) > 0) {
		ret = PyUnicode_FromStringAndSize(MSG_TOPIC_PTR(data->message_dynamic), MSG_TOPIC_LENGTH(data->message_dynamic));
	}
	else {
		ret = PyUnicode_FromString("");
	}
	if (ret == NULL) {
		VL_MSG_ERR("Could not create unicode object for topic in rrr_python3_vl_message_f_get_topic\n");
		PyErr_Print();
		Py_RETURN_FALSE;
	}

	return ret;
}

static PyMethodDef vl_message_methods[] = {
		{
				.ml_name	= "set",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_set,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Set all parameters"
		},
		{
				.ml_name	= "set_data",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_set_data,
				.ml_flags	= METH_O,
				.ml_doc		= "Set data parameter"
		},
		{
				.ml_name	= "get_data",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_get_data,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get data parameter from message as byte array"
		},
		{
				.ml_name	= "set_topic",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_set_topic,
				.ml_flags	= METH_O,
				.ml_doc		= "Set topic parameter"
		},
		{
				.ml_name	= "get_topic",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_get_topic,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get topic parameter from message as a string"
		},
		{ NULL, NULL, 0, NULL }
};

struct rrr_python3_vl_message_data dummy;
#define RRR_PY_VL_MESSAGE_OFFSET(member) \
	(((void*) &(dummy.message_static.member)) - ((void*) &(dummy)))

static PyMemberDef vl_message_members[] = {
		{"type",			RRR_PY_32,	RRR_PY_VL_MESSAGE_OFFSET(type),				0, "Type"},
		{"class",			RRR_PY_32,	RRR_PY_VL_MESSAGE_OFFSET(class),			0, "Class"},
		{"timestamp_from",	RRR_PY_64,	RRR_PY_VL_MESSAGE_OFFSET(timestamp_from),	0, "From timestamp"},
		{"timestamp_to",	RRR_PY_64,	RRR_PY_VL_MESSAGE_OFFSET(timestamp_to),		0, "To timestamp"},
		{"data_numeric",	RRR_PY_64, 	RRR_PY_VL_MESSAGE_OFFSET(data_numeric),		0, "Numeric data"},
		{ NULL, 0, 0, 0, NULL}
};

PyTypeObject rrr_python3_vl_message_type = {
		.ob_base		= PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    .tp_name		= RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_VL_MESSAGE_TYPE_NAME,
	    .tp_basicsize	= sizeof(struct rrr_python3_vl_message_data),
		.tp_itemsize	= 0,
	    .tp_dealloc		= (destructor) rrr_python3_vl_message_f_dealloc,
	    .tp_print		= NULL,
	    .tp_getattr		= NULL,
	    .tp_setattr		= NULL,
	    .tp_as_async	= NULL,
	    .tp_repr		= NULL,
	    .tp_as_number	= NULL,
	    .tp_as_sequence	= NULL,
	    .tp_as_mapping	= NULL,
	    .tp_hash		= NULL,
	    .tp_call		= NULL,
	    .tp_str			= NULL,
	    .tp_getattro	= NULL,
	    .tp_setattro	= NULL,
	    .tp_as_buffer	= NULL,
	    .tp_flags		= Py_TPFLAGS_DEFAULT,
	    .tp_doc			= "ReadRouteRecord type for VL Message structure",
	    .tp_traverse	= NULL,
	    .tp_clear		= NULL,
	    .tp_richcompare	= NULL,
	    .tp_weaklistoffset = 0,
	    .tp_iter		= NULL,
	    .tp_iternext	= NULL,
	    .tp_methods		= vl_message_methods,
	    .tp_members		= vl_message_members,
	    .tp_getset		= NULL,
	    .tp_base		= NULL,
	    .tp_dict		= NULL,
	    .tp_descr_get	= NULL,
	    .tp_descr_set	= NULL,
	    .tp_dictoffset	= 0,
	    .tp_init		= rrr_python3_vl_message_f_init,
	    .tp_alloc		= PyType_GenericAlloc,
	    .tp_new			= rrr_python3_vl_message_f_new,
	    .tp_free		= NULL,
	    .tp_is_gc		= NULL,
	    .tp_bases		= NULL,
	    .tp_mro			= NULL,
	    .tp_cache		= NULL,
	    .tp_subclasses	= NULL,
	    .tp_weaklist	= NULL,
	    .tp_del			= NULL,
	    .tp_version_tag	= 0,
	    .tp_finalize	= NULL
};

struct vl_message *rrr_python3_vl_message_get_message (PyObject *self) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	memcpy (data->message_dynamic, &data->message_static, sizeof(data->message_static) - 1);
	return data->message_dynamic;
}

PyObject *rrr_python3_vl_message_new_from_message (struct rrr_socket_msg *msg) {
	struct rrr_python3_vl_message_data *ret = NULL;

	if (msg->msg_size < sizeof(ret->message_static)) {
		VL_BUG("Received object of wrong size in rrr_python3_vl_message_new_from_message\n");
	}

	ret = PyObject_New(struct rrr_python3_vl_message_data, &rrr_python3_vl_message_type);
	if (ret == NULL) {
		return NULL;
	}


	ret->message_dynamic = malloc(msg->msg_size);
	if (ret->message_dynamic == NULL) {
		return NULL;
	}
	memcpy(ret->message_dynamic, msg, msg->msg_size);
	memcpy(&ret->message_static, ret->message_dynamic, sizeof(ret->message_static) - 1);

	return (PyObject *) ret;
}
