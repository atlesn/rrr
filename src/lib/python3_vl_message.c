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
#include "python3_array.h"
#include "rrr_socket_msg.h"
#include "messages.h"
#include "array.h"
#include "fixed_point.h"
#include "../global.h"

//static const unsigned long int max_8 = 0xff;
//static const unsigned long int max_16 = 0xffff;
static const unsigned long int max_32 = 0xffffffff;
static const unsigned long int max_64 = 0xffffffffffffffff;

struct rrr_python3_vl_message_data {
	PyObject_HEAD
	struct vl_message message_static;
	struct vl_message *message_dynamic;
	PyObject *rrr_array;
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

	memcpy(&data->message_static, data->message_dynamic, sizeof(data->message_static));

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
	RRR_FREE_IF_NOT_NULL(data->message_dynamic);
	Py_XDECREF(data->rrr_array);
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

static PyObject *rrr_python3_vl_message_f_get_array(PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);

	if (data->rrr_array == NULL) {
		data->rrr_array = rrr_python3_array_new();
		if (data->rrr_array == NULL) {
			VL_MSG_ERR("Could not create new array in vl_message.get_array()");
			Py_RETURN_NONE;
		}
	}

	Py_INCREF(data->rrr_array);
	return data->rrr_array;
}

static PyObject *rrr_python3_vl_message_f_has_array(PyObject *self, PyObject *args) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	(void)(args);

	if (data->rrr_array != NULL) {
		Py_RETURN_TRUE;
	}

	Py_RETURN_FALSE;
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
				.ml_name	= "get_array",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_get_array,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get array object from message (or create one) for reading and writing values"
		},
		{
				.ml_name	= "has_array",
				.ml_meth	= (PyCFunction) rrr_python3_vl_message_f_has_array,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Check if the message has an array"
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

#define ALLOCATE_DEF						\
	struct rrr_type_value **target,			\
	uint8_t type,							\
	uint8_t type_flags,						\
	ssize_t item_size,						\
	const char *tag,						\
	rrr_type_length tag_length,				\
	ssize_t elements

#define CONVERT_DEF							\
	struct rrr_type_value *target,			\
	PyObject *item,							\
	int index,								\
	ssize_t size

#define PRELIMINARY_CHECK_DEF				\
	int (**allocate_function)(ALLOCATE_DEF),\
	int (**convert_function)(CONVERT_DEF),	\
	uint8_t *target_type,					\
	uint8_t *target_type_flags,				\
	ssize_t *size,							\
	PyObject **new_subject,					\
	PyObject *subject

static int __allocate_64 (ALLOCATE_DEF) {
	(void)(item_size);

	if (rrr_type_value_new (
			target,
			rrr_type_get_from_id(type),
			type_flags,
			tag_length,
			tag,
			sizeof(rrr_type_h) * elements,
			elements,
			sizeof(rrr_type_h) * elements
	) != 0) {
		VL_MSG_ERR("Could not allocate 64 bit value in __allocate_64\n");
		return 1;
	}

	return 0;
}

static int __allocate_blob (ALLOCATE_DEF) {
	if (rrr_type_value_new (
			target,
			rrr_type_get_from_id(type),
			type_flags,
			tag_length,
			tag,
			item_size * elements,
			elements,
			item_size * elements
	) != 0) {
		VL_MSG_ERR("Could not allocate blob value in __allocate_64\n");
		return 1;
	}

	return 0;
}

void __convert_save_data (
		struct rrr_type_value *target,
		const void *data,
		int index,
		ssize_t allocated_size,
		ssize_t new_size
) {
	char *pos = target->data + new_size * index;

	if (new_size != allocated_size) {
		VL_BUG("Size mismatch in __convert_save_data\n");
	}

	if (pos + new_size > target->data + target->total_stored_length) {
		VL_BUG("Write position exceeds total stored length in __convert_save_data\n");
	}

	memcpy(pos, data, new_size);
}

static int __convert_ulong (CONVERT_DEF) {
	unsigned long long int tmp = PyLong_AsUnsignedLongLong(item);
	__convert_save_data(target, &tmp, index, size, sizeof(rrr_type_h));
	return 0;
}

static int __convert_long (CONVERT_DEF) {
	long long int tmp = PyLong_AsLongLong(item);
	__convert_save_data(target, &tmp, index, size, sizeof(rrr_type_h));
	return 0;
}

static int __convert_str (CONVERT_DEF) {
	ssize_t new_size = 0;
	const char *str = PyUnicode_AsUTF8AndSize(item, &new_size);
	if (str == NULL) {
		VL_MSG_ERR("Could not convert string in  __convert_str\n");
		return 1;
	}

	__convert_save_data(target, str, index, size, new_size);

	return 0;
}

static int __convert_blob (CONVERT_DEF) {
	ssize_t new_size = PyByteArray_Size(item);
	const char *str = PyByteArray_AsString(item);
	if (str == NULL) {
		VL_MSG_ERR("Could not convert byte array to string in  __convert_blob\n");
		return 1;
	}

	__convert_save_data(target, str, index, size, new_size);

	return 0;
}

static int __preliminary_check_fixp (PRELIMINARY_CHECK_DEF) {
	int ret = 0;
	PyObject *replacement_subject = NULL;

	rrr_fixp test_f = 0;
	double test_d = 0.0;

	if (PyLong_Check(subject)) {
		// OK
	}
	else {
		if (PyFloat_Check(subject)) {
			test_d = PyFloat_AsDouble(subject);
			if (test_d == -1.0 && PyErr_Occurred()) {
				VL_MSG_ERR("Error while converting double in __convert_preliminary_check_long\n");
				ret = 1;
				goto out;
			}
			if ((ret = rrr_fixp_ldouble_to_fixp(&test_f, test_d)) != 0) {
				VL_MSG_ERR("Could not convert double to fixed pointer in __convert_preliminary_check_fixp\n");
				goto out;
			}
		}
		else if (PyUnicode_Check(subject)) {
			const char *str = PyUnicode_AsUTF8(subject);
			if (str == NULL) {
				VL_MSG_ERR("Could not convert unicode to string in __convert_preliminary_check_fixp\n");
				ret = 1;
				goto out;
			}

			const char *endptr;
			if ((ret = rrr_fixp_str_to_fixp(&test_f, str, PyUnicode_GetLength(subject), &endptr)) != 0) {
				VL_MSG_ERR("Error while converting string to fixed pointer in __convert_preliminary_check_fixp\n");
				goto out;
			}

			if (endptr == str) {
				VL_MSG_ERR("Could not understand supposed fixed point string '%s' while converting\n", str);
				ret = 1;
				goto out;
			}
		}
		else {
			VL_MSG_ERR("Unknown type '%s' while converting to fixed point\n", subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if ((replacement_subject = PyLong_FromLongLong(test_f)) == NULL) {
			VL_MSG_ERR("Could not allocate replacement unicode string for type %s in __convert_preliminary_check_fixp\n",
					subject->ob_type->tp_name);
			return 1;
		}
	}

	*new_subject = replacement_subject;
	*allocate_function = __allocate_64;
	*convert_function = __convert_long;
	if (*target_type == 0) {
		*target_type = RRR_TYPE_FIXP;
	}
	*target_type_flags = 0;
	*size = sizeof(rrr_fixp);

	out:
	return ret;
}

static int __preliminary_check_long (PRELIMINARY_CHECK_DEF) {
	int ret = 0;
	unsigned long long int test_u = 0;
	long long int test_i = 0;
	double test_d = 0.0;

	PyObject *replacement_subject = NULL;

	if (PyFloat_Check(subject)) {
		test_d = PyFloat_AsDouble(subject);
		if (test_d == -1.0 && PyErr_Occurred()) {
			VL_MSG_ERR("Error while converting double in __convert_preliminary_check_long\n");
			ret = 1;
			goto out;
		}
		if (test_d > INT64_MAX || test_d < INT64_MIN) {
			VL_MSG_ERR("Double value was out of range in __convert_preliminary_check_long\n");
			ret = 1;
			goto out;
		}
		if (!isfinite(test_d)) {
			VL_MSG_ERR("Double value was not finite in __convert_preliminary_check_long\n");
			ret = 1;
			goto out;
		}
		if (test_d > 0.0) {
			test_u = (unsigned long long int) test_d;
			goto do_unsigned_and_convert;
		}
	}
	else if (PyLong_Check(subject)) {
		test_u = PyLong_AsUnsignedLongLong(subject);
		if (PyErr_Occurred()) {
			PyErr_Clear();
			goto do_signed;
		}
		goto do_unsigned;
	}
	else if (PyUnicode_Check(subject)) {
		const char *str = PyUnicode_AsUTF8(subject);
		char *endptr = NULL;
		if (*str == '-') {
			test_i = strtoll(str, &endptr, 10);
			if (endptr < str + 1) {
				goto not_convertible;
			}
			goto do_signed_and_convert;
		}
		else if (*str >= '0' && *str <= '9') {
			char *endptr = NULL;
			test_u = strtoull(str, &endptr, 10);
			goto do_unsigned_and_convert;
		}
	}

	goto not_convertible;

	do_signed_and_convert:
		if ((replacement_subject = PyLong_FromLongLong(test_i)) == NULL) {
			VL_MSG_ERR("Could not create long object in __convert_preliminary_check_long\n");
			ret = 1;
			goto out;
		}
	do_signed:
		RRR_TYPE_FLAG_SET_SIGNED(*target_type_flags);
		*convert_function = __convert_long;
		goto out;

	do_unsigned_and_convert:
		if ((replacement_subject = PyLong_FromUnsignedLongLong(test_u)) == NULL) {
			VL_MSG_ERR("Could not create long object in __convert_preliminary_check_long\n");
			ret = 1;
			goto out;
		}
	do_unsigned:
		// If one or more values are signed, all must be saved as signed
		if (*convert_function == NULL) {
			*convert_function = __convert_ulong;
		}
		goto out;

	not_convertible:
		*convert_function = NULL;
		goto out;

	out:

	*new_subject = replacement_subject;
	*allocate_function = __allocate_64;
	if (*target_type == 0) {
		*target_type = RRR_TYPE_H;
	}
	*target_type_flags = 0;
	*size = sizeof(rrr_type_h);

	return ret;
}

static int __preliminary_check_stringish (PRELIMINARY_CHECK_DEF) {
	int ret = 0;

	PyObject *replacement_subject = NULL;
	ssize_t new_size = 0;

	if (PyUnicode_Check(subject)) {
		new_size = PyUnicode_GetLength(subject);
	}
	else {
		if (PyLong_Check(subject)) {
			unsigned long long int temp_u = PyLong_AsUnsignedLongLong(subject);
			// We get an error if number is negative
			if (PyErr_Occurred()) {
				PyErr_Clear();
				long long int temp_i = PyLong_AsLongLong(subject);
				if (PyErr_Occurred()) {
					VL_MSG_ERR("Could not convert long to string in __convert_preliminary_check_stringish\n");
					ret = 1;
					goto out;
				}
				replacement_subject = PyUnicode_FromFormat("%lli", temp_i);
			}
			else {
				replacement_subject = PyUnicode_FromFormat("%llu", temp_u);
			}
		}
		else if (PyFloat_Check(subject)) {
			double temp_d = PyFloat_AsDouble(subject);
			if (PyErr_Occurred()) {
				VL_MSG_ERR("Could not convert double to string in __convert_preliminary_check_stringish\n");
				ret = 1;
				goto out;
			}
			replacement_subject = PyUnicode_FromFormat("%d", temp_d);
		}
		else if (PyBool_Check(subject)) {
			replacement_subject = PyUnicode_FromString(subject == Py_True ? "TRUE" : "FALSE");
		}
		else if (PyByteArray_Check(subject)) {
			new_size = PyByteArray_Size(subject);
			const char *str = PyByteArray_AsString(subject);
			replacement_subject = PyUnicode_FromStringAndSize(str, new_size);
		}
		else if (PyBytes_Check(subject)) {
			new_size = PyBytes_Size(subject);
			const char *str = PyBytes_AsString(subject);
			replacement_subject = PyUnicode_FromStringAndSize(str, new_size);
		}
		else {
			VL_MSG_ERR("Unsupported type '%s' while converting to string in __convert_preliminary_check_stringish\n",
					subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if (replacement_subject == NULL) {
			VL_MSG_ERR("Could not allocate replacement unicode string for type %s in __convert_preliminary_check_stringish\n",
					subject->ob_type->tp_name);
			return 1;
		}

		if (new_size == 0) {
			new_size = PyUnicode_GetLength(replacement_subject);
		}
	}

	if (*size != 0 && *size != new_size) {
		VL_MSG_ERR("Size of strings in array was not of equal length, which is required.\n");
		return 1;
	}

	*new_subject = replacement_subject;
	*allocate_function = __allocate_blob;
	*convert_function = __convert_str;
	if (*target_type == 0) {
		*target_type = RRR_TYPE_STR;
	}
	*target_type_flags = 0;
	*size = new_size;

	replacement_subject = NULL;

	out:
	Py_XDECREF(replacement_subject);
	return ret;
}


static int __preliminary_check_sep (PRELIMINARY_CHECK_DEF) {
	int ret = 0;

	if ((ret = __preliminary_check_stringish (
			allocate_function,
			convert_function,
			target_type,
			target_type_flags,
			size,
			new_subject,
			subject
	)) != 0) {
		return ret;
	}

	const char *str = PyUnicode_AsUTF8(*new_subject != NULL ? *new_subject : subject);
	if (str == NULL) {
		VL_MSG_ERR("Could not get string from unicode in __convert_preliminary_check_sep\n");
		return 1;
	}

	for (int i = 0; i < *size; i++) {
		unsigned char c = str[i];
		if (!RRR_TYPE_CHAR_IS_SEP(c)) {
			VL_MSG_ERR("Found non-separator character 0x%02x in supposed separator string while converting\n", c);
			ret = 1;
			// Don't break, report all errors
		}
	}

	return ret;
}

static int __preliminary_check_blob (PRELIMINARY_CHECK_DEF) {
	int ret = 0;

	PyObject *replacement_subject = NULL;
	ssize_t new_size = 0;

	if (PyByteArray_Check(subject)) {
		new_size = PyByteArray_Size(subject);
	}
	else {
		if (PyBytes_Check(subject)) {
			new_size = PyBytes_Size(subject);
			replacement_subject = PyByteArray_FromObject(subject);
		}
		else if (PyUnicode_Check(subject)) {
			const char *str = PyUnicode_AsUTF8AndSize(subject, &new_size);
			if (str == NULL) {
				VL_MSG_ERR("Could not get string from unicode object in __convert_preliminary_check_blob\n");
			}
			replacement_subject = PyByteArray_FromStringAndSize(str, new_size);
		}
		else {
			VL_MSG_ERR("Could not convert type %s to bytearray in __convert_preliminary_check_blob\n",
					subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if (replacement_subject == NULL) {
			VL_MSG_ERR("Could not create replacement bytearray in __convert_preliminary_check_blob\n");
			ret = 1;
			goto out;
		}
	}

	*new_subject = replacement_subject;
	*allocate_function = __allocate_blob;
	*convert_function = __convert_blob;
	if (*target_type == 0) {
		*target_type = RRR_TYPE_BLOB;
	}
	*target_type_flags = 0;
	*size = new_size;

	out:
	Py_XDECREF(replacement_subject);
	return ret;
}


static int __rrr_python3_array_vl_message_get_message_store_array_node_callback (
		PyObject *tag,
		PyObject *list,
		uint8_t type_orig,
		void *arg
) {
	struct rrr_array *target = arg;
	struct rrr_type_value *new_value = NULL;

	const char *tag_str = NULL;
	ssize_t tag_length = 0;

	int ret = 0;

	if (list == NULL) {
		VL_BUG("List was NULL in __rrr_python3_array_vl_message_get_message_store_array_node_callback\n");
	}

	Py_INCREF(list);

	if (tag == NULL || tag == Py_None) {
		tag_str = "";
		tag_length = 0;
	}
	else {
		if (!PyUnicode_Check(tag)) {
			VL_MSG_ERR("Tag of array element was not a string\n");
			ret = 1;
			goto out;
		}

		if ((tag_str = PyUnicode_AsUTF8AndSize(tag, &tag_length)) == NULL) {
			VL_MSG_ERR("Could not convert tag object to string in __rrr_python3_array_vl_message_get_message_store_array_node_callback\n");
			ret = 1;
			goto out;
		}
	}

	if (!PyList_Check(list)) {
		VL_BUG("Value was not a list in __rrr_python3_array_vl_message_get_message_store_array_node_callback\n");
	}

	ssize_t count = PyList_GET_SIZE(list);
	PyObject *first_item = PyList_GET_ITEM(list, 0);

	uint8_t target_type = 0;
	uint8_t target_type_flags = 0;

	ssize_t item_size = 0;

	int (*preliminary_check_function)(PRELIMINARY_CHECK_DEF) = NULL;
	int (*allocate_function)(ALLOCATE_DEF) = NULL;
	int (*convert_function)(CONVERT_DEF) = NULL;

	// Attempt to use original type
	if (type_orig > 0) {
		if (RRR_TYPE_IS_FIXP(type_orig)) {
			preliminary_check_function = __preliminary_check_fixp;
		}
		else if (RRR_TYPE_IS_64(type_orig)) {
			preliminary_check_function = __preliminary_check_long;
		}
		else if (RRR_TYPE_IS_SEP(type_orig)) {
			target_type = RRR_TYPE_SEP;
			preliminary_check_function = __preliminary_check_sep;
		}
		else if (RRR_TYPE_IS_STR(type_orig)) {
			preliminary_check_function = __preliminary_check_stringish;
		}
		else if (RRR_TYPE_IS_MSG(type_orig)) {
			target_type = RRR_TYPE_MSG;
			preliminary_check_function = __preliminary_check_blob;
		}
		else if (RRR_TYPE_IS_BLOB(type_orig)) {
			preliminary_check_function = __preliminary_check_blob;
		}
	}

	// Attempt to auto-detect type
	if (preliminary_check_function == NULL) {
		if (PyLong_Check(first_item)) {
			preliminary_check_function = __preliminary_check_long;
		}
		else if (PyUnicode_Check(first_item)) {
			preliminary_check_function = __preliminary_check_stringish;
		}
		else if (PyLong_Check(first_item)) {
			preliminary_check_function = __preliminary_check_long;
		}
		else if (PyFloat_Check(first_item)) {
			preliminary_check_function = __preliminary_check_fixp;
		}
		else if (PyBytes_Check(first_item) || PyByteArray_Check(first_item)) {
			preliminary_check_function = __preliminary_check_blob;
		}
	}

	if (preliminary_check_function == NULL) {
		VL_MSG_ERR("Type '%s' is not supported and cannot be used in arrays\n", first_item->ob_type->tp_name);
		ret = 1;
		goto out;
	}

	for (int i = 0; i < count; i++) {
		PyObject *item = PyList_GET_ITEM(list, i);
		PyObject *replacement_item = NULL;

		if ((ret = preliminary_check_function (
				&allocate_function,
				&convert_function,
				&target_type,
				&target_type_flags,
				&item_size,
				&replacement_item,
				item
		)) != 0) {
			VL_MSG_ERR("Could not convert item of type '%s' in array, preliminary check failed\n", item->ob_type->tp_name);
			goto out;
		}

		if (replacement_item != NULL) {
			Py_DECREF(item);
			PyList_SET_ITEM(list, i, replacement_item);
		}

		if (convert_function == NULL) {
			VL_MSG_ERR("Could not convert item of type '%s' to type '%u' in array, item is not convertible to target type\n",
					item->ob_type->tp_name, target_type);
			goto out;
		}
	}

	if ((ret = allocate_function (
			&new_value,
			target_type,
			target_type_flags,
			item_size,
			tag_str,
			tag_length,
			count
	)) != 0) {
		VL_MSG_ERR("Could not allocate memory for type %u in __rrr_python3_array_vl_message_get_message_store_array_node_callback\n",
				target_type);
		goto out;
	}

	for (int i = 0; i < count; i++) {
		PyObject *item = PyList_GET_ITEM(list, i);
		if ((ret = convert_function(new_value, item, i, item_size)) != 0) {
			VL_MSG_ERR("Error while converting value of type '%s' to %u\n",
					item->ob_type->tp_name, target_type);
			goto out;
		}
	}

	RRR_LINKED_LIST_APPEND(target, new_value);
	new_value = NULL;

	out:
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
	Py_DECREF(list);
	return ret;
}

struct vl_message *rrr_python3_vl_message_get_message (PyObject *self) {
	struct rrr_python3_vl_message_data *data = (struct rrr_python3_vl_message_data *) self;
	struct rrr_array array_tmp = {0};

	struct vl_message *ret = data->message_dynamic;
	struct vl_message *new_msg = NULL;

	// Overwrite header fields
	memcpy (ret, &data->message_static, sizeof(data->message_static) - 1);

	// If array is present, also overwrite the body
	if (data->rrr_array != NULL) {
		if (rrr_python3_array_iterate (
				data->rrr_array,
				__rrr_python3_array_vl_message_get_message_store_array_node_callback,
				&array_tmp
		) != 0) {
			VL_MSG_ERR("Error while iterating array in rrr_python3_vl_message_get_message\n");
			goto out_err;
		}

		if (rrr_array_new_message_from_collection (
				&new_msg,
				&array_tmp,
				ret->timestamp_from,
				MSG_TOPIC_PTR(ret),
				MSG_TOPIC_LENGTH(ret)
		) != 0) {
			VL_MSG_ERR("Could not create new array message in rrr_python3_vl_message_get_message\n");
			goto out_err;
		}

		free(ret);
		ret = new_msg;
		data->message_dynamic = new_msg;
		new_msg = NULL;
	}

	goto out;
	out_err:
		ret = NULL;

	out:
		RRR_FREE_IF_NOT_NULL(new_msg);
		rrr_array_clear(&array_tmp);
		return ret;
}

PyObject *rrr_python3_vl_message_new_from_message (struct rrr_socket_msg *msg) {
	struct rrr_python3_vl_message_data *ret = NULL;
	struct rrr_array array_tmp = {0};
	PyObject *node_value_tmp = NULL;
	PyObject *node_element_value_tmp = NULL;
	PyObject *node_tag_tmp = NULL;

	struct vl_message *vl_message = (struct vl_message *) msg;

	if (!RRR_SOCKET_MSG_IS_VL_MESSAGE(msg)) {
		VL_BUG("Received message in rrr_python3_vl_message_new_from_message was not a vl_message\n");
	}

	if (msg->msg_size < sizeof(ret->message_static)) {
		VL_BUG("Received object of wrong size in rrr_python3_vl_message_new_from_message\n");
	}

	ret = PyObject_New(struct rrr_python3_vl_message_data, &rrr_python3_vl_message_type);
	if (ret == NULL) {
		goto out_err;
	}

	ret->message_dynamic = malloc(MSG_TOTAL_SIZE(msg));
	if (ret->message_dynamic == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_python3_vl_message_new_from_message\n");
		goto out_err;
	}

	memcpy(ret->message_dynamic, msg, MSG_TOTAL_SIZE(msg));
	memcpy(&ret->message_static, ret->message_dynamic, sizeof(ret->message_static) - 1);

	ret->rrr_array = NULL;

	if (!MSG_IS_ARRAY(vl_message)) {
		goto no_array;
	}

	ret->rrr_array = rrr_python3_array_new();
	if (ret->rrr_array == NULL) {
		VL_MSG_ERR("Could not create array in rrr_python3_vl_message_new_from_message\n");
		goto out_err;
	}

	if (rrr_array_message_to_collection(&array_tmp, vl_message) != 0) {
		VL_MSG_ERR("Could not parse array from message in rrr_python3_vl_message_new_from_message\n");
		goto out_err;
	}

	RRR_LINKED_LIST_ITERATE_BEGIN(&array_tmp, struct rrr_type_value);
		if (node->tag == NULL) {
			node_tag_tmp = PyUnicode_FromString("");
		}
		else {
			node_tag_tmp = PyUnicode_FromString(node->tag);
			if (node_tag_tmp == NULL) {
				VL_MSG_ERR("Could not create node for tag in rrr_python3_vl_message_new_from_message\n");
				goto out_err;
			}
		}

		if (node->element_count > 1) {
			node_value_tmp = PyList_New(node->element_count);
			if (node_value_tmp == NULL) {
				VL_MSG_ERR("Could not create list for node in rrr_python3_vl_message_new_from_message\n");
				goto out_err;
			}
		}

		ssize_t element_size = node->total_stored_length / node->element_count;
		for (rrr_type_array_size i = 0; i < node->element_count; i++) {
			const char *data_pos = node->data + element_size * i;

			if (RRR_TYPE_IS_64(node->definition->type)) {
				if (RRR_TYPE_FLAG_IS_SIGNED(node->flags)) {
					node_element_value_tmp = PyLong_FromLongLong(*((long long *) data_pos));
				}
				else {
					node_element_value_tmp = PyLong_FromUnsignedLongLong(*((unsigned long long *) data_pos));
				}
			}
			else if (RRR_TYPE_IS_FIXP(node->definition->type)) {
				node_element_value_tmp = PyLong_FromLongLong(*((long long *) data_pos));
			}
			else if (RRR_TYPE_IS_STR(node->definition->type)) {
				node_element_value_tmp = PyUnicode_FromStringAndSize(data_pos, element_size);
			}
			else if (RRR_TYPE_IS_BLOB(node->definition->type)) {
				node_element_value_tmp = PyByteArray_FromStringAndSize(data_pos, element_size);
			}
			else {
				VL_MSG_ERR("Unsupported data type %u in array in rrr_python3_vl_message_new_from_message\n",
						node->definition->type);
				goto out_err;
			}

			if (node_element_value_tmp == NULL) {
				VL_MSG_ERR("Could not create array node data in rrr_python3_vl_message_new_from_message\n");
				goto out_err;
			}

			if (node_value_tmp == NULL) {
				// Single element only
				node_value_tmp = node_element_value_tmp;
				node_element_value_tmp = NULL;
				break;
			}
			else {
				PyList_SET_ITEM(node_value_tmp, i, node_element_value_tmp);
				node_element_value_tmp = NULL;
			}
		}

		if (rrr_python3_array_append(ret->rrr_array, node_tag_tmp, node_value_tmp, node->definition->type) != 0) {
			VL_MSG_ERR("Could not append node value to array in rrr_python3_vl_message_new_from_message\n");
			goto out_err;
		}

		Py_XDECREF(node_tag_tmp);
		Py_XDECREF(node_value_tmp);

		node_tag_tmp = NULL;
		node_value_tmp = NULL;
	RRR_LINKED_LIST_ITERATE_END(&array_tmp);

	no_array:

	goto out;
	out_err:
		Py_XDECREF(ret);
		ret = NULL;

	out:
		Py_XDECREF(node_element_value_tmp);
		Py_XDECREF(node_value_tmp);
		Py_XDECREF(node_tag_tmp);
		rrr_array_clear(&array_tmp);
		return (PyObject *) ret;
}
