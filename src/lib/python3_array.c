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

#include "linked_list.h"
#include "python3_module_common.h"
#include "python3_array.h"

struct rrr_python3_array_value {
	RRR_LINKED_LIST_NODE(struct rrr_python3_array_value);
	PyObject *tag;
	PyObject *value;
	uint8_t type_orig;
};

struct rrr_python3_array_data {
	RRR_LINKED_LIST_HEAD(struct rrr_python3_array_value);
};

static void __rrr_python3_array_value_destroy (struct rrr_python3_array_value *value) {
	Py_XDECREF(value->tag);
	Py_XDECREF(value->value);
	free(value);
}

static struct rrr_python3_array_value *__rrr_python3_array_value_new (void) {
	struct rrr_python3_array_value *result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_python3_array_value_new\n");
		return NULL;
	}
	memset(result, '\0', sizeof(*result));
	return result;
}

static void rrr_python3_array_f_dealloc (PyObject *self) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	RRR_LINKED_LIST_DESTROY(data, struct rrr_python3_array_value, __rrr_python3_array_value_destroy(node));

	PyObject_Del(self);
}

int rrr_python3_array_iterate (
		PyObject *self,
		int (*callback)(PyObject *tag, PyObject *value, uint8_t type_orig, void *arg),
		void *callback_arg
) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	int ret = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct rrr_python3_array_value);
		if ((ret = callback(node->tag, node->value, node->type_orig, callback_arg)) != 0) {
			RRR_LINKED_LIST_SET_STOP();
		}
	RRR_LINKED_LIST_ITERATE_END(data);

	return ret;
}

static struct rrr_python3_array_value *__rrr_python3_array_get_node_by_index (
		struct rrr_python3_array_data *data,
		int index
) {
	int i = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct rrr_python3_array_value);
		if (i == index) {
			return node;
		}
		i++;
	RRR_LINKED_LIST_ITERATE_END(data);

	return NULL;
}

static struct rrr_python3_array_value *__rrr_python3_array_get_node_by_tag (
		struct rrr_python3_array_data *data,
		PyObject *tag
) {
	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct rrr_python3_array_value);
	if (node->tag != NULL && node->tag != Py_None) {
		if (PyUnicode_Compare(node->tag, tag) == 0) {
			return node;
		}
		else {
			if (PyErr_Occurred()) {
				VL_MSG_ERR("Error while getting array node by tag: \n");
				PyErr_Print();
				return NULL;
			}
		}
	}
	RRR_LINKED_LIST_ITERATE_END(data);

	return NULL;
}

static int rrr_python3_array_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	if (kwds != NULL && PyDict_Size(kwds) != 0) {
		VL_MSG_ERR("Keywords not supported in array init\n");
		return 1;
	}

	Py_ssize_t argc = PyTuple_Size(args);
	if (argc != 0) {
		VL_MSG_ERR("Arguments not supported in array init.\n");
		return 1;
	}

	memset (data, '\0', sizeof(*data));

	return 0;
}

static PyObject *rrr_python3_array_f_new (PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyObject *self = PyType_GenericNew(type, args, kwds);
	if (self == NULL) {
		return NULL;
	}

//	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	return self;
}

static struct rrr_python3_array_value *rrr_python3_array_get_or_append_new (
		struct rrr_python3_array_data *data,
		int index
) {
	struct rrr_python3_array_value *node = NULL;

	ssize_t node_count = RRR_LINKED_LIST_COUNT(data);

	// Append new node if index is just after the current element count
	if (index == node_count) {
		node = __rrr_python3_array_value_new();
		if (node == NULL) {
			return NULL;
		}
		RRR_LINKED_LIST_APPEND(data, node);
	}
	else if (index > node_count) {
		VL_MSG_ERR("Index was too big in rrr_python3_array_set_value, max index is the current last index + 1, otherwise a hole would be produced\n");
		return NULL;
	}
	else {
		node = __rrr_python3_array_get_node_by_index(data, index);
	}

	if (node == NULL) {
		VL_BUG("node was NULL in rrr_python3_array_set_value\n");
	}

	return node;
}

void rrr_python3_array_value_set_value (struct rrr_python3_array_value *node, PyObject *value) {
	Py_XDECREF(node->value);
	Py_INCREF(value);
	node->value = value;
}

void rrr_python3_array_value_set_tag (struct rrr_python3_array_value *node, PyObject *tag) {
	Py_XDECREF(node->tag);
	Py_INCREF(tag);
	node->value = tag;
}

int __rrr_python3_array_get_index_from_args (long *index_final, PyObject *args[], PyObject *count) {
	*index_final = 0;

	long argc = PyLong_AsLong(count);
	if (argc < 1) {
		VL_MSG_ERR("Missing index argument\n");
		return 1;
	}

	if (!PyLong_Check(args[0])) {
		VL_MSG_ERR("Non-numeric type specified as index\n");
		return 1;
	}

	long index = PyLong_AsLong(args[0]);
	if (index < 0) {
		VL_MSG_ERR("Negative index value provided\n");
		return 1;
	}

	*index_final = index;

	return 0;
}

static PyObject *rrr_python3_array_f_get (PyObject *self, PyObject *args[], PyObject *count) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	PyObject *tuple = NULL;

	long index = 0;
	if (__rrr_python3_array_get_index_from_args(&index, args, count) != 0) {
		Py_RETURN_NONE;
	}

	if (PyLong_AsLong(count) > 1) {
		VL_MSG_ERR("Too many arguments to rrr_array.get_tuple()\n");
		Py_RETURN_NONE;
	}

	struct rrr_python3_array_value *node = rrr_python3_array_get_or_append_new(data, index);
	if (node == NULL) {
		VL_MSG_ERR("Could not retrieve element with index %li in rrr_array.get_tuple()\n", index);
		Py_RETURN_NONE;
	}

	tuple = PyTuple_New(2);
	if (tuple == NULL) {
		VL_MSG_ERR("Could not create array value tuple in rrr_array.get_tuple()\n");
		Py_RETURN_NONE;
	}

	PyObject *tag = node->tag;
	PyObject *value = node->value;

	if (tag == NULL) {
		tag = Py_None;
	}
	if (value == NULL) {
		value = Py_None;
	}

	Py_INCREF(tag);
	Py_INCREF(value);

	PyTuple_SET_ITEM(tuple, 0, tag);
	PyTuple_SET_ITEM(tuple, 1, value);

	return tuple;
}


static PyObject *rrr_python3_array_f_set (PyObject *self, PyObject *args[], PyObject *count) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	long index = 0;
	if (__rrr_python3_array_get_index_from_args(&index, args, count) != 0) {
		Py_RETURN_FALSE;
	}

	if (PyLong_AsLong(count) > 2) {
		VL_MSG_ERR("Too many arguments to rrr_array.set_tuple()\n");
		Py_RETURN_FALSE;
	}

	PyObject *tuple = args[1];
	if (!PyTuple_CheckExact(tuple)) {
		VL_MSG_ERR("Argument given to rrr_array.set_tuple() was not a tuple\n");
		Py_RETURN_FALSE;
	}

	if (PyTuple_Size(tuple) != 2) {
		VL_MSG_ERR("Tuple given to rrr_array.set_tuple() was of wrong size, must contain 2 elements (one tag and one value)\n");
		Py_RETURN_FALSE;
	}

	PyObject *tag = PyTuple_GetItem(tuple, 0);
	PyObject *value = PyTuple_GetItem(tuple, 1);

	if (tag != Py_None && !PyUnicode_Check(tag)) {
		VL_MSG_ERR("Tag (first element in tuple) given to rrr_array.set_tuple() was not of type None or a string\n");
		Py_RETURN_FALSE;
	}

	struct rrr_python3_array_value *node = rrr_python3_array_get_or_append_new(data, index);
	if (node == NULL) {
		VL_MSG_ERR("Could not retrieve element with index %li in rrr_array.set_tuple()\n", index);
		Py_RETURN_FALSE;
	}

	rrr_python3_array_value_set_tag(node, tag);
	rrr_python3_array_value_set_tag(node, value);

	Py_RETURN_TRUE;
}

int rrr_python3_array_append (PyObject *self, PyObject *tag, PyObject *value, uint8_t type_orig) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	struct rrr_python3_array_value *result = __rrr_python3_array_value_new();
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate array value in rrr_python3_array_append\n");
		return 1;
	}

	result->type_orig = type_orig;

	RRR_LINKED_LIST_APPEND(data, result);

	rrr_python3_array_value_set_tag(result, tag);
	rrr_python3_array_value_set_value(result, value);

	return 0;
}

static PyObject *rrr_python3_array_f_append (PyObject *self, PyObject *args[], PyObject *count) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	if (PyLong_AsLong(count) != 2) {
		VL_MSG_ERR("Wrong number of arguments to rrr_array.append(), only tag and value may be given\n");
		Py_RETURN_FALSE;
	}

	PyObject *tag = args[0];
	PyObject *value = args[1];

	if (rrr_python3_array_append(self, tag, value, 0)  != 0) {
		VL_MSG_ERR("Could not append tag and value in rrr_array.append()\n");
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_array_f_get_by_tag (PyObject *self, PyObject *tag) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	if (!PyUnicode_Check(tag)) {
		VL_MSG_ERR("Argument to rrr_array.get() was not a string\n");
		Py_RETURN_NONE;
	}

	struct rrr_python3_array_value *node = __rrr_python3_array_get_node_by_tag(data, tag);
	if (node == NULL) {
		VL_MSG_ERR("Tag '%s' not found in rrr_array.get()\n", PyUnicode_AsUTF8(tag));
		Py_RETURN_NONE;
	}

	if (node->value == NULL) {
		Py_RETURN_NONE;
	}

	Py_INCREF(node->value);
	return node->value;
}

static PyObject *rrr_python3_array_f_set_by_tag_or_index (PyObject *self, PyObject *args[], PyObject *count) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	if (PyLong_AsLong(count) != 2) {
		VL_MSG_ERR("Wrong number of arguments to rrr_array.set(), only tag and value must be given\n");
		Py_RETURN_FALSE;
	}

	PyObject *tag = args[0];
	PyObject *value = args[1];

	struct rrr_python3_array_value *node = NULL;

	if (PyUnicode_Check(tag)) {
		node = __rrr_python3_array_get_node_by_tag(data, tag);
		if (node == NULL) {
			VL_MSG_ERR("Tag '%s' not found in rrr_array.set()\n", PyUnicode_AsUTF8(tag));
			Py_RETURN_FALSE;
		}
	}
	else if (PyLong_Check(tag)) {
		long index = PyLong_AsLong(tag);
		if (index < 0) {
			VL_MSG_ERR("Negative index given to rrr_array.set()\n");
			Py_RETURN_FALSE;
		}
		node = __rrr_python3_array_get_node_by_index(data, index);
		if (node == NULL) {
			VL_MSG_ERR("Could not get node with index %li in rrr_array.set()\n", index);
			Py_RETURN_FALSE;
		}
	}
	else {
		VL_MSG_ERR("Tag argument to rrr_array.set() was not a string or integer\n");
		Py_RETURN_FALSE;
	}

	rrr_python3_array_value_set_value(node, value);

	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_array_count (PyObject *self, PyObject *dummy) {
	struct rrr_python3_array_data *data = (struct rrr_python3_array_data *) self;

	(void)(dummy);

	PyObject *result = PyLong_FromLong(RRR_LINKED_LIST_COUNT(data));
	if (result == NULL) {
		VL_MSG_ERR("Could not create Long-object in rrr_python3_array_count\n");
		PyErr_Print();
		Py_RETURN_NONE;
	}

	return result;
}

static PyMethodDef array_methods[] = {
		{
				.ml_name	= "get_tuple",
				.ml_meth	= (PyCFunction) rrr_python3_array_f_get,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Get a data parameter tuple for position x"
		},
		{
				.ml_name	= "set_tuple",
				.ml_meth	= (PyCFunction) rrr_python3_array_f_set,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Set a data parameter at position x using the given tuple"
		},
		{
				.ml_name	= "get",
				.ml_meth	= (PyCFunction) rrr_python3_array_f_get_by_tag,
				.ml_flags	= METH_O,
				.ml_doc		= "Get a value of parameter with tag x"
		},
		{
				.ml_name	= "set",
				.ml_meth	= (PyCFunction) rrr_python3_array_f_set_by_tag_or_index,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Set a value of parameter with tag or index x to value y"
		},
		{
				.ml_name	= "append",
				.ml_meth	= (PyCFunction) rrr_python3_array_f_append,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Append a tag x and value y"
		},
		{
				.ml_name	= "count",
				.ml_meth	= (PyCFunction) rrr_python3_array_count,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get the number of items in the array"
		},
		{ NULL, NULL, 0, NULL }
};

static PyMemberDef array_members[] = {
		{ NULL, 0, 0, 0, NULL}
};

PyTypeObject rrr_python3_array_type = {
		.ob_base		= PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    .tp_name		= RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_VL_MESSAGE_TYPE_NAME,
	    .tp_basicsize	= sizeof(struct rrr_python3_array_data),
		.tp_itemsize	= 0,
	    .tp_dealloc		= (destructor) rrr_python3_array_f_dealloc,
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
	    .tp_doc			= "ReadRouteRecord type for VL Message Array structure",
	    .tp_traverse	= NULL,
	    .tp_clear		= NULL,
	    .tp_richcompare	= NULL,
	    .tp_weaklistoffset = 0,
	    .tp_iter		= NULL,
	    .tp_iternext	= NULL,
	    .tp_methods		= array_methods,
	    .tp_members		= array_members,
	    .tp_getset		= NULL,
	    .tp_base		= NULL,
	    .tp_dict		= NULL,
	    .tp_descr_get	= NULL,
	    .tp_descr_set	= NULL,
	    .tp_dictoffset	= 0,
	    .tp_init		= rrr_python3_array_f_init,
	    .tp_alloc		= PyType_GenericAlloc,
	    .tp_new			= rrr_python3_array_f_new,
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

PyObject *rrr_python3_array_new (void) {
	return (PyObject *) PyObject_New(struct rrr_python3_array_data, &rrr_python3_array_type);
}
