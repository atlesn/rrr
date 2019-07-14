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

#include "messages.h"
#include "python3.h"
#include "../global.h"

/*
 * GIL LOCKING MUST BE HANDLED BY THESE TWO FUNCTIONS, OTHER FUNCTIONS
 * DO NOT LOCK THEMSELVES
 */

struct python3_thread_state python3_swap_thread_in(PyThreadState *tstate, int *condition) {
	struct python3_thread_state ret;
	memset (&ret, '\0', sizeof(ret));

	if (tstate != NULL) {
		ret.tstate = tstate;
		ret.condition = condition;
		PyEval_RestoreThread(tstate);
		*(ret.condition) = 1;
	}

	return ret;
}

void python3_swap_thread_out(struct python3_thread_state *tstate_holder) {
	if (tstate_holder->condition != NULL && *(tstate_holder->condition) == 1) {
		if (PyEval_SaveThread() != tstate_holder->tstate) {
			VL_MSG_ERR("Bug: tstates did not match in python3_swap_thread_out\n");
			exit(EXIT_FAILURE);
		}
		if (tstate_holder->condition != NULL) {
			*(tstate_holder->condition) = 0;
		}
	}

	tstate_holder->tstate = NULL;
}

PyObject *rrr_py_import_object (PyObject *dictionary, const char *symbol) {
	PyObject *res = PyDict_GetItemString(dictionary, symbol);
	Py_XINCREF(res);
	return res;
}

PyObject *rrr_py_import_function (PyObject *dictionary, const char *symbol) {
	PyObject *ret = rrr_py_import_object(dictionary, symbol);

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

PyObject *rrr_py_import_and_call_function_no_args(PyObject *dictionary, const char *symbol) {
	PyObject *result = NULL;

	PyObject *function = rrr_py_import_function(dictionary, symbol);
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

/* Should match struct vl_message more or less */
const char *py_message_struct =
		"class vl_message:\n"
		"	type=0\n"
		"	m_class=0\n"
		"	timestamp_from=0\n"
		"	timestamp_to=0\n"
		"	data_numeric=0\n"
		"	length=0\n"
		"	data=bytes(" MSG_DATA_MAX_LENGTH_STR ")\n"
		"	def __init__(self, t, c, tf, tt, dn, l, d : bytearray):\n"
		"		self.type = t\n"
		"		self.m_class = c\n"
		"		self.timestamp_from = tf\n"
		"		self.timestamp_to = tt\n"
		"		self.data_numeric = dn\n"
		"		self.length = l\n"
		"		self.data = d\n"

		"def vl_message_new(t, c, tf, tt, dn, l, d : bytearray):\n"
		"	return vl_message(t, c, tf, tt, dn, l, d)"
;

PyObject *rrr_py_new_message(struct python3_message_maker *message_maker, const struct vl_message *message) {
	PyObject *ret = NULL;
	PyObject *binary_data = NULL;
	PyObject *arglist = NULL;

	binary_data = PyByteArray_FromStringAndSize(message->data, message->length);
	if (binary_data == NULL) {
		VL_MSG_ERR("Could not create python3 binary data: \n");
		PyErr_Print();
		goto out;
	}

	arglist = Py_BuildValue("(kkKKKkO)",
			message->type,
			message->class,
			message->timestamp_from,
			message->timestamp_to,
			message->data_numeric,
			message->length,
			binary_data
	);

	ret = PyObject_CallObject(message_maker->vl_message_new, arglist);
	if (ret == NULL) {
		VL_MSG_ERR("Could not create python3 message object: \n");
		PyErr_Print();
		goto out;
	}

	out:
	Py_XDECREF(arglist);
	Py_XDECREF(binary_data);
	return ret;
}

int rrr_py_message_to_internal(struct vl_message **target, PyObject *py_message) {
	int ret = 0;

	PyObject *type = NULL;
	PyObject *class = NULL;
	PyObject *timestamp_from = NULL;
	PyObject *timestamp_to = NULL;
	PyObject *data_numeric = NULL;
	PyObject *length = NULL;
	PyObject *data = NULL;

	*target = NULL;

	if (strcmp(Py_TYPE(py_message)->tp_name, "vl_message") != 0) {
		VL_MSG_ERR("Bug: rrr_py_message_to_internal was called with wrong object type '%s'\n", Py_TYPE(py_message)->tp_name);
		exit (EXIT_FAILURE);
	}

	struct vl_message *result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_py_message_to_internal\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	type = PyObject_GetAttrString(py_message, "type");
	class = PyObject_GetAttrString(py_message, "m_class");
	timestamp_from = PyObject_GetAttrString(py_message, "timestamp_from");
	timestamp_to = PyObject_GetAttrString(py_message, "timestamp_to");
	data_numeric  = PyObject_GetAttrString(py_message, "data_numeric");
	length = PyObject_GetAttrString(py_message, "length");
	data = PyObject_GetAttrString(py_message, "data");

	if (type == NULL ||
		class == NULL ||
		timestamp_from == NULL ||
		timestamp_to == NULL ||
		data_numeric == NULL ||
		length == NULL ||
		data == NULL
	) {
		VL_MSG_ERR("Could not find all required paramenters in python3 vl_message struct\n");
		ret = 1;
		goto out;
	}

	if (!PyByteArray_Check(data)) {
		VL_MSG_ERR("Returned data in returned message from python3 process function was not a byte array\n");
		ret = 1;
		goto out;
	}

	Py_ssize_t returned_length = PyByteArray_Size(data);
	if (returned_length > MSG_DATA_MAX_LENGTH) {
		VL_MSG_ERR("Returned length of data field was too large (returned: %li, required: <=%i)",
				returned_length, MSG_DATA_MAX_LENGTH);
		ret = 1;
		goto out;
	}

	char *returned_bytes = PyByteArray_AsString(data);
	memcpy(result->data, returned_bytes, returned_length);

	result->type = PyLong_AsUnsignedLong(type);
	result->class = PyLong_AsUnsignedLong(class);
	result->timestamp_from = PyLong_AsUnsignedLongLong(timestamp_from);
	result->timestamp_to = PyLong_AsUnsignedLongLong(timestamp_to);
	result->data_numeric = PyLong_AsUnsignedLongLong(data_numeric);
	result->length = PyLong_AsUnsignedLong(length);

	out:
	if (ret == 0) {
		*target = result;
	}
	else {
		RRR_FREE_IF_NOT_NULL(result);
	}

	Py_XDECREF(type);
	Py_XDECREF(class);
	Py_XDECREF(timestamp_from);
	Py_XDECREF(timestamp_to);
	Py_XDECREF(data_numeric);
	Py_XDECREF(length);
	Py_XDECREF(data);

	return ret;
}

int rrr_py_process_message(PyObject **result, PyObject *process_function, PyObject *message) {
	int ret = 0;

	VL_DEBUG_MSG_3("rrr_py_process_message processing message\n");

	*result = NULL;
	PyObject *res = NULL;
	PyObject *arglist = Py_BuildValue("(O)", message);
	if (arglist == NULL) {
		VL_MSG_ERR("Could not prepare argument list while processing python3 message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	res = PyObject_CallObject(process_function, arglist);
	if (res == NULL) {
		VL_MSG_ERR("Could not run process function while processing python3 message:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_3("rrr_py_process_message received an object of type %s from process function\n", Py_TYPE(res)->tp_name);

	if (strcmp(Py_TYPE(res)->tp_name, "vl_message") == 0) {
		VL_DEBUG_MSG_3("rrr_py_process_message received a vl_message back, return it\n");
		*result = res;
		res = NULL;
	}
	else if (PyLong_Check(res)) {
		VL_DEBUG_MSG_3("rrr_py_process_message received an integer (status message, check if non-zero)\n");
		ret = PyLong_AsLong(res);
		VL_DEBUG_MSG_3("rrr_py_process_message return value from process function: %i\n", ret);
	}
	else {
		VL_DEBUG_MSG_3("rrr_py_process_message received an object of unknown type back from process function\n");
	}

	out:
	Py_XDECREF(res);
	Py_XDECREF(arglist);
	return ret;
}

void rrr_py_destroy_message_struct (struct python3_message_maker *message_maker) {
	Py_XDECREF(message_maker->vl_message_class);
	Py_XDECREF(message_maker->vl_message_new);

	memset (message_maker, '\0', sizeof(*message_maker));
}

int rrr_py_get_message_struct (struct python3_message_maker *target, PyObject *dictionary) {
	PyObject *res = NULL;
	int ret = 0;

	memset (target, '\0', sizeof(*target));

	res = PyRun_String (py_message_struct, Py_file_input, dictionary, dictionary);
	if (res == NULL) {
		VL_MSG_ERR("Could generate python3 message struct: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	Py_XDECREF(res);

	res = rrr_py_import_object(dictionary, "vl_message");
	if (res == NULL) {
		VL_MSG_ERR("Could not find vl_message class while getting message struct: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->vl_message_class = res;

	res = rrr_py_import_function(dictionary, "vl_message_new");
	if (res == NULL) {
		VL_MSG_ERR("Could not find vl_message_new function while getting message struct: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	target->vl_message_new = res;

	out:
	if (ret != 0) {
		rrr_py_destroy_message_struct(target);
	}

	return ret;
}
