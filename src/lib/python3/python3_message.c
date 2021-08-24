/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include "python3_headers.h"

#include "python3_array.h"
#include "python3_module_common.h"
#include "python3_message.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"
#include "../array.h"
#include "../fixed_point.h"
#include "../ip/ip_util.h"
#include "../ip/ip_defines.h"
#include "../util/posix.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"

//static const unsigned long int max_8 = 0xff;
//static const unsigned long int max_16 = 0xffff;
//static const unsigned long int max_32 = 0xffffffff;
//static const unsigned long int max_64 = 0xffffffffffffffff;

struct rrr_python3_rrr_message_constants {
		unsigned int TYPE_MSG;
		unsigned int TYPE_TAG;
		unsigned int CLASS_DATA;
		unsigned int CLASS_ARRAY;
};

static const struct rrr_python3_rrr_message_constants message_constants = {
		MSG_TYPE_MSG,
		MSG_TYPE_TAG,
		MSG_CLASS_DATA,
		MSG_CLASS_ARRAY
};

struct rrr_python3_rrr_message_data {
	PyObject_HEAD
	struct rrr_msg_msg message_static;
	struct rrr_msg_msg *message_dynamic;
	PyObject *rrr_array;
	struct rrr_python3_rrr_message_constants constants;
	struct sockaddr_storage ip_addr;
	socklen_t ip_addr_len;
	uint8_t ip_protocol;
};

static int __rrr_python3_rrr_message_set_topic_and_data (
		struct rrr_python3_rrr_message_data *data,
		const char *topic_str,
		rrr_slength topic_length,
		const char *data_str,
		rrr_slength data_length
) {
	int ret = 0;

	if (topic_length < 0 || data_length < 0) {
		RRR_BUG("Bug: Negative topic and/or data length to __rrr_python3_rrr_message_set_topic_and_data\n");
	}

	if (topic_length > UINT16_MAX) {
		RRR_MSG_0("Topic too long in __rrr_python3_rrr_message_set_topic_and_data (%lli>%lli)\n",
			(long long int) topic_length, (long long int) UINT16_MAX);
		ret = 1;
		goto out;
	}

// Ideally, this should have been Py_SSIZE_T_MAX but it does not work in macros.
// Assuming that Py_ssize_t maps to ssize_t
#if SSIZE_MAX < UINT32_MAX
	// 4-byte width
	if ((rrr_biglength) topic_length + (rrr_biglength) data_length > (rrr_biglength) PY_SSIZE_T_MAX) {
#else
	// 8-byte width
	if ((rrr_biglength) topic_length + (rrr_biglength) data_length > UINT32_MAX) {
#endif
		RRR_MSG_0("Combined size of topic and message too long in __rrr_python3_rrr_message_set_topic_and_data (%llu>%llu)\n",
			(long long unsigned) topic_length + (long long unsigned) data_length, (long long unsigned) UINT16_MAX);
		ret = 1;
		goto out;
	}

	struct rrr_msg_msg *new_message = rrr_msg_msg_duplicate_no_data_with_size (
			data->message_dynamic,
			(uint16_t) topic_length,
			(uint32_t) data_length
	);
	if (new_message == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_python3_rrr_message_set_topic_and_data\n");
		ret = 1;
		goto out;
	}

	memcpy(MSG_TOPIC_PTR(new_message), topic_str, (size_t) topic_length);
	memcpy(MSG_DATA_PTR(new_message), data_str, (size_t) data_length);

	rrr_free(data->message_dynamic);
	data->message_dynamic = new_message;

	memcpy(&data->message_static, data->message_dynamic, sizeof(data->message_static));

	out:
	return ret;
}

static PyObject *rrr_python3_rrr_message_f_set_data (PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	if (data->rrr_array != NULL) {
		RRR_MSG_0("rrr_message.set_data() called while the message contained an array. discard_array() must be called first.\n");
		Py_RETURN_FALSE;
	}

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
		RRR_MSG_0("Unknown data type to rrr_message.set_data(), must be Bytearray or Unicode\n");
		Py_RETURN_FALSE;
	}

	if (__rrr_python3_rrr_message_set_topic_and_data (
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

static PyObject *rrr_python3_rrr_message_f_set_topic (PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	const char *str;
	Py_ssize_t len;
	if (PyUnicode_Check(args)) {
		str = PyUnicode_AsUTF8AndSize(args, &len);
	}
	else {
		RRR_MSG_0("Unknown data type to rrr_message.set_data(), must be Bytearray or Unicode\n");
		Py_RETURN_FALSE;
	}

	if (__rrr_python3_rrr_message_set_topic_and_data (
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

static PyObject *rrr_python3_rrr_message_f_new (PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyObject *self = PyType_GenericNew(type, args, kwds);
	if (self == NULL) {
		return NULL;
	}

	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	data->message_dynamic = rrr_allocate(sizeof(*(data->message_dynamic)) - 1);
	if (data->message_dynamic == NULL) {
		RRR_MSG_0("Could not allocate memory for message in rrr_python3_rrr_message_f_new\n");
		return NULL;
	}

	memset (data->message_dynamic, '\0', sizeof(*(data->message_dynamic)) - 1);
	memset (&data->message_static, '\0', sizeof(data->message_static));

	data->constants = message_constants;

	return self;
}

static int rrr_python3_rrr_message_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	memset (&data->message_static, '\0', sizeof(data->message_static));
	memset (data->message_dynamic, '\0', sizeof(*(data->message_dynamic)) - 1);

	if (kwds != NULL && PyDict_Size(kwds) != 0) {
		RRR_MSG_0("Keywords not supported in rrr_message init\n");
		return 1;
	}

	uint64_t new_timestamp = rrr_time_get_64();

	Py_ssize_t argc = PyTuple_Size(args);
	if (argc != 0) {
		if (argc != 1) {
			RRR_MSG_0("Wrong number of parameters to rrr_messag init. Got %lli but expected 1 or 0.\n",
				(long long int) argc);
			return 1;
		}

		PyObject *args_timestamp = PyTuple_GetItem(args, 0);
		if (!PyLong_Check(args_timestamp)) {
			RRR_MSG_0("Timestamp argument to rrr_message init was not a number.\n");
			return 1;
		}

		new_timestamp = RRR_PY_LONG_AS_64(args_timestamp);
	}

	data->message_static.timestamp = new_timestamp;
	MSG_SET_TYPE(&data->message_static, MSG_TYPE_MSG);
	MSG_SET_CLASS(&data->message_static, MSG_CLASS_DATA);

	return 0;
}

static void rrr_python3_rrr_message_f_dealloc (PyObject *self) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	RRR_FREE_IF_NOT_NULL(data->message_dynamic);
	Py_XDECREF(data->rrr_array);
	PyObject_Del(self);
}

static PyObject *rrr_python3_rrr_message_f_get_data(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	const rrr_biglength msg_data_length = MSG_DATA_LENGTH(data->message_dynamic);

	if (msg_data_length > SSIZE_MAX) {
		RRR_MSG_0("Message size overflow while getting data in python3\n");
		Py_RETURN_FALSE;
	}	

	PyObject *ret = PyByteArray_FromStringAndSize(MSG_DATA_PTR(data->message_dynamic), (ssize_t) msg_data_length);

	if (ret == NULL) {
		RRR_MSG_0("Could not create bytearray object for topic in rrr_python3_rrr_message_f_get_data\n");
		PyErr_Print();
		Py_RETURN_FALSE;
	}

	return ret;
}

static PyObject *rrr_python3_rrr_message_f_get_array(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	if (data->rrr_array == NULL) {
		data->rrr_array = rrr_python3_array_new();
		if (data->rrr_array == NULL) {
			RRR_MSG_0("Could not create new array in rrr_message.get_array()");
			Py_RETURN_NONE;
		}
	}

	Py_INCREF(data->rrr_array);
	return data->rrr_array;
}

static PyObject *rrr_python3_rrr_message_f_has_array(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	if (data->rrr_array != NULL) {
		Py_RETURN_TRUE;
	}

	Py_RETURN_FALSE;
}

static PyObject *rrr_python3_rrr_message_f_discard_array(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	Py_XDECREF(data->rrr_array);
	data->rrr_array = NULL;

	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_rrr_message_f_set_array (PyObject *self, PyObject *arg) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	if (!rrr_python3_array_check(arg)) {
		RRR_MSG_0("Argument to rrr_message.set_array() must be an rrr_array\n");
		Py_RETURN_FALSE;
	}

	Py_XDECREF(data->rrr_array);
	Py_INCREF(arg);
	data->rrr_array = arg;

	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_rrr_message_f_get_topic(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	PyObject *ret = NULL;
	if (MSG_TOPIC_LENGTH(data->message_dynamic) > 0) {
		ret = PyUnicode_FromStringAndSize(MSG_TOPIC_PTR(data->message_dynamic), MSG_TOPIC_LENGTH(data->message_dynamic));
	}
	else {
		ret = PyUnicode_FromString("");
	}
	if (ret == NULL) {
		RRR_MSG_0("Could not create unicode object for topic in rrr_python3_rrr_message_f_get_topic\n");
		PyErr_Print();
		Py_RETURN_FALSE;
	}

	return ret;
}

static PyObject *rrr_python3_rrr_message_f_get_ip(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	PyObject *ret = NULL;

	if (data->ip_addr_len == 0) {
		Py_RETURN_NONE;
	}

	char ip_addr[128];
	uint16_t port_u = 0;

	if (rrr_ip_to_str_and_port(&port_u, ip_addr, sizeof(ip_addr), (const struct sockaddr *) &data->ip_addr, data->ip_addr_len) != 0) {
		RRR_MSG_0("Failed to convert IP address in rrr_message.get_ip()\n");
		goto out_false;
	}

	if ((ret = PyTuple_New(2)) == NULL) {
		RRR_MSG_0("Failed to create tuple in rrr_python3_rrr_message_f_get_ip\n");
		PyErr_Print();
		goto out_false;
	}

	{
		PyObject *ip = PyUnicode_FromString(ip_addr);
		if (ip == NULL) {
			RRR_MSG_0("Failed to create python string in rrr_python3_rrr_message_f_get_ip\n");
			PyErr_Print();
			goto out_false;
		}
		PyTuple_SET_ITEM(ret, 0, ip);
	}

	{
		PyObject *port = PyLong_FromUnsignedLong(port_u);
		if (port == NULL) {
			RRR_MSG_0("Failed to create python long in rrr_python3_rrr_message_f_get_ip\n");
			PyErr_Print();
			goto out_false;
		}
		PyTuple_SET_ITEM(ret, 1, port);
	}

	goto out;
	out_false:
		Py_XDECREF(ret);
		Py_RETURN_FALSE;
	out:
		return ret;
}

static PyObject *rrr_python3_rrr_message_f_clear_ip(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	data->ip_addr_len = 0;
	memset(&data->ip_addr, '\0', sizeof(data->ip_addr));

	Py_RETURN_TRUE;
}

static int __rrr_python3_rrr_message_f_set_ip_extract_ip (char **target, PyObject *ip) {
	int ret = 0;

	*target = NULL;

	Py_ssize_t ip_str_size = 0;
	const char *ip_str_tmp = PyUnicode_AsUTF8AndSize(ip, &ip_str_size);

	if (ip_str_size <= 0 || (size_t) ip_str_size > SIZE_MAX - 1) {
		RRR_MSG_0("Error: IP given to rrr_message.set_ip() was empty or too big\n");
		ret = 1;
		goto out;
	}

	const size_t final_size = (size_t) ip_str_size + 1;

	char *result;
	if ((result = rrr_allocate(final_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory for string in __rrr_python3_rrr_message_f_set_ip_extract_ip\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', final_size);
	memcpy(result, ip_str_tmp, (size_t) ip_str_size);

	*target = result;

	out:
	return ret;
}

static PyObject *rrr_python3_rrr_message_f_set_ip(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	int ret = 0;

	char *ip_str_tmp = NULL;

	if (PyTuple_Size(args) != 2) {
		RRR_MSG_0("Error: Wrong number of arguments to rrr_message.set_ip(), excactly two arguments are expected but %lli were given.\n",
				(long long int) PyTuple_Size(args));
		ret = 1;
		goto out;
	}

	int af_protocol = 0;
	char ip_bin_tmp[sizeof(((struct sockaddr_in6 *) NULL)->sin6_addr)];

	memset(ip_bin_tmp, '\0', sizeof(ip_bin_tmp));

	// Convert IP argument
	{
		// Borrowed reference
		PyObject *ip = PyTuple_GetItem(args, 0);
		if (!PyUnicode_Check(ip)) {
			RRR_MSG_0("Error: First argument to rrr_message.set_ip() was not a string.\n");
			ret = 1;
			goto out;
		}

		if ((ret = __rrr_python3_rrr_message_f_set_ip_extract_ip(&ip_str_tmp, ip)) != 0) {
			goto out;
		}

		// IPv6 must be checked first as this address may also contain dots .
		if (strchr(ip_str_tmp, ':') != NULL) {
			af_protocol = AF_INET6;
		}
		else if (strchr(ip_str_tmp, '.') != NULL) {
			af_protocol = AF_INET;
		}
		else {
			RRR_MSG_0("Error: Could not find colon : or dot . in IP given to rrr_message.set_ip() which was '%s'\n", ip_str_tmp);
			ret = 1;
			goto out;
		}

		// Note : Returns 1 on success
		if (inet_pton(af_protocol, ip_str_tmp, ip_bin_tmp) != 1) {
			RRR_MSG_0("Error: Could not convert IP given to rrr_message.set_ip() which was '%s'. The value was invalid.\n", ip_str_tmp);
			ret = 1;
			goto out;
		}
	}

	long int port_long = 0;

	// Convert port argument
	{
		// Borrowed reference
		PyObject *port = PyTuple_GetItem(args, 1);
		if (PyLong_Check(port)) {
			printf("is long\n");
			port_long = PyLong_AsLong(port);
		}
		else if (PyUnicode_Check(port)) {
			PyObject *port_long_tmp = NULL;
			if ((port_long_tmp = PyLong_FromUnicodeObject(port, 10)) == NULL) {
				RRR_MSG_0("Error: Could convert port given to rrr_message.set_ip() to number\n");
				PyErr_Print();
				ret = 1;
				goto out;
			}
			port_long = PyLong_AsLong(port_long_tmp);
			Py_XDECREF(port_long_tmp);
		}

		if (port_long < 1 || port_long > 65535) {
			RRR_MSG_0("Error: Invalidt port given to rrr_message.set_ip(). The value was %li after conversion.\n", port_long);
			ret = 1;
			goto out;
		}
	}

	struct sockaddr_storage sockaddr_tmp = {0};

	// Save address and port
	{
		if (af_protocol == AF_INET6) {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &sockaddr_tmp;
			in6->sin6_family = AF_INET6;
			in6->sin6_port = htons((uint16_t) port_long);
			memcpy(&in6->sin6_addr, ip_bin_tmp, sizeof(in6->sin6_addr));

			data->ip_addr_len = sizeof(*in6);
		}
		else {
			struct sockaddr_in *in = (struct sockaddr_in *) &sockaddr_tmp;
			in->sin_family = AF_INET6;
			in->sin_port = htons((uint16_t) port_long);
			memcpy(&in->sin_addr, ip_bin_tmp, sizeof(in->sin_addr));

			data->ip_addr_len = sizeof(*in);
		}
	}

	RRR_ASSERT(sizeof(data->ip_addr) == sizeof(sockaddr_tmp), rrr_python3_rrr_message_f_set_ip_correct_size_of_sockaddr_tmp);

	memcpy(&data->ip_addr, &sockaddr_tmp, sizeof(sockaddr_tmp));

	out:
	RRR_FREE_IF_NOT_NULL(ip_str_tmp);
	if (ret) {
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE;
}

static PyObject *rrr_python3_rrr_message_f_get_ip_proto(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	(void)(args);

	PyObject *ret = NULL;

	const char *protocol = "";

	if (data->ip_protocol == RRR_IP_TCP) {
		protocol = "TCP";
	}
	else if (data->ip_protocol == RRR_IP_UDP) {
		protocol = "UDP";
	}

	if ((ret = PyUnicode_FromString(protocol)) == NULL) {
		RRR_MSG_0("Could not allocate string in rrr_python3_rrr_message_f_get_ip_proto\n");
		goto out;
	}

	out:
	if (ret != NULL) {
		return ret;
	}
	Py_RETURN_FALSE;
}

static PyObject *rrr_python3_rrr_message_f_set_ip_proto(PyObject *self, PyObject *args) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;

	int ret = 0;

	if (!PyUnicode_Check(args)) {
		RRR_MSG_0("Error: Value given to rrr_message.set_ip_proto() was not a string\n");
		ret = 1;
		goto out;
	}

	const char *protocol = NULL;
	Py_ssize_t protocol_len = 0;

	protocol = PyUnicode_AsUTF8AndSize(args, &protocol_len);

	if (protocol_len == 0) {
		data->ip_protocol = 0;
	}
	else if (protocol_len != 3) {
		goto out_invalid_value;
	}
	else if (rrr_posix_strncasecmp(protocol, "TCP", 3) == 0) {
		data->ip_protocol = RRR_IP_TCP;
	}
	else if (rrr_posix_strncasecmp(protocol, "UDP", 3) == 0) {
		data->ip_protocol = RRR_IP_UDP;
	}
	else {
		goto out_invalid_value;
	}

	goto out;
	out_invalid_value:
		RRR_MSG_0("Error: Invalid value given to rrr_message.set_ip_proto(), value must be TCP, UDP or empty\n");
		ret = 1;
		goto out;
	out:
	if (ret != 0) {
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE;
}

static PyMethodDef rrr_message_methods[] = {
		{
				.ml_name	= "set_data",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_set_data,
				.ml_flags	= METH_O,
				.ml_doc		= "Set data parameter"
		},
		{
				.ml_name	= "get_data",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_get_data,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get data parameter from message as byte array"
		},
		{
				.ml_name	= "get_array",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_get_array,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get array object from message (or create one) for reading and writing values"
		},
		{
				.ml_name	= "has_array",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_has_array,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Check if the message has an array"
		},
		{
				.ml_name	= "discard_array",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_discard_array,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Discard array of message (if any present)"
		},
		{
				.ml_name	= "set_array",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_set_array,
				.ml_flags	= METH_O,
				.ml_doc		= "Set the array of a message, discarding any existing array."
		},
		{
				.ml_name	= "set_topic",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_set_topic,
				.ml_flags	= METH_O,
				.ml_doc		= "Set topic parameter"
		},
		{
				.ml_name	= "get_topic",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_get_topic,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get topic parameter from message as a string"
		},
		{
				.ml_name	= "get_ip",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_get_ip,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get IP and port tuplet from the message"
		},
		{
				.ml_name	= "clear_ip",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_clear_ip,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Clear any IP address information from the message"
		},
		{
				.ml_name	= "set_ip",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_set_ip,
				.ml_flags	= METH_VARARGS,
				.ml_doc		= "Set IP address and port of a message"
		},
		{
				.ml_name	= "get_ip_proto",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_get_ip_proto,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get the protocol of a message, either UDP or TCP"
		},
		{
				.ml_name	= "set_ip_proto",
				.ml_meth	= (PyCFunction) rrr_python3_rrr_message_f_set_ip_proto,
				.ml_flags	= METH_O,
				.ml_doc		= "Set the protocol of a message, either UDP or TCP"
		},
		{ NULL, NULL, 0, NULL }
};

static struct rrr_python3_rrr_message_data dummy;
#define RRR_PY_RRR_MESSAGE_OFFSET(member) \
	(((void*) &(dummy.message_static.member)) - ((void*) &(dummy)))
#define RRR_PY_RRR_MESSAGE_CONSTANT_OFFSET(member) \
	(((void*) &(dummy.constants.member)) - ((void*) &(dummy)))

static PyMemberDef rrr_message_members[] = {
		{"type_and_class",	RRR_PY_16,	RRR_PY_RRR_MESSAGE_OFFSET(type_and_class),	0, "Type and class"},
		{"timestamp",		RRR_PY_64,	RRR_PY_RRR_MESSAGE_OFFSET(timestamp),		0, "Timestamp"},

		{"TYPE_MSG",		RRR_PY_32,	RRR_PY_RRR_MESSAGE_CONSTANT_OFFSET(TYPE_MSG),		READONLY,	"Type is MSG (default)"},
		{"TYPE_TAG",		RRR_PY_32,	RRR_PY_RRR_MESSAGE_CONSTANT_OFFSET(TYPE_TAG),		READONLY,	"Type is TAG"},
		{"CLASS_DATA",		RRR_PY_32,	RRR_PY_RRR_MESSAGE_CONSTANT_OFFSET(CLASS_DATA),		READONLY,	"Class is DATA (default)"},
		{"CLASS_ARRAY",		RRR_PY_32,	RRR_PY_RRR_MESSAGE_CONSTANT_OFFSET(CLASS_ARRAY),	READONLY,	"Class is ARRAY"},
		{ NULL, 0, 0, 0, NULL}
};

PyTypeObject rrr_python3_rrr_message_type = {
		.ob_base		= PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    .tp_name		= RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_RRR_MESSAGE_TYPE_NAME,
	    .tp_basicsize	= sizeof(struct rrr_python3_rrr_message_data),
		.tp_itemsize	= 0,
	    .tp_dealloc		= (destructor) rrr_python3_rrr_message_f_dealloc,
#ifdef RRR_PYTHON3_HAS_PTYPEOBJECT_TP_PRINT
	    .tp_print		= NULL,
#endif
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
	    .tp_doc			= "ReadRouteRecord type for RRR Message structure",
	    .tp_traverse	= NULL,
	    .tp_clear		= NULL,
	    .tp_richcompare	= NULL,
	    .tp_weaklistoffset = 0,
	    .tp_iter		= NULL,
	    .tp_iternext	= NULL,
	    .tp_methods		= rrr_message_methods,
	    .tp_members		= rrr_message_members,
	    .tp_getset		= NULL,
	    .tp_base		= NULL,
	    .tp_dict		= NULL,
	    .tp_descr_get	= NULL,
	    .tp_descr_set	= NULL,
	    .tp_dictoffset	= 0,
	    .tp_init		= rrr_python3_rrr_message_f_init,
	    .tp_alloc		= PyType_GenericAlloc,
	    .tp_new			= rrr_python3_rrr_message_f_new,
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

#define ALLOCATE_DEF                                           \
    struct rrr_type_value **target,                            \
    uint8_t type,                                              \
    uint8_t type_flags,                                        \
    rrr_length item_size,                                      \
    const char *tag,                                           \
    rrr_length tag_length,                                     \
    rrr_length elements

#define CONVERT_DEF                                            \
    struct rrr_type_value *target,                             \
    PyObject *item,                                            \
    rrr_length index,                                          \
    rrr_length size

#define PRELIMINARY_CHECK_DEF                                  \
    int (**allocate_function)(ALLOCATE_DEF),                   \
    int (**convert_function)(CONVERT_DEF),                     \
    uint8_t *target_type,                                      \
    uint8_t *target_type_flags,                                \
    rrr_length *size,                                          \
    PyObject **new_subject,                                    \
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
			NULL,
			elements,
			NULL,
			sizeof(rrr_type_h) * elements
	) != 0) {
		RRR_MSG_0("Could not allocate 64 bit value in __allocate_64\n");
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
			NULL,
			elements,
			NULL,
			item_size * elements
	) != 0) {
		RRR_MSG_0("Could not allocate blob value in __allocate_64\n");
		return 1;
	}

	return 0;
}

void __convert_save_data (
		struct rrr_type_value *target,
		const void *data,
		rrr_length index,
		rrr_length allocated_size,
		rrr_length new_size
) {
	char *pos = target->data + new_size * index;

	if (new_size != allocated_size) {
		RRR_BUG("Size mismatch in __convert_save_data\n");
	}

	if (pos + new_size > target->data + target->total_stored_length) {
		RRR_BUG("Write position exceeds total stored length in __convert_save_data\n");
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

static int __convert_check_str (
		rrr_length *new_size_final,
		ssize_t new_size,
		const char *str
) {
	if (str == NULL || new_size < 0) {
		RRR_MSG_0("Could not convert string in  __convert_*\n");
		return 1;
	}

#if RRR_LENGTH_MAX < SSIZE_MAX
	if (new_size > RRR_LENGTH_MAX) {
		RRR_MSG_0("String too long in __convert_* (%lli>%lli)\n",
			 (long long int) new_size, (long long int) RRR_LENGTH_MAX);
		return 1;
	}
#endif

	*new_size_final = (rrr_length) new_size;

	return 0;
}

static int __convert_str (CONVERT_DEF) {
	ssize_t new_size = 0;
	const char *str = PyUnicode_AsUTF8AndSize(item, &new_size);

	rrr_length new_size_final = 0;
	if (__convert_check_str(&new_size_final, new_size, str) != 0) {
		return 1;
	}

	__convert_save_data(target, str, index, size, new_size_final);

	return 0;
}

static int __convert_blob (CONVERT_DEF) {
	ssize_t new_size = PyByteArray_Size(item);
	const char *str = PyByteArray_AsString(item);

	rrr_length new_size_final = 0;
	if (__convert_check_str(&new_size_final, new_size, str) != 0) {
		return 1;
	}

	__convert_save_data(target, str, index, size, new_size_final);

	return 0;
}

static int __convert_vain (CONVERT_DEF) {
	(void)(target);
	(void)(item);
	(void)(size);

	if (index > 0) {
		RRR_MSG_0("Multiple values not supported for Py_None/vain type\n");
		return 1;
	}

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
				RRR_MSG_0("Error while converting double in __preliminary_check_fixp\n");
				ret = 1;
				goto out;
			}
			if ((ret = rrr_fixp_ldouble_to_fixp(&test_f, test_d)) != 0) {
				RRR_MSG_0("Could not convert double to fixed pointer in __preliminary_check_fixp\n");
				goto out;
			}
		}
		else if (PyUnicode_Check(subject)) {
			const char *str = PyUnicode_AsUTF8(subject);
			if (str == NULL) {
				RRR_MSG_0("Could not convert unicode to string in __preliminary_check_fixp\n");
				ret = 1;
				goto out;
			}

			Py_ssize_t length = PyUnicode_GetLength(subject);
			if (length < 0) {
				RRR_MSG_0("Negative result from GetLength in __preliminary_check_fixp\n");
				ret = 1;
				goto out;
			}
#if RRR_LENGTH_MAX < SSIZE_MAX
			else if (length > RRR_LENGTH_MAX) {
				length = RRR_LENGTH_MAX;
			}
#endif

			const char *endptr;
			if ((ret = rrr_fixp_str_to_fixp(&test_f, str, (rrr_length) length, &endptr)) != 0) {
				RRR_MSG_0("Error while converting string to fixed pointer in __preliminary_check_fixp\n");
				goto out;
			}

			if (endptr == str) {
				RRR_MSG_0("Could not understand supposed fixed point string '%s' while converting\n", str);
				ret = 1;
				goto out;
			}
		}
		else {
			RRR_MSG_0("Unknown type '%s' while converting to fixed point\n", subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if ((replacement_subject = PyLong_FromLongLong(test_f)) == NULL) {
			RRR_MSG_0("Could not allocate replacement unicode string for type %s in __preliminary_check_fixp\n",
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
			RRR_MSG_0("Error while converting double in __preliminary_check_long\n");
			ret = 1;
			goto out;
		}
		// Value of INT64_MAX as double
		if (test_d > 9223372036854775807.0 || test_d < INT64_MIN) {
			RRR_MSG_0("Double value was out of range in __preliminary_check_long\n");
			ret = 1;
			goto out;
		}
		if (!isfinite(test_d)) {
			RRR_MSG_0("Double value was not finite in __preliminary_check_long\n");
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
		(void)(test_u);
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
			RRR_MSG_0("Could not create long object in __preliminary_check_long\n");
			ret = 1;
			goto out;
		}
	do_signed:
		RRR_TYPE_FLAG_SET_SIGNED(*target_type_flags);
		*convert_function = __convert_long;
		goto out;

	do_unsigned_and_convert:
		if ((replacement_subject = PyLong_FromUnsignedLongLong(test_u)) == NULL) {
			RRR_MSG_0("Could not create long object in __preliminary_check_long\n");
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
					RRR_MSG_0("Could not convert long to string in __preliminary_check_stringish\n");
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
				RRR_MSG_0("Could not convert double to string in __preliminary_check_stringish\n");
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
			RRR_MSG_0("Unsupported type '%s' while converting to string in __preliminary_check_stringish\n",
					subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if (replacement_subject == NULL) {
			RRR_MSG_0("Could not allocate replacement unicode string for type %s in __preliminary_check_stringish\n",
					subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if (new_size == 0) {
			new_size = PyUnicode_GetLength(replacement_subject);
		}
	}

#if RRR_LENGTH_MAX < SSIZE_MAX
	if (new_size > RRR_LENGTH_MAX) {
		RRR_MSG_0("Size overflow in __preliminary_check_stringish (%lli>%lli)\n",
			(long long int) new_size, (long long int) RRR_LENGTH_MAX);
		ret = 1;
		goto out;
	}
#endif

	if (*size != 0 && (rrr_slength) *size != (rrr_slength) new_size) {
		RRR_MSG_0("Size of strings in array was not of equal length, which is required.\n");
		ret = 1;
		goto out;
	}

	*new_subject = replacement_subject;
	*allocate_function = __allocate_blob;
	*convert_function = __convert_str;
	if (*target_type == 0) {
		*target_type = RRR_TYPE_STR;
	}
	*target_type_flags = 0;
	*size = (rrr_length) new_size;

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
		RRR_MSG_0("Could not get string from unicode in __preliminary_check_sep\n");
		return 1;
	}

	for (rrr_length i = 0; i < *size; i++) {
		unsigned char c = (unsigned char) str[i];
		if (!RRR_TYPE_CHAR_IS_SEP(c) && !RRR_TYPE_CHAR_IS_STX(c)) {
			RRR_MSG_0("Found non-separator character 0x%02x in supposed separator string while converting\n", c);
			ret = 1;
			// Don't break, report all errors
		}
	}

	return ret;
}

static int __preliminary_check_blob (PRELIMINARY_CHECK_DEF) {
	int ret = 0;

	PyObject *replacement_subject = NULL;
	rrr_length new_size = 0;

	if (PyByteArray_Check(subject)) {
		new_size = (rrr_length) PyByteArray_Size(subject);
	}
	else {
		if (PyBytes_Check(subject)) {
			new_size = (rrr_length) PyBytes_Size(subject);
			replacement_subject = PyByteArray_FromObject(subject);
		}
		else if (PyUnicode_Check(subject)) {
			Py_ssize_t py_new_size = 0;
			const char *str = PyUnicode_AsUTF8AndSize(subject, &py_new_size);
			if (str == NULL) {
				RRR_MSG_0("Could not get string from unicode object in __preliminary_check_blob\n");
				ret = 1;
				goto out;
			}
#if RRR_LENGTH_MAX < SSIZE_MAX
			if (py_new_size < 0 || py_new_size > RRR_LENGTH_MAX) {
#else
			if (py_new_size < 0) {
#endif
				RRR_MSG_0("Negative or too long size in __preliminary_check_blob (%lli vs %lli)\n",
					(long long int) py_new_size, (long long int) (RRR_LENGTH_MAX));
				ret = 1;
				goto out;
			}
			replacement_subject = PyByteArray_FromStringAndSize(str, py_new_size);
			new_size = (rrr_length) py_new_size;
		}
		else {
			RRR_MSG_0("Could not convert type %s to bytearray in __preliminary_check_blob\n",
					subject->ob_type->tp_name);
			ret = 1;
			goto out;
		}

		if (replacement_subject == NULL) {
			RRR_MSG_0("Could not create replacement bytearray in __preliminary_check_blob\n");
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

static int __preliminary_check_vain (PRELIMINARY_CHECK_DEF) {
	(void)(new_subject);

	int ret = 0;

	if (subject != Py_None) {
		RRR_MSG_0("Value of type %s found when Py_None was expected in __preliminary_check_vain\n",
				subject->ob_type->tp_name);
		ret = 1;
		goto out;
	}

	*convert_function = __convert_vain;
	*allocate_function = __allocate_blob;
	*target_type = RRR_TYPE_VAIN;
	*target_type_flags = 0;
	*size = 0;

	out:
	return ret;
}


static int __rrr_python3_array_rrr_message_get_message_store_array_node_callback (
		PyObject *tag,
		PyObject *list,
		uint8_t type_orig,
		void *arg
) {
	struct rrr_array *target = arg;

	int ret = 0;

	struct rrr_type_value *new_value = NULL;

	const char *tag_str = NULL;
	rrr_length tag_length = 0;

	ssize_t count = 0;
	PyObject *first_item = PyList_GetItem(list, 0); // Borrowed reference

	uint8_t target_type = 0;
	uint8_t target_type_flags = 0;

	rrr_length item_size = 0;

	int (*preliminary_check_function)(PRELIMINARY_CHECK_DEF) = NULL;
	int (*allocate_function)(ALLOCATE_DEF) = NULL;
	int (*convert_function)(CONVERT_DEF) = NULL;

	if (list == NULL) {
		RRR_BUG("List was NULL in __rrr_python3_array_rrr_message_get_message_store_array_node_callback\n");
	}

	Py_INCREF(list);

	if (tag == NULL || tag == Py_None) {
		tag_str = "";
		tag_length = 0;
	}
	else {
		if (!PyUnicode_Check(tag)) {
			RRR_MSG_0("Tag of array element was not a string\n");
			ret = 1;
			goto out;
		}

		ssize_t tag_length_tmp;
		if ((tag_str = PyUnicode_AsUTF8AndSize(tag, &tag_length_tmp)) == NULL) {
			RRR_MSG_0("Could not convert tag object to string in __rrr_python3_array_rrr_message_get_message_store_array_node_callback\n");
			ret = 1;
			goto out;
		}

#if RRR_LENGTH_MAX < SSIZE_MAX
		if (tag_length_tmp > RRR_LENGTH_MAX) {
			RRR_MSG_0("Tag was too long itn __rrr_python3_array_rrr_message_get_message_store_array_node_callback (%lli>%lli)\n",
				(long long int) tag_length_tmp, (long long int) RRR_LENGTH_MAX);
			ret = 1;
			goto out;
		}
#endif

		tag_length = (rrr_length) tag_length_tmp;
	}

	if (!PyList_Check(list)) {
		RRR_BUG("Value was not a list in __rrr_python3_array_rrr_message_get_message_store_array_node_callback\n");
	}

	{
		count = PyList_GET_SIZE(list);
#if RRR_LENGTH_MAX < SSIZE_MAX
		if (count < 1 || first_item == NULL || count > RRR_LENGTH_MAX) {
#else
		if (count < 1 || first_item == NULL) {
#endif
			RRR_MSG_0("List of node had no value elements or list length overflow in __rrr_python3_array_rrr_message_get_message_store_array_node_callback\n");
			ret = 1;
			goto out;
		}
	}

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
		else if (RRR_TYPE_IS_STX(type_orig)) {
			target_type = RRR_TYPE_STX;
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
		else if (RRR_TYPE_IS_VAIN(type_orig)) {
			preliminary_check_function = __preliminary_check_vain;
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
		else if (first_item == Py_None) {
			preliminary_check_function = __preliminary_check_vain;
		}
	}

	if (preliminary_check_function == NULL) {
		RRR_MSG_0("Type '%s' is not supported and cannot be used in arrays\n", first_item->ob_type->tp_name);
		ret = 1;
		goto out;
	}

	for (ssize_t i = 0; i < count; i++) {
		PyObject *item = PyList_GET_ITEM(list, (ssize_t) i);
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
			RRR_MSG_0("Could not convert item of type '%s' in array, preliminary check failed\n", item->ob_type->tp_name);
			goto out;
		}

		if (replacement_item != NULL) {
			Py_DECREF(item);
			PyList_SET_ITEM(list, i, replacement_item);
		}

		if (convert_function == NULL) {
			RRR_MSG_0("Could not convert item of type '%s' to type '%u' in array, item is not convertible to target type\n",
					item->ob_type->tp_name, target_type);
			ret = 1;
			goto out;
		}
	}

	if ((ret = allocate_function (
			&new_value,
			target_type,
			target_type_flags,
			item_size,
			tag_str,
			rrr_length_from_slength_bug_const(tag_length),
			rrr_length_from_slength_bug_const(count)
	)) != 0) {
		RRR_MSG_0("Could not allocate memory for type %u in __rrr_python3_array_rrr_message_get_message_store_array_node_callback\n",
				target_type);
		goto out;
	}

	for (ssize_t i = 0; i < count; i++) {
		PyObject *item = PyList_GET_ITEM(list, i);
		if ((ret = convert_function(new_value, item, (rrr_length) i, item_size)) != 0) {
			RRR_MSG_0("Error while converting value of type '%s' to %u\n",
					item->ob_type->tp_name, target_type);
			goto out;
		}
	}

	RRR_LL_APPEND(target, new_value);
	new_value = NULL;

	out:
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
	Py_DECREF(list);
	return ret;
}

struct rrr_msg_msg *rrr_python3_rrr_message_get_message (struct rrr_msg_addr *message_addr, PyObject *self) {
	struct rrr_python3_rrr_message_data *data = (struct rrr_python3_rrr_message_data *) self;
	struct rrr_array array_tmp = {0};

	struct rrr_msg_msg *ret = data->message_dynamic;
	struct rrr_msg_msg *new_msg = NULL;

	// Overwrite header fields
	memcpy (ret, &data->message_static, sizeof(data->message_static) - 1);

	uint8_t type_orig = MSG_TYPE(ret);

	// If array is present, also overwrite the body
	if (data->rrr_array != NULL) {
		if (rrr_python3_array_iterate (
				data->rrr_array,
				__rrr_python3_array_rrr_message_get_message_store_array_node_callback,
				&array_tmp
		) != 0) {
			RRR_MSG_0("Error while iterating array in rrr_python3_rrr_message_get_message\n");
			goto out_err;
		}

		if (rrr_array_new_message_from_array (
				&new_msg,
				&array_tmp,
				ret->timestamp,
				MSG_TOPIC_PTR(ret),
				MSG_TOPIC_LENGTH(ret)
		) != 0) {
			RRR_MSG_0("Could not create new array message in rrr_python3_rrr_message_get_message\n");
			goto out_err;
		}

		rrr_free(ret);
		ret = new_msg;
		data->message_dynamic = new_msg;
		new_msg = NULL;
	}
	else {
		MSG_SET_CLASS(ret, MSG_CLASS_DATA);
	}

	// Make sure the message type is preserver in case the user has changed it. The user is however
	// not able to choose the class, this is always set to to either ARRAY or DATA.
	MSG_SET_TYPE(ret, type_orig);

	if (!MSG_TYPE_OK(ret)) {
		RRR_MSG_0("Warning: Detected unknown message type %u while converting python3 RRR message, this might cause problems in other modules.\n",
				MSG_TYPE(ret));
	}

	memcpy (&message_addr->addr, &data->ip_addr, data->ip_addr_len);
	RRR_MSG_ADDR_SET_ADDR_LEN(message_addr, data->ip_addr_len);
	message_addr->protocol = data->ip_protocol;

	goto out;
	out_err:
		ret = NULL;

	out:
		RRR_FREE_IF_NOT_NULL(new_msg);
		rrr_array_clear(&array_tmp);
		return ret;
}

PyObject *rrr_python3_rrr_message_new_from_message_and_address (
		const struct rrr_msg_msg *msg,
		const struct rrr_msg_addr *message_addr
) {
	struct rrr_python3_rrr_message_data *ret = NULL;
	struct rrr_array array_tmp = {0};
	PyObject *node_list = NULL;
	PyObject *node_element_value = NULL;
	PyObject *node_tag = NULL;

	if (msg->msg_size < MSG_MIN_SIZE(&ret->message_static)) {
		RRR_BUG("Received object of wrong size in rrr_python3_rrr_message_new_from_message_and_address\n");
	}

	ret = (struct rrr_python3_rrr_message_data *) rrr_python3_rrr_message_f_new(&rrr_python3_rrr_message_type, NULL, NULL);
	if (ret == NULL) {
		goto out_err;
	}

	if (message_addr != NULL) {
		memcpy(&ret->ip_addr, &message_addr->addr, RRR_MSG_ADDR_GET_ADDR_LEN(message_addr));
		ret->ip_addr_len = (socklen_t) RRR_MSG_ADDR_GET_ADDR_LEN(message_addr);
		ret->ip_protocol = message_addr->protocol;
	}
	else {
		memset(&ret->ip_addr, '\0', sizeof(ret->ip_addr));
		ret->ip_addr_len = 0;
	}

	RRR_FREE_IF_NOT_NULL(ret->message_dynamic);

	ret->message_dynamic = rrr_allocate(MSG_TOTAL_SIZE(msg));
	if (ret->message_dynamic == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_python3_rrr_message_new_from_message_and_address\n");
		goto out_err;
	}

	memcpy(ret->message_dynamic, msg, MSG_TOTAL_SIZE(msg));
	memcpy(&ret->message_static, ret->message_dynamic, sizeof(ret->message_static) - 1);

	ret->rrr_array = NULL;

	if (!MSG_IS_ARRAY(msg)) {
		goto no_array;
	}

	ret->rrr_array = rrr_python3_array_new();
	if (ret->rrr_array == NULL) {
		RRR_MSG_0("Could not create array in rrr_python3_rrr_message_new_from_message_and_address\n");
		goto out_err;
	}

	uint16_t array_version_dummy;
	if (rrr_array_message_append_to_array(&array_version_dummy, &array_tmp, msg) != 0) {
		RRR_MSG_0("Could not parse array from message in rrr_python3_rrr_message_new_from_message_and_address\n");
		goto out_err;
	}

	RRR_LL_ITERATE_BEGIN(&array_tmp, struct rrr_type_value);
		if (node->tag == NULL) {
			node_tag = PyUnicode_FromString("");
		}
		else {
			node_tag = PyUnicode_FromString(node->tag);
			if (node_tag == NULL) {
				RRR_MSG_0("Could not create node for tag in rrr_python3_rrr_message_new_from_message_and_address\n");
				goto out_err;
			}
		}

#if RRR_LENGTH_MAX > SSIZE_MAX
		if (node->element_count > SSIZE_MAX) {
			RRR_MSG_0("Too many elements in array field while importing to python3\n");
			goto out_err;
		}
		if ((rrr_biglength) node->total_stored_length * node->element_count > SSIZE_MAX) {
			RRR_MSG_0("Data too large in array field while importing to python3\n");
			goto out_err;
		}
#endif
		const ssize_t element_count = (ssize_t) node->element_count;

		node_list = PyList_New(element_count);
		if (node_list == NULL) {
			RRR_MSG_0("Could not create list for node in rrr_python3_rrr_message_new_from_message_and_address\n");
			goto out_err;
		}

		ssize_t element_size = (ssize_t) (node->total_stored_length / (rrr_length) element_count);
		if (node->total_stored_length != (rrr_biglength) element_size * (rrr_biglength) element_count) {
			RRR_MSG_0("Size inconsistency in array node in rrr_python3_rrr_message_new_from_message_and_address\n");
			goto out_err;
		}
		for (ssize_t i = 0; i < element_count; i++) {
			const char *data_pos = node->data + element_size * i;

			if (RRR_TYPE_IS_64(node->definition->type)) {
				if (RRR_TYPE_FLAG_IS_SIGNED(node->flags)) {
					node_element_value = PyLong_FromLongLong(*((long long *) data_pos));
				}
				else {
					node_element_value = PyLong_FromUnsignedLongLong(*((unsigned long long *) data_pos));
				}
			}
			else if (RRR_TYPE_IS_FIXP(node->definition->type)) {
				node_element_value = PyLong_FromLongLong(*((long long *) data_pos));
			}
			else if (RRR_TYPE_IS_STR(node->definition->type)) {
				node_element_value = PyUnicode_FromStringAndSize(data_pos, element_size);
			}
			else if (RRR_TYPE_IS_BLOB(node->definition->type)) {
				node_element_value = PyByteArray_FromStringAndSize(data_pos, element_size);
			}
			else if (RRR_TYPE_IS_VAIN(node->definition->type)) {
				node_element_value = Py_None;
				Py_INCREF(Py_None);
			}
			else {
				RRR_MSG_0("Unsupported data type %u in array in rrr_python3_rrr_message_new_from_message_and_address\n",
						node->definition->type);
				goto out_err;
			}

			if (node_element_value == NULL) {
				RRR_MSG_0("Could not create array node data in rrr_python3_rrr_message_new_from_message_and_address\n");
				goto out_err;
			}

			PyList_SET_ITEM(node_list, i, node_element_value);
			node_element_value = NULL;
		}

		if (rrr_python3_array_append_value_with_list(ret->rrr_array, node_tag, node_list, node->definition->type) != 0) {
			RRR_MSG_0("Could not append node value to array in rrr_python3_rrr_message_new_from_message_and_address\n");
			goto out_err;
		}

		Py_XDECREF(node_tag);
		Py_XDECREF(node_list);

		node_tag = NULL;
		node_list = NULL;
	RRR_LL_ITERATE_END();

	no_array:

	goto out;
	out_err:
		Py_XDECREF(ret);
		ret = NULL;

	out:
		Py_XDECREF(node_element_value);
		Py_XDECREF(node_list);
		Py_XDECREF(node_tag);
		rrr_array_clear(&array_tmp);
		return (PyObject *) ret;
}

PyObject *rrr_python3_rrr_message_new_from_message (
		const struct rrr_msg_msg *msg
) {
	return rrr_python3_rrr_message_new_from_message_and_address(msg, NULL);
}
