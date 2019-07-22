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

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <Python.h>

#include "python3_module_common.h"

struct rrr_python3_socket_data {
	PyObject_HEAD
	int socket_fd;
	char *filename;
};

static void __rrr_python3_socket_dealloc_internals (PyObject *self) {
	struct rrr_python3_socket_data *socket_data = (struct rrr_python3_socket_data *) self;

	if (socket_data->socket_fd > 0) {
		close(socket_data->socket_fd);
		socket_data->socket_fd = 0;
	}
	if (socket_data->filename != NULL) {
		unlink (socket_data->filename);
		PyMem_Free(socket_data->filename);
		socket_data->filename = NULL;
	}
}

static void rrr_python3_socket_f_dealloc (PyObject *self) {
	printf ("rrr_python3_socket_f_dealloc called\n");
	__rrr_python3_socket_dealloc_internals(self);
	PyObject_Del(self);
}

static int rrr_python3_socket_f_init (PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_socket_data *socket_data = (struct rrr_python3_socket_data *) self;
	int ret = 0;

	char *arg_filename = "";
	char *valid_keys[] = {"filename", NULL};

	printf ("rrr_python3_socket_f_init called\n");

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s", valid_keys, &arg_filename)) {
		VL_MSG_ERR("Could not parse arguments to socket __init__ python3 module: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	char *filename = NULL;
	if (*arg_filename != '\0') {
		int fd = open(arg_filename, O_CREAT, S_IRUSR|S_IWUSR);
		if (fd == -1) {
			VL_MSG_ERR("Could not open specified socket file %s: %s\n", arg_filename, strerror(errno));
			ret = 1;
			goto out;
		}
		close (fd);
		if (unlink (arg_filename) != 0) {
			VL_MSG_ERR("Could not unlink file to be used for socket in python3 socket __init__ (%s): %s\n", arg_filename, strerror(errno));
			ret = 1;
			goto out;
		}

		filename = arg_filename;
	}
	else {
		socket_data->socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
		if (socket_data->socket_fd == -1) {
			VL_MSG_ERR("Could not create UNIX socket in python3 module socket __init__: %s\n", strerror(errno));
			ret = 1;
			goto out;
		}

		char filename_template[128];
		sprintf(filename_template, RRR_TMP_PATH "/rrr-py-socket-XXXXXX");

		filename = filename_template;

		int fd = mkstemp (filename);
		if (fd == -1) {
			VL_MSG_ERR("Could not create temporary filename for UNIX socket in python3 module in socket __init_: %s\n", strerror(errno));
			ret = 1;
			goto out;
		}
		close(fd);

		if (unlink (filename) != 0) {
			VL_MSG_ERR("Could not unlink file to be used for socket in python3 socket __init__ (%s): %s\n", arg_filename, strerror(errno));
			ret = 1;
			goto out;
		}
	}

	socket_data->filename = PyMem_Malloc(strlen(filename)+1);
	strcpy(socket_data->filename, filename);

	struct sockaddr_un addr;
	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_data->filename, sizeof(addr.sun_path)-1);
	if (bind(socket_data->socket_fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		VL_MSG_ERR("Could bind to socket %s in python3 module in socket __init_: %s\n", socket_data->filename, strerror(errno));
		ret = 1;
		goto out;
	}

	printf ("Filename is %s\n", socket_data->filename);

	out:
	if (ret != 0) {
		__rrr_python3_socket_dealloc_internals(self);
	}
	return ret;
}

static PyObject *rrr_python3_socket_f_get_filename(PyObject *self, PyObject *args) {
	struct rrr_python3_socket_data *socket_data = (struct rrr_python3_socket_data *) self;

	(void)(args);

	if (socket_data->filename == NULL) {
		VL_MSG_ERR("Could not get filename as socket is not initialized in python3 module\n");
		return NULL;
	}
	return (PyUnicode_FromString(socket_data->filename));
}

const char *rrr_python3_socket_get_filename(PyObject *self) {
	struct rrr_python3_socket_data *socket_data = (struct rrr_python3_socket_data *) self;
	if (socket_data->filename == NULL) {
		VL_BUG("rrr_python3_socket_get_filename called with filename being NULL, socket it probably not initialized\n");
	}
	return socket_data->filename;
}

static PyMethodDef socket_methods[] = {
		{
				ml_name:	"get_filename",
				ml_meth:	(PyCFunction) rrr_python3_socket_f_get_filename,
				ml_flags:	METH_NOARGS,
				ml_doc:		"Tests that basics for socket works"
		},
		{ NULL, NULL, 0, NULL }
};

PyTypeObject rrr_python3_socket_type = {
		ob_base:			PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    tp_name:			RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_SOCKET_TYPE_NAME,
	    tp_basicsize:		sizeof(struct rrr_python3_socket_data),
		tp_itemsize:		0,
	    tp_dealloc:			(destructor) rrr_python3_socket_f_dealloc,
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
	    tp_doc:				"ReadRouteRecord type for UNIX socket IPC",
	    tp_traverse:		NULL,
	    tp_clear:			NULL,
	    tp_richcompare:		NULL,
	    tp_weaklistoffset:	0,
	    tp_iter:			NULL,
	    tp_iternext:		NULL,
	    tp_methods:			socket_methods,
	    tp_members:			NULL,
	    tp_getset:			NULL,
	    tp_base:			NULL,
	    tp_dict:			NULL,
	    tp_descr_get:		NULL,
	    tp_descr_set:		NULL,
	    tp_dictoffset:		0,
	    tp_init:			rrr_python3_socket_f_init,
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

/*
static PyObject *rrr_python3_socket_f_test (PyObject *self, PyObject *args, PyObject *kwds) {
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

	printf ("rrr_python3_f_test called: arg1: %i, arg2: %s\n", arg1, arg2);

	out:
	Py_INCREF(ret); // <-- Yes, INC is correct
	return ret;
}
*/
