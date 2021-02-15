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

// Put first to avoid problems with other files including sys/time.h
#include "../util/rrr_time.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "python3_common.h"
#include "python3_module.h"
#include "python3_module_common.h"
#include "python3_socket.h"
#include "python3_message.h"

#include "../log.h"
#include "../settings.h"
#include "../read.h"
#include "../socket/rrr_socket.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../cmodule/cmodule_ext.h"
#include "../util/posix.h"

struct rrr_python3_socket_data {
	PyObject_HEAD
	struct rrr_cmodule_worker *worker;
	uint64_t time_start;
	// Protects sending in case we have threads in the pythond program
	pthread_mutex_t send_lock;
};

static void __rrr_python3_socket_dealloc_internals (PyObject *self) {
	struct rrr_python3_socket_data *socket_data = (struct rrr_python3_socket_data *) self;

	socket_data->worker = NULL;
}

static void rrr_python3_socket_f_dealloc (PyObject *self) {
	__rrr_python3_socket_dealloc_internals(self);
	PyObject_Del(self);
}

static PyObject *rrr_python3_socket_f_new (PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyObject *self = PyType_GenericNew(type, args, kwds);
	if (self == NULL) {
		return NULL;
	}

	return self;
}

static int rrr_python3_socket_f_init (PyObject *self, PyObject *args, PyObject *kwds) {
	__rrr_python3_socket_dealloc_internals(self);
	(void)(args);
	(void)(kwds);
	return 0;
}

static PyObject *rrr_python3_socket_f_send (PyObject *self, PyObject *arg) {
	int ret = 0;

	struct rrr_msg_addr message_addr = {0};
	const struct rrr_msg_msg *message_orig = NULL;
	struct rrr_msg_msg *message = NULL;

	if (!rrr_python3_rrr_message_check(arg)) {
		RRR_MSG_0("Received unknown object type in python3 socket send\n");
		ret = 1;
		goto out;
	}

	message_orig = rrr_python3_rrr_message_get_message (&message_addr, arg);

	message = rrr_msg_msg_duplicate(message_orig);
	if (message == NULL) {
		RRR_MSG_0("Could not duplicate message in rrr_python3_socket_f_send\n");
		ret = 1;
		goto out;
	}


	rrr_msg_addr_init_head(&message_addr, RRR_MSG_ADDR_GET_ADDR_LEN(&message_addr));

	// socket_send always handles memory of message
	if ((ret = rrr_python3_socket_send(self, message, &message_addr)) != 0) {
		RRR_MSG_0("Received error in python3 socket send function\n");
		ret = 1;
		goto out;
	}

	out:
	if (ret != 0) {
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE;
}

static PyMethodDef socket_methods[] = {
		{
				.ml_name	= "send",
				.ml_meth	= (PyCFunction) rrr_python3_socket_f_send,
				.ml_flags	= METH_O,
				.ml_doc		= "Send an rrr_msg_msg object on the socket"
		},
		{ NULL, NULL, 0, NULL }
};

PyTypeObject rrr_python3_socket_type = {
		.ob_base		= PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    .tp_name		= RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_SOCKET_TYPE_NAME,
	    .tp_basicsize	= sizeof(struct rrr_python3_socket_data),
		.tp_itemsize	= 0,
	    .tp_dealloc		= (destructor) rrr_python3_socket_f_dealloc,
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
	    .tp_doc			= "ReadRouteRecord type for MMAP channel IPC",
	    .tp_traverse	= NULL,
	    .tp_clear		= NULL,
	    .tp_richcompare	= NULL,
	    .tp_weaklistoffset	= 0,
	    .tp_iter		= NULL,
	    .tp_iternext	= NULL,
	    .tp_methods		= socket_methods,
	    .tp_members		= NULL,
	    .tp_getset		= NULL,
	    .tp_base		= NULL,
	    .tp_dict		= NULL,
	    .tp_descr_get	= NULL,
	    .tp_descr_set	= NULL,
	    .tp_dictoffset	= 0,
	    .tp_init		= rrr_python3_socket_f_init,
	    .tp_alloc		= PyType_GenericAlloc,
	    .tp_new			= rrr_python3_socket_f_new,
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

PyObject *rrr_python3_socket_new (struct rrr_cmodule_worker *worker) {
	struct rrr_python3_socket_data *new_socket = NULL;

	new_socket = PyObject_New(struct rrr_python3_socket_data, &rrr_python3_socket_type);
	if (new_socket == NULL) {
		RRR_MSG_0("Could not create new socket in rrr_python3_socket_new:\n");
		PyErr_Print();
		goto out;
	}

	new_socket->worker = worker;

	if (rrr_posix_mutex_init(&new_socket->send_lock, 0) != 0) {
		RRR_MSG_0("Could not initialize lock in rrr_python3_socket_new\n");
		goto out_free;
	}

	new_socket->time_start = rrr_time_get_64();

	goto out;
	out_free:
		RRR_Py_XDECREF((PyObject *) new_socket);
		new_socket = NULL;
	out:
		return (PyObject *) new_socket;
}

int rrr_python3_socket_send (
		PyObject *socket,
		struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
) {
	struct rrr_python3_socket_data *socket_data = (struct rrr_python3_socket_data *) socket;
	int ret = 0;

	RRR_DBG_3 ("python3 socket send from application in pid %i size %u\n",
			getpid(), message->msg_size
	);

	if (message->msg_size < sizeof(struct rrr_msg)) {
		RRR_BUG("Received a socket message of wrong size in rrr_python3_socket_send (it says %u bytes)\n", message->msg_size);
	}

	pthread_mutex_lock(&socket_data->send_lock);

	if ((ret = rrr_cmodule_ext_send_message_to_parent (
			socket_data->worker,
			message,
			message_addr
	)) != 0) {
		RRR_MSG_0("Could not send address message on memory map channel in python3.\n");
		ret = 1;
	}

	pthread_mutex_unlock(&socket_data->send_lock);
	free(message);
	return ret;
}
