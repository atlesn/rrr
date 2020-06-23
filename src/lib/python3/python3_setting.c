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

#include <string.h>

#include <Python.h>
#include <structmember.h>

#include "python3_common.h"
#include "python3_module_common.h"
#include "python3_setting.h"
#include "../log.h"
#include "../settings.h"

struct rrr_python3_setting_data {
	PyObject_HEAD
	struct rrr_setting_packed setting;
};

static PyObject *rrr_python3_setting_f_new (PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyObject *self = PyType_GenericNew(type, args, kwds);
	if (self == NULL) {
		return NULL;
	}

	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;

	memset (&data->setting, '\0', sizeof(data->setting));

	return self;
}

// TODO : Check that args/kwds are empty
static int rrr_python3_setting_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;
	(void)(args);
	(void)(kwds);
	memset (&data->setting, '\0', sizeof(data->setting));
	return 0;
}

static void rrr_python3_setting_f_dealloc (PyObject *self) {
	PyObject_Del(self);
}

PyObject *rrr_python3_setting_f_set (PyObject *self, PyObject *arg) {
	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;

	if (!PyUnicode_Check(arg)) {
		RRR_MSG_0("Expected unicode/string argument in rrr_setting.set()\n");
		Py_RETURN_FALSE;
	}

	data->setting.type = RRR_SETTINGS_TYPE_STRING;
	const char *str = PyUnicode_AsUTF8(arg);
	int len = strlen (str);
	if (len > RRR_SETTINGS_MAX_DATA_SIZE - 1) {
		RRR_MSG_0("Length of string in rrr_setting.set() was too long, max is %i\n", RRR_SETTINGS_MAX_DATA_SIZE - 1);
		Py_RETURN_FALSE;
	}

	strcpy(data->setting.data, str);
	data->setting.data_size = len + 1;

	Py_RETURN_TRUE;
}

PyObject *rrr_python3_setting_f_get (PyObject *self, PyObject *dummy) {
	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;

	(void)(dummy);

	if (RRR_SETTING_IS_STRING(&data->setting)) {
		data->setting.was_used = 1;
		return PyUnicode_FromString(data->setting.data);
	}
	else if (RRR_SETTING_IS_UINT(&data->setting)) {
		RRR_BUG("Unsigned integer setting not implemented\n");
	}
	else {
		RRR_BUG("Unknown setting type %u in rrr_python3_setting_f_get\n", data->setting.type);
	}

	Py_RETURN_NONE;
}

PyObject *rrr_python3_setting_f_get_name (PyObject *self, void *closure) {
	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;

	(void)(closure);

	if (*(data->setting.name) == '\0') {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(data->setting.name);
}

static PyMethodDef setting_methods[] = {
		{
				.ml_name	= "set",
				.ml_meth	= (PyCFunction) rrr_python3_setting_f_set,
				.ml_flags	= METH_O,
				.ml_doc		= "Set value"
		},
		{
				.ml_name	= "get",
				.ml_meth	= (PyCFunction) rrr_python3_setting_f_get,
				.ml_flags	= METH_NOARGS,
				.ml_doc		= "Get value"
		},
		{ NULL, NULL, 0, NULL }
};
/*
struct rrr_python3_setting_data dummy = {0};
static PyMemberDef setting_members[] = {
		{
				"name",
				T_STRING,
				(void*)dummy.setting.name - (void*)&dummy,
				READONLY,
				"Name of the setting"
		},
		{ NULL, 0, 0, 0, NULL}
};
*/

PyGetSetDef getsets[] = {
		{
				"name",
				(getter) rrr_python3_setting_f_get_name,
				NULL, // (setter) rrr_python3_setting_f_set_name,
				"Get the name of the setting",
				NULL
		},
		{NULL, NULL, NULL, NULL, NULL}
};

PyTypeObject rrr_python3_setting_type = {
		.ob_base		= PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    .tp_name		= RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_SETTING_TYPE_NAME,
	    .tp_basicsize	= sizeof(struct rrr_python3_setting_data),
		.tp_itemsize	= 0,
	    .tp_dealloc		= (destructor) rrr_python3_setting_f_dealloc,
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
	    .tp_methods		= setting_methods,
	    .tp_members		= NULL,
	    .tp_getset		= getsets,
	    .tp_base		= NULL,
	    .tp_dict		= NULL,
	    .tp_descr_get	= NULL,
	    .tp_descr_set	= NULL,
	    .tp_dictoffset	= 0,
	    .tp_init		= rrr_python3_setting_f_init,
	    .tp_alloc		= PyType_GenericAlloc,
	    .tp_new			= rrr_python3_setting_f_new,
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

struct rrr_setting_packed *rrr_python3_setting_get_setting (PyObject *self) {
	struct rrr_python3_setting_data *data = (struct rrr_python3_setting_data *) self;
	return &data->setting;
}

PyObject *rrr_python3_setting_new_from_setting (const struct rrr_socket_msg *msg) {
	struct rrr_python3_setting_data *new_setting = NULL;

	int ret = 0;

	if (!RRR_SOCKET_MSG_IS_SETTING(msg)) {
		RRR_BUG("Non-setting socket message given to rrr_python3_setting_new_from_setting\n");
	}

	if (msg->msg_size > sizeof(new_setting->setting)) {
		RRR_BUG("Received object of wrong size in rrr_python3_setting_new_from_setting\n");
	}

	new_setting = PyObject_New(struct rrr_python3_setting_data, &rrr_python3_setting_type);
	if (new_setting) {
		memcpy(&new_setting->setting, msg, sizeof(new_setting->setting));
	}

	if (rrr_settings_packed_validate(&new_setting->setting)) {
		RRR_MSG_0("Received an invalid setting in rrr_python3_setting_new_from_setting\n");
		ret = 1;
		goto out;
	}

	out:
	if (ret != 0) {
		RRR_Py_XDECREF((PyObject *) new_setting);
		new_setting = NULL;
	}

	return (PyObject *) new_setting;
}
