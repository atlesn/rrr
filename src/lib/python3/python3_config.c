/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <string.h>

#include "python3_common.h"
#include "python3_module_common.h"
#include "python3_config.h"
#include "../log.h"
#include "../settings.h"

struct rrr_python3_config_data {
	PyObject_HEAD
	struct rrr_instance_settings *settings;
};

static PyObject *rrr_python3_config_f_new (PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyObject *self = PyType_GenericNew(type, args, kwds);
	if (self == NULL) {
		return NULL;
	}

	struct rrr_python3_config_data *data = (struct rrr_python3_config_data *) self;

	data->settings = NULL;

	return self;
}

// TODO : Check that args/kwds are empty
static int rrr_python3_config_f_init(PyObject *self, PyObject *args, PyObject *kwds) {
	struct rrr_python3_config_data *data = (struct rrr_python3_config_data *) self;
	(void)(args);
	(void)(kwds);
	data->settings = NULL;
	return 0;
}

static void rrr_python3_config_f_dealloc (PyObject *self) {
	PyObject_Del(self);
}

static PyObject *__rrr_python3_config_set (PyObject *self, PyObject * const *argv, Py_ssize_t argc, int do_replace) {
	struct rrr_python3_config_data *data = (struct rrr_python3_config_data *) self;

	if (data->settings == NULL) {
		RRR_MSG_0("Configuration class not properly initialized. This class can only be created by RRR internally.\n");
		Py_RETURN_FALSE;
	}

	if (argc != 2) {
		RRR_MSG_0("Wrong number of arguments (%li) to config add or replace function, exactly 2 is required\n", argc);
		Py_RETURN_FALSE;
	}

	PyObject *name = argv[0];
	PyObject *value = argv[1];

	if (!PyUnicode_Check(name)) {
		RRR_MSG_0("Unknown type in first parameter to to config add or replace function, expected a string (or convertible to string)\n");
		Py_RETURN_FALSE;
	}

	if (!PyUnicode_Check(value)) {
		RRR_MSG_0("Unknown type in second parameter to to config add or replace function, expected a string (or convertible to string)\n");
		Py_RETURN_FALSE;
	}

	const char *str_name = PyUnicode_AsUTF8(name);
	const char *str_value = PyUnicode_AsUTF8(value);

	int ret_tmp;

	if (do_replace) {
		ret_tmp = rrr_settings_replace_string(data->settings, str_name, str_value);
	}
	else {
		ret_tmp = rrr_settings_add_string(data->settings, str_name, str_value);
	}

	if (ret_tmp != 0) {
		RRR_MSG_0("Error while writing to settings in config class\n");
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

PyObject *rrr_python3_config_f_add (PyObject *self, PyObject * const *argv, Py_ssize_t argc) {
	return __rrr_python3_config_set(self, argv, argc, 0);
}

PyObject *rrr_python3_config_f_replace (PyObject *self, PyObject * const *argv, Py_ssize_t argc) {
	return __rrr_python3_config_set(self, argv, argc, 1);
}

PyObject *rrr_python3_config_f_get (PyObject *self, PyObject *name) {
	struct rrr_python3_config_data *data = (struct rrr_python3_config_data *) self;
	PyObject *result = NULL;
	char *string_value_tmp = NULL;

	if (!PyUnicode_Check(name)) {
		RRR_MSG_0("Unknown type in parameter to to config get function, expected a string (or convertible to string)\n");
		goto out_return_none;
	}

	const char *string_name = PyUnicode_AsUTF8(name);

	int ret_tmp = 0;
	if ((ret_tmp = rrr_settings_get_string_noconvert_silent(&string_value_tmp, data->settings, string_name)) != 0) {
		if (ret_tmp == RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Setting '%s' could not be found in get function of config class, check spelling.\n", string_name);
		}
		else {
			RRR_MSG_0("Error while getting setting '%s' in get function of config class.\n", string_name);
		}
		goto out_return_none;
	}

	result = PyUnicode_FromString(string_value_tmp);
	goto out;

	out_return_none:
		Py_INCREF(Py_None);
		result = Py_None;

	out:
		RRR_FREE_IF_NOT_NULL(string_value_tmp);
		return result;
}

static PyMethodDef setting_methods[] = {
		{
				.ml_name	= "add",
				.ml_meth	= (void *) rrr_python3_config_f_add,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Add value"
		},
		{
				.ml_name	= "replace",
				.ml_meth	= (void *) rrr_python3_config_f_replace,
				.ml_flags	= METH_FASTCALL,
				.ml_doc		= "Replace value"
		},
		{
				.ml_name	= "get",
				.ml_meth	= (void *) rrr_python3_config_f_get,
				.ml_flags	= METH_O,
				.ml_doc		= "Get value"
		},
		{ NULL, NULL, 0, NULL }
};

PyGetSetDef getsets[] = {
		{NULL, NULL, NULL, NULL, NULL}
};

PyTypeObject rrr_python3_config_type = {
		.ob_base		= PyVarObject_HEAD_INIT(NULL, 0) // Comma is inside macro
	    .tp_name		= RRR_PYTHON3_MODULE_NAME	"." RRR_PYTHON3_CONFIG_TYPE_NAME,
	    .tp_basicsize	= sizeof(struct rrr_python3_config_data),
		.tp_itemsize	= 0,
	    .tp_dealloc		= (destructor) rrr_python3_config_f_dealloc,
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
	    .tp_doc			= "Type for RRR Config structure",
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
	    .tp_init		= rrr_python3_config_f_init,
	    .tp_alloc		= PyType_GenericAlloc,
	    .tp_new			= rrr_python3_config_f_new,
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

PyObject *rrr_python3_config_new (struct rrr_instance_settings *settings) {
	struct rrr_python3_config_data *new_config = NULL;

	new_config = PyObject_New(struct rrr_python3_config_data, &rrr_python3_config_type);
	if (new_config) {
		new_config->settings = settings;
	}

	return (PyObject *) new_config;
}

