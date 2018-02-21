/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#ifndef VL_MODULES_H
#define VL_MODULES_H

#include <stdlib.h>

#define VL_MODULE_TYPE_SOURCE 1
#define VL_MODULE_TYPE_DESTINATION 2
#define VL_MODULE_TYPE_PROCESSOR 3

// TODO : Create processor modules

struct module_data *_module_data;
struct reading *_reading;
struct output *_output;

struct module_operations {
	int (*module_init)(struct module_data *data);
	int (*module_destroy)(struct module_data *data);
	int (*poll)(struct module_data *module_data, struct reading *reading);
	int (*print)(struct module_data *module_data, struct output *output);
};

struct module_data {
	const char *name;
	const unsigned int type;
	void *dl_ptr;
	const struct module_operations *operations;
	struct module_data *next;
};

struct module_data *get_module(const char *name, unsigned int type);
int load_module(const char *name);
int unload_modules();

#endif
