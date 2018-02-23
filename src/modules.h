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
#include <string.h>
#include <error.h>

#define VL_MODULE_TYPE_SOURCE 1
#define VL_MODULE_TYPE_DESTINATION 2
#define VL_MODULE_TYPE_PROCESSOR 3

//#define VL_MODULE_NO_DL_CLOSE

// TODO : Create processor modules

struct module_dynamic_data *_module_data;
struct reading *_reading;
struct output *_output;

struct module_operations {
	void (*module_destroy)(struct module_dynamic_data *data);
	void *(*thread_entry)(void*);

	/* Used by source modules */
	int (*poll)(struct module_dynamic_data *module_data, void (*callback)(void*));

	/* Used by output modules */
	int (*print)(struct module_dynamic_data *module_data, struct output *output);

	/* Used by processor and output modules */
	void (*set_sender)(struct module_dynamic_data *data, struct module_dynamic_data *sender);
};

struct module_dynamic_data {
	const char *name;
	unsigned int type;
	struct module_operations operations;
	void *dl_ptr;
	void *private_data;
};

//struct module_data *get_module(const char *name, unsigned int type);
struct module_dynamic_data *load_module(const char *name);
void unload_module(struct module_dynamic_data *data);

#endif
