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
#include <semaphore.h>
#include <string.h>
#include <error.h>

#define VL_MODULE_TYPE_SOURCE 1
#define VL_MODULE_TYPE_DESTINATION 2
#define VL_MODULE_TYPE_PROCESSOR 3

#define VL_MODULE_NO_DL_CLOSE

#define VL_MODULE_STATE_NEW 1
#define VL_MODULE_STATE_UP 2
#define VL_MODULE_STATE_INVALID 3

// TODO : Create processor modules

struct module_data *_module_data;
struct reading *_reading;
struct output *_output;

struct module_operations {
	int (*module_init)(struct module_data *data);
	int (*module_destroy)(struct module_data *data);
	int (*module_do_work)(struct module_data *data);

	/* Used by source modules */
	int (*poll)(struct module_data *module_data, struct reading *reading);

	/* Used by output modules */
	int (*print)(struct module_data *module_data, struct output *output);

	/* Used by processor modules */
	int (*set_receiver)(struct module_data *data, struct module_data *receiver);
	int (*set_sender)(struct module_data *data, struct module_data *sender);
};


struct module_data {
	const char *name;
	const unsigned int type;
	int state;
	void *dl_ptr;
	const struct module_operations *operations;
	struct module_data *next;
	sem_t users;
	void *private;
};

static inline int take_module(struct module_data *module) {
	return sem_post(&module->users);
}

static inline int give_module(struct module_data *module) {
	return sem_trywait(&module->users);
}

static inline int wait_module(struct module_data *module) {
	return sem_wait(&module->users);
}

int count_module_users(struct module_data *module, int *result);

struct module_data *get_module(const char *name, unsigned int type);
int load_module(const char *name);
int hard_unload_modules();

#endif
