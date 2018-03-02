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

#include "lib/threads.h"

#define VL_MODULE_PRIVATE_MEMORY_SIZE 1024

#define VL_MODULE_TYPE_SOURCE 1
#define VL_MODULE_TYPE_PROCESSOR 3

#define VL_POLL_RESULT_ERR -1
#define VL_POLL_RESULT_OK 1
#define VL_POLL_EMPTY_RESULT_OK 0

#define VL_MODULE_MAX_SENDERS 8

//#define VL_MODULE_NO_DL_CLOSE

struct module_dynamic_data;
struct reading;

struct vl_thread_start_data;
struct module_thread_data;
struct fifo_callback_args;

// Try not to put functions with equal arguments next to each other
struct module_operations {
	void *(*thread_entry)(struct vl_thread_start_data *);
	int (*poll)(struct module_thread_data *data, void (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size), struct fifo_callback_args *poll_data);
	int (*print)(struct module_thread_data *data);
	int (*poll_delete)(struct module_thread_data *data, void (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size), struct fifo_callback_args *poll_data);
};

struct module_dynamic_data {
	const char *name;
	unsigned int type;
	struct module_operations operations;
	void *dl_ptr;
	void *private_data;
	void (*unload)(struct module_dynamic_data *data);
};

struct module_thread_data {
	struct vl_thread *thread;
	struct module_thread_data *senders[VL_MODULE_MAX_SENDERS];
	unsigned long int senders_count;
	struct module_dynamic_data *module;
	void *private_data;
	char private_memory[VL_MODULE_PRIVATE_MEMORY_SIZE];
};

struct module_thread_init_data {
	struct module_dynamic_data *module;
	struct module_metadata *senders[VL_MODULE_MAX_SENDERS];
	unsigned long int senders_count;
};

struct module_metadata {
	struct module_dynamic_data *module;
	struct module_thread_data *thread_data;
	struct module_metadata *senders[VL_MODULE_MAX_SENDERS];
	unsigned long int senders_count;
};

void module_threads_init();
void module_threads_stop();
void module_threads_destroy();
void module_free_thread(struct module_thread_data *module);
struct module_thread_data *module_start_thread(struct module_thread_init_data *init_data, struct cmd_data *cmd);
struct module_dynamic_data *load_module(const char *name);
void unload_module(struct module_dynamic_data *data);

#endif
