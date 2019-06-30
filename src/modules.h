/*

Voltage Logger

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#define VL_MODULE_PRIVATE_MEMORY_SIZE 8196

#define VL_MODULE_TYPE_SOURCE 1
#define VL_MODULE_TYPE_PROCESSOR 3

/*#define VL_POLL_RESULT_ERR -1
#define VL_POLL_RESULT_OK 1
#define VL_POLL_EMPTY_RESULT_OK 0*/

#define VL_MODULE_MAX_SENDERS 8

//#define VL_MODULE_NO_DL_CLOSE

struct module_dynamic_data;
struct module_thread_data;
struct fifo_callback_args;
struct vl_thread_start_data;

struct module_load_data {
	void *dl_ptr;
	void (*init)(struct module_dynamic_data *data);
	void (*unload)();
};

// Try not to put functions with equal arguments next to each other
struct module_operations {
	void *(*thread_entry)(struct vl_thread_start_data *);

	// For modules which returns vl_message struct from buffer
	int (*poll)(struct module_thread_data *data, int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size), struct fifo_callback_args *poll_data);
	int (*print)(struct module_thread_data *data);
	int (*poll_delete)(struct module_thread_data *data, int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size), struct fifo_callback_args *poll_data);

	// For modules which return ip_buffer_entry from buffer
	int (*poll_delete_ip)(struct module_thread_data *data, int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size), struct fifo_callback_args *poll_data);
};

void module_unload (void *dl_ptr, void (*unload)());
int module_load(struct module_load_data *target, const char *name);

#endif
