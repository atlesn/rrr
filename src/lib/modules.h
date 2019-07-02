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

struct instance_dynamic_data;
struct instance_thread_data;
struct fifo_callback_args;
struct vl_thread_start_data;
struct rrr_instance_config;
struct vl_message;

struct module_load_data {
	void *dl_ptr;
	void (*init)(struct instance_dynamic_data *data);
	void (*unload)();
};

#define RRR_MODULE_POLL_CALLBACK_SIGNATURE \
	struct fifo_callback_args *poll_data, char *data, unsigned long int size

#define RRR_MODULE_POLL_SIGNATURE \
		struct instance_thread_data *data, \
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE), \
		struct fifo_callback_args *poll_data

#define RRR_MODULE_PRINT_SIGNATURE \
		struct instance_thread_data *data

#define RRR_MODULE_INCJECT_SIGNATURE \
		struct instance_thread_data *thread_data, \
		struct vl_message *message

// Try not to put functions with equal arguments next to each other
struct module_operations {
	void *(*thread_entry)(struct vl_thread_start_data *);

	// For modules which returns vl_message struct from buffer
	int (*poll)(RRR_MODULE_POLL_SIGNATURE);
	int (*print)(RRR_MODULE_PRINT_SIGNATURE);
	int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE);

	// For modules which return ip_buffer_entry from buffer
	int (*poll_delete_ip)(RRR_MODULE_POLL_SIGNATURE);

	// Test of configuration arguments
	int (*test_config)(struct rrr_instance_config *config);

	// Inject any packet into buffer manually (usually for testing)
	int (*inject)(RRR_MODULE_INCJECT_SIGNATURE);
};

void module_unload (void *dl_ptr, void (*unload)());
int module_load(struct module_load_data *target, const char *name);

#endif
