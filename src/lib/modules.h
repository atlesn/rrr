/*

Read Route Record

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

#ifndef RRR_MODULES_H
#define RRR_MODULES_H

#define RRR_MODULE_PRIVATE_MEMORY_SIZE 8196
#define RRR_MODULE_PRELOAD_MEMORY_SIZE 64

#define RRR_MODULE_TYPE_SOURCE 1
#define RRR_MODULE_TYPE_PROCESSOR 3
#define RRR_MODULE_TYPE_FLEXIBLE 4
#define RRR_MODULE_TYPE_DEADEND 5
#define RRR_MODULE_TYPE_NETWORK 6

#define RRR_MODULE_MAX_SENDERS 8

//#define RRR_MODULE_NO_DL_CLOSE

struct rrr_instance_dynamic_data;
struct rrr_instance_thread_data;
struct rrr_fifo_callback_args;
struct rrr_thread_start_data;
struct rrr_instance_config;
struct rrr_message;
struct rrr_ip_buffer_entry;
struct rrr_thread;

struct rrr_module_load_data {
	void *dl_ptr;
	void (*init)(struct rrr_instance_dynamic_data *data);
	void (*unload)(void);
};

#define RRR_MODULE_POLL_CALLBACK_SIGNATURE \
	struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size

#define RRR_MODULE_POLL_SIGNATURE \
		struct rrr_instance_thread_data *data, \
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE), \
		struct rrr_fifo_callback_args *poll_data, \
		unsigned int wait_milliseconds

#define RRR_MODULE_PRINT_SIGNATURE \
		struct rrr_instance_thread_data *data

#define RRR_MODULE_INJECT_SIGNATURE \
		struct rrr_instance_thread_data *thread_data, \
		struct rrr_ip_buffer_entry *message

// Try not to put functions with equal arguments next to each other
struct rrr_module_operations {
	// Preload function - Run before thread is started in main thread context
	int (*preload)(struct rrr_thread *);

	// Main function with a loop to run the thread
	void *(*thread_entry)(struct rrr_thread *);

	// Post stop function - Run after thread has finished from main thread context
	void (*poststop)(const struct rrr_thread *);

	// For modules which returns rrr_message struct from buffer
	int (*poll)(RRR_MODULE_POLL_SIGNATURE);
	int (*print)(RRR_MODULE_PRINT_SIGNATURE);
	int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE);

	// For modules which return rrr_ip_buffer_entry from buffer
	int (*poll_delete_ip)(RRR_MODULE_POLL_SIGNATURE);

	// Test of configuration arguments
	int (*test_config)(struct rrr_instance_config *config);

	// Inject any packet into buffer manually (usually for testing)
	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);

	// Custom cancellation method (if we are hung and main wants to cancel us)
	int (*cancel_function)(struct rrr_thread *);
};

void rrr_module_unload (void *dl_ptr, void (*unload)(void));
int rrr_module_load(struct rrr_module_load_data *target, const char *name, const char **library_paths);

#endif
