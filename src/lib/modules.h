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

struct rrr_instance_module_data;
struct rrr_instance_runtime_data;
struct rrr_instance_config_data;
struct rrr_msg_holder;
struct rrr_thread;

struct rrr_module_load_data {
	void *dl_ptr;
	void (*init)(struct rrr_instance_module_data *data);
	void (*unload)(void);
};

#define RRR_MODULE_POLL_CALLBACK_SIGNATURE                     \
    struct rrr_msg_holder *entry,                              \
    void *arg

#define RRR_MODULE_INJECT_SIGNATURE                            \
    struct rrr_instance_runtime_data *thread_data,             \
    struct rrr_msg_holder *message

// Try not to put functions with equal arguments next to each other
struct rrr_module_operations {
	// Preload function - Run before thread is started in main thread context
	int (*preload)(struct rrr_thread *);

	// Main function with a loop to run the thread
	void *(*thread_entry)(struct rrr_thread *);

	// Inject any packet into buffer manually (usually for testing)
	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);

	// Custom cancellation method (if we are hung and main wants to cancel us)
	int (*cancel_function)(struct rrr_thread *);
};

void rrr_module_unload (
		void *dl_ptr,
		void (*unload)(void)
);
int rrr_module_load (
		struct rrr_module_load_data *target,
		const char *name,
		const char **library_paths
);

#endif
