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

#ifndef RRR_CMODULE_WORKER_H
#define RRR_CMODULE_WORKER_H

#include <stdint.h>
#include <pthread.h>

#include "cmodule_defines.h"
#include "../util/linked_list.h"

struct rrr_mmap_channel;
struct rrr_instance_settings;
struct rrr_fork_handler;
struct rrr_mmap;
struct rrr_msg_msg;
struct rrr_msg_addr;

struct rrr_cmodule_worker {
	RRR_LL_NODE(struct rrr_cmodule_worker);

	rrr_setting_uint spawn_interval_us;
	rrr_setting_uint sleep_time_us;
	rrr_setting_uint nothing_happened_limit;

	int do_spawning;
	int do_processing;
	int do_drop_on_error;

	// Managed pointer
	char *name;

	pthread_mutex_t pid_lock;

	pid_t pid;
	int received_stop_signal;

	int config_complete;

	struct rrr_mmap_channel *channel_to_fork;
	struct rrr_mmap_channel *channel_to_parent;

	uint64_t total_msg_mmap_to_fork;
	uint64_t total_msg_mmap_to_parent;

	unsigned int ping_counter;

	unsigned long long int to_fork_write_retry_counter;
	unsigned long long int to_parent_write_retry_counter;

	uint64_t total_msg_processed;

	// Used by fork only
	int ping_received;
	// Used by parent reader thread only. Unprotected, only access from reader thread.
	uint64_t pong_receive_time;

	// Unmanaged pointers provided by application
	struct rrr_instance_settings *settings;
	struct rrr_fork_handler *fork_handler;
};

int rrr_cmodule_worker_send_message_and_address_to_parent (
		struct rrr_cmodule_worker *worker,
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
);
int rrr_cmodule_worker_new (
		struct rrr_cmodule_worker **result,
		const char *name,
		struct rrr_instance_settings *settings,
		struct rrr_fork_handler *fork_handler,
		struct rrr_mmap *mmap,
		rrr_setting_uint spawn_interval_us,
		rrr_setting_uint sleep_time_us,
		rrr_setting_uint nothing_happened_limit,
		int do_spawning,
		int do_processing,
		int do_drop_on_error
);
void rrr_cmodule_worker_clear_queue_to_fork (
		struct rrr_cmodule_worker *worker
);
void rrr_cmodule_worker_destroy (
		struct rrr_cmodule_worker *worker
);
void rrr_cmodule_worker_get_mmap_channel_to_fork_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
);
void rrr_cmodule_worker_get_mmap_channel_to_parent_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
);
int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback)(RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg,
		int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),
		void *custom_tick_callback_arg
);
int rrr_cmodule_worker_loop_init_wrapper_default (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
);
int rrr_cmodule_worker_main (
		struct rrr_cmodule_worker *worker,
		const char *log_prefix,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg,
		int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),
		void *custom_tick_callback_arg
);

#endif /* RRR_CMODULE_WORKER_H */
