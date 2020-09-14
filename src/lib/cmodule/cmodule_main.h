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

#ifndef RRR_CMODULE_NATIVE_H
#define RRR_CMODULE_NATIVE_H

#define RRR_CMODULE_NATIVE_CTX
#include "../../cmodules/cmodule.h"

#include <inttypes.h>
#include <pthread.h>

#include "cmodule_defer_queue.h"
#include "cmodule_channel.h"
#include "cmodule_defines.h"

#include "../settings.h"
#include "../util/linked_list.h"

struct rrr_instance_config_data;
struct rrr_instance_settings;
struct rrr_fork_handler;
struct rrr_mmap_channel;

struct rrr_cmodule_config_data {
	rrr_setting_uint spawn_interval_us;
	rrr_setting_uint sleep_time_us;
	rrr_setting_uint nothing_happened_limit;

	int do_spawning;
	int do_processing;
	int do_drop_on_error;

	char *config_function;
	char *process_function;
	char *source_function;
	char *log_prefix;
};

struct rrr_cmodule_worker {
	RRR_LL_NODE(struct rrr_cmodule_worker);

	// Pointer managed by parent rrr_cmodule struct
	struct rrr_cmodule_config_data *config_data;

	// Managed pointer
	char *name;

	pthread_mutex_t pid_lock;

	pid_t pid;
	int received_stop_signal;

	int config_complete;

	struct rrr_cmodule_deferred_message_collection deferred_to_fork;
	struct rrr_cmodule_deferred_message_collection deferred_to_parent;

	struct rrr_mmap_channel *channel_to_fork;
	struct rrr_mmap_channel *channel_to_parent;

	uint64_t total_msg_mmap_to_fork;
	uint64_t total_msg_mmap_to_parent;

	unsigned long long int to_fork_write_retry_counter;
	unsigned long long int to_parent_write_retry_counter;

	uint64_t total_msg_processed;

	// Unmanaged pointers provided by application
	struct rrr_instance_settings *settings;
	struct rrr_fork_handler *fork_handler;
};

struct rrr_cmodule {
	RRR_LL_HEAD(struct rrr_cmodule_worker);
	struct rrr_mmap *mmap;

	struct rrr_cmodule_config_data config_data;

	// Used when creating forks and cleaning up, not managed
	struct rrr_fork_handler *fork_handler;

	// Used by message_broker_cmodule poll functions, not managed
	void *callback_data_tmp;
};

int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback)(RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
int rrr_cmodule_worker_loop_init_wrapper_default (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
);
int rrr_cmodule_worker_fork_start (
		pid_t *handle_pid,
		struct rrr_cmodule *cmodule,
		const char *name,
		struct rrr_instance_settings *settings,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
void rrr_cmodule_workers_stop (
		struct rrr_cmodule *cmodule
);
void rrr_cmodule_destroy (
		struct rrr_cmodule *cmodule
);
void rrr_cmodule_destroy_void (
		void *arg
);
int rrr_cmodule_new (
		struct rrr_cmodule **result,
		const char *name,
		struct rrr_fork_handler *fork_handler
);
// Call once in a while, like every second
void rrr_cmodule_maintain (
		struct rrr_cmodule *cmodule
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

#endif /* RRR_CMODULE_NATIVE_H */
