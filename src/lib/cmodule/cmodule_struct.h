/*
Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_CMODULE_STRUCT_H
#define RRR_CMODULE_STRUCT_H
	
#include "cmodule_config_data.h"
#include "../message_holder/message_holder_collection.h"

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
	struct rrr_event_queue *notify_queue;
};

struct rrr_cmodule {
	RRR_LL_HEAD(struct rrr_cmodule_worker);
	struct rrr_mmap *mmap;

	struct rrr_cmodule_config_data config_data;

	int config_check_complete;
	int config_check_complete_message_printed;

	// Used when creating forks and cleaning up, not managed
	struct rrr_fork_handler *fork_handler;

//	struct rrr_msg_holder_collection queue_to_forks;
};

#endif /* RRR_CMODULE_STRUCT_H */
