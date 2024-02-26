/*
Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

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
	
#include "../event/event.h"
#include "../message_holder/message_holder_collection.h"
#include "../settings.h"

#include "cmodule_config_data.h"
#include "cmodule_defines.h"

struct rrr_mmap_channel;
struct rrr_fork_handler;
struct rrr_discern_stack_collection;
struct rrr_msg_msg;
struct rrr_msg_addr;

struct rrr_cmodule_worker {
	uint8_t index;

	rrr_time_us_t spawn_interval;

	enum rrr_cmodule_process_mode process_mode;
	int do_spawning;
	int do_drop_on_error;

	// Managed structures
	char *name;

	pthread_mutex_t pid_lock;

	pid_t pid;
	volatile int received_stop_signal;
	volatile int received_sigusr2_signal;

	int config_complete;

	struct rrr_mmap_channel *channel_to_fork;
	struct rrr_mmap_channel *channel_to_parent;

	uint64_t total_msg_mmap_to_fork;
	uint64_t total_msg_mmap_to_parent;

	unsigned int ping_counter;

	unsigned long long int to_fork_write_retry_counter;
	unsigned long long int to_parent_write_retry_counter;

	uint64_t total_msg_processed;

	struct rrr_settings *settings;
	struct rrr_settings_used settings_used;

	// Used by fork only
	int ping_received;
	// Used by parent reader thread only. Unprotected, only access from reader thread.
	rrr_time_us_t pong_receive_time;

	// Unmanaged pointers provided by application
	struct rrr_fork_handler *fork_handler;
	struct rrr_event_queue *event_queue_parent;
	const struct rrr_discern_stack_collection *methods;

	// Both worker and parent destroy this. It is allocated before forking but
	// the worker also calls destroy to clean up memory for events it created after forking
	struct rrr_event_queue *event_queue_worker;

	// Created after forking if app periodic function is used
	rrr_event_handle app_periodic_event;
};

struct rrr_cmodule {
	char *name;

	struct rrr_cmodule_config_data config_data;

	int config_check_complete;
	int config_check_complete_message_printed;

	struct rrr_msg_holder_collection input_queue;

	// Created just before event dispatch, not managed
	rrr_event_handle input_queue_event;

	// Create just before event dispatch in case app periodic
	// callback is used.
	rrr_event_handle app_periodic_event;

	// Used when creating forks and cleaning up, not managed
	struct rrr_fork_handler *fork_handler;

	uint8_t worker_count;
	struct rrr_cmodule_worker workers[RRR_CMODULE_WORKER_MAX_WORKER_COUNT];
};

#endif /* RRR_CMODULE_STRUCT_H */
