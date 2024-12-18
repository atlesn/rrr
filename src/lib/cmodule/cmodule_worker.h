/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

struct rrr_cmodule;
struct rrr_cmodule_worker;
struct rrr_mmap_channel;
struct rrr_settings;
struct rrr_fork_handler;
struct rrr_mmap;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_event_queue;
struct rrr_discern_stack_collection;

struct rrr_cmodule_worker_callbacks {
	int (*ping_callback)(RRR_CMODULE_PING_CALLBACK_ARGS);
	void *ping_callback_arg;
	int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS);
	void *configuration_callback_arg;
	int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS);
	void *process_callback_arg;
	int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS);
	void *custom_tick_callback_arg;
	int (*periodic_callback)(RRR_CMODULE_PERIODIC_CALLBACK_ARGS);
	void *periodic_callback_arg;
};

int rrr_cmodule_worker_send_message_and_address_to_parent (
		struct rrr_cmodule_worker *worker,
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
);
void rrr_cmodule_worker_get_mmap_channel_to_fork_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
);
void rrr_cmodule_worker_get_mmap_channel_to_parent_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
);
void rrr_cmodule_worker_stats_message_write (
		struct rrr_cmodule_worker *worker,
		const struct rrr_msg_stats *msg
);
int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		const struct rrr_cmodule_worker_callbacks *callbacks
);
int rrr_cmodule_worker_loop_init_wrapper_default (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
);
int rrr_cmodule_worker_main (
		struct rrr_cmodule_worker *worker,
		const char *log_prefix,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_arg,
		struct rrr_cmodule_worker_callbacks *callbacks
);
struct rrr_event_queue *rrr_cmodule_worker_get_event_queue (
		struct rrr_cmodule_worker *worker
);
struct rrr_settings *rrr_cmodule_worker_get_settings (
		struct rrr_cmodule_worker *worker
);
struct rrr_settings_used *rrr_cmodule_worker_get_settings_used (
		struct rrr_cmodule_worker *worker
);
int rrr_cmodule_worker_init (
		struct rrr_cmodule_worker *worker,
		const char *name,
		const struct rrr_settings *settings,
		const struct rrr_settings_used *settings_used,
		struct rrr_event_queue *event_queue_parent,
		struct rrr_event_queue *event_queue_worker,
		struct rrr_fork_handler *fork_handler,
		const struct rrr_discern_stack_collection *methods,
		rrr_time_us_t spawn_interval,
		enum rrr_cmodule_process_mode process_mode,
		int do_spawning,
		int do_drop_on_error
);
void rrr_cmodule_worker_cleanup (
		struct rrr_cmodule_worker *worker
);

#endif /* RRR_CMODULE_WORKER_H */
