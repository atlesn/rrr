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

#ifndef RRR_CMODULE_HELPER_H
#define RRR_CMODULE_HELPER_H

#include <sys/types.h>

#include "cmodule_defines.h"
#include "../instances.h"
#include "../event/event.h"

struct rrr_instance_runtime_data;
struct rrr_stats_instance;
struct rrr_poll_collection;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_cmodule;

extern struct rrr_instance_event_functions rrr_cmodule_helper_event_functions;

const struct rrr_cmodule_config_data *rrr_cmodule_helper_config_data_get (
		struct rrr_instance_runtime_data *thread_data
);
void rrr_cmodule_helper_loop (
		struct rrr_instance_runtime_data *thread_data,
		unsigned int periodic_interval_us
);
int rrr_cmodule_helper_parse_config (
		struct rrr_instance_runtime_data *thread_data,
		const char *config_prefix,
		const char *config_suffix
);
void rrr_cmodule_helper_mmap_channel_event_function_set (
		struct rrr_instance_runtime_data *thread_data,
		int (*function)(RRR_EVENT_FUNCTION_ARGS)
);
int rrr_cmodule_helper_worker_forks_start (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
int rrr_cmodule_helper_worker_custom_fork_start (
		struct rrr_instance_runtime_data *thread_data,
		unsigned int tick_interval_us,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),
		void *custom_tick_callback_arg
);
void rrr_cmodule_helper_get_mmap_channel_to_forks_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		unsigned long long int *write_retry_counter,
		struct rrr_cmodule *cmodule
);
void rrr_cmodule_helper_get_mmap_channel_to_parent_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		unsigned long long int *write_retry_counter,
		struct rrr_cmodule *cmodule
);

#endif /* RRR_CMODULE_HELPER_H */
