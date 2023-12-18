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

#ifndef RRR_CMODULE_HELPER_H
#define RRR_CMODULE_HELPER_H

#include <sys/types.h>

#include "cmodule_defines.h"
#include "../instances.h"
#include "../event/event.h"

#define RRR_CMODULE_HELPER_SET_METHOD_TO_USE(default_actions)      \
    const char *method_to_use;                                     \
    switch (cmodule_config_data->process_mode) {                   \
      case RRR_CMODULE_PROCESS_MODE_DEFAULT:                       \
        method_to_use = cmodule_config_data->process_method;       \
        default_actions; break;                                    \
      case RRR_CMODULE_PROCESS_MODE_DIRECT_DISPATCH:               \
        assert(method != NULL); method_to_use = method; break;     \
      case RRR_CMODULE_PROCESS_MODE_NONE:                          \
      default: method_to_use = NULL; assert(0); }

#define RRR_CMODULE_HELPER_APP_PERIODIC_CALLBACK_ARGS \
    struct rrr_instance_runtime_data *thread_data

struct rrr_instance_runtime_data;
struct rrr_stats_instance;
struct rrr_poll_collection;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_cmodule;
struct rrr_cmodule_worker_callbacks;

extern struct rrr_instance_event_functions rrr_cmodule_helper_event_functions;

const struct rrr_cmodule_config_data *rrr_cmodule_helper_config_data_get (
		struct rrr_instance_runtime_data *thread_data
);
int rrr_cmodule_helper_methods_iterate (
		struct rrr_instance_runtime_data *thread_data,
		int (*method_callback)(const char *stack_name, const char *method_name, void *arg),
		void *callback_arg
);
void rrr_cmodule_helper_loop (
		struct rrr_instance_runtime_data *thread_data
);
void rrr_cmodule_helper_loop_with_periodic (
		struct rrr_instance_runtime_data *thread_data,
		int (*app_periodic_callback)(RRR_CMODULE_HELPER_APP_PERIODIC_CALLBACK_ARGS)
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
int rrr_cmodule_helper_worker_forks_start_deferred_callback_set (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg
);
int rrr_cmodule_helper_worker_forks_start_with_ping_callback (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*ping_callback)(RRR_CMODULE_PING_CALLBACK_ARGS),
		void *ping_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
int rrr_cmodule_helper_worker_forks_start_with_periodic_callback (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*periodic_callback)(RRR_CMODULE_PERIODIC_CALLBACK_ARGS),
		void *periodic_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
int rrr_cmodule_helper_worker_custom_fork_start (
		struct rrr_instance_runtime_data *thread_data,
		rrr_time_us_t tick_interval_us,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),
		void *custom_tick_callback_arg
);
void rrr_cmodule_helper_get_mmap_channel_to_forks_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule *cmodule
);
void rrr_cmodule_helper_get_mmap_channel_to_parent_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule *cmodule
);

#endif /* RRR_CMODULE_HELPER_H */
