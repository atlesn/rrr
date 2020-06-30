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

#ifndef RRR_CMODULE_COMMON_H
#define RRR_CMODULE_COMMON_H

#include <sys/types.h>

#include "message_addr.h"
#include "cmodule_native.h"

struct rrr_instance_thread_data;
struct rrr_stats_instance;
struct rrr_poll_collection;
struct rrr_message;
struct rrr_message_addr;

struct rrr_cmodule_common_read_callback_data {
	struct rrr_instance_thread_data *thread_data;
	const struct rrr_message *message;
	int count;
	struct rrr_message_addr addr_message;
};

void rrr_cmodule_common_loop (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_stats_instance *stats,
		struct rrr_poll_collection *poll,
		pid_t fork_pid
);
int rrr_cmodule_common_parse_config (
		struct rrr_instance_thread_data *thread_data,
		const char *config_prefix,
		const char *config_suffix
);
int rrr_cmodule_common_start_worker_fork (
		pid_t *handle_pid,
		struct rrr_instance_thread_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);

#endif /* RRR_CMODULE_COMMON_H */
