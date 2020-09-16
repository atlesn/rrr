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

#ifndef RRR_MAIN_H
#define RRR_MAIN_H

#define RRR_ENV_DEBUGLEVEL				"RRR_DEBUGLEVEL"
#define RRR_ENV_DEBUGLEVEL_ON_EXIT		"RRR_DEBUGLEVEL_ON_EXIT"
#define RRR_ENV_NO_WATCHDOG_TIMERS		"RRR_NO_WATCHDOG_TIMERS"
#define RRR_ENV_NO_THREAD_RESTART		"RRR_NO_THREAD_RESTART"
#define RRR_ENV_LOGLEVEL_TRANSLATION	"RRR_LOGLEVEL_TRANSLATION"
#define RRR_ENV_TIME_TO_LIVE			"RRR_TIME_TO_LIVE"

#include "lib/cmdlineparser/cmdline_defines.h"

struct cmd_data;
struct rrr_thread_collection;
struct rrr_instance_collection;
struct rrr_config;
struct rrr_stats_engine;
struct rrr_message_broker;
struct rrr_fork_handler;

int rrr_main_create_and_start_threads (
		struct rrr_thread_collection **thread_collection,
		struct rrr_instance_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
);

void rrr_main_threads_stop_and_destroy (struct rrr_thread_collection *collection);
int rrr_main_parse_cmd_arguments_and_env(struct cmd_data *cmd, const char **env, cmd_conf config);
int rrr_main_print_help_and_version (
		struct cmd_data *cmd,
		int argc_minimum
);

#endif /* RRR_MAIN_H */
