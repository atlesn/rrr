/*

Read Route Record

Copyright (C) 2018-2022 Atle Solbakken atle@goliathdns.no

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

#define RRR_ENV_DEBUGLEVEL               "RRR_DEBUGLEVEL"
#define RRR_ENV_DEBUGLEVEL_ON_EXIT       "RRR_DEBUGLEVEL_ON_EXIT"
#define RRR_ENV_START_INTERVAL           "RRR_START_INTERVAL"
#define RRR_ENV_NO_WATCHDOG_TIMERS       "RRR_NO_WATCHDOG_TIMERS"
#define RRR_ENV_NO_THREAD_RESTART        "RRR_NO_THREAD_RESTART"
#define RRR_ENV_LOGLEVEL_TRANSLATION     "RRR_LOGLEVEL_TRANSLATION"
#define RRR_ENV_RUN_DIRECTORY            "RRR_RUN_DIRECTORY"
#define RRR_ENV_OUTPUT_BUFFER_WARN_LIMIT "RRR_INSTANCE_OUTPUT_BUFFER_WARN_LIMIT"

#include "lib/cmdlineparser/cmdline_defines.h"

struct cmd_data;
struct rrr_thread_collection;
struct rrr_instance_collection;
struct rrr_instance_config_collection;
struct rrr_stats_engine;
struct rrr_message_broker;
struct rrr_fork_handler;

int rrr_main_parse_cmd_arguments_and_env(struct cmd_data *cmd, const char **env, cmd_conf config);
int rrr_main_print_banner_help_and_version (
		struct cmd_data *cmd,
		unsigned int argc_minimum
);

#endif /* RRR_MAIN_H */
