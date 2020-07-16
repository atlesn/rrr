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

#include "lib/cmdlineparser/cmdline_defines.h"

struct cmd_data;
struct rrr_thread_collection;
struct instance_metadata_collection;
struct rrr_config;
struct rrr_stats_engine;
struct rrr_message_broker;
struct rrr_fork_handler;

int main_start_threads (
		struct rrr_thread_collection **thread_collection,
		struct instance_metadata_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
);

void main_threads_stop (struct rrr_thread_collection *collection, struct instance_metadata_collection *instances);
int main_parse_cmd_arguments(struct cmd_data *cmd, cmd_conf config);
int rrr_print_help_and_version (
		struct cmd_data *cmd,
		int argc_minimum
);

#endif /* RRR_MAIN_H */
