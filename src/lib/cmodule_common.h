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

struct rrr_instance_thread_data;
struct rrr_stats_instance;
struct rrr_poll_collection;
struct rrr_message;
struct rrr_message_addr;

struct rrr_cmodule_common_read_callback_data {
	struct rrr_instance_thread_data *thread_data;
	int count;
	const struct rrr_message *message;
	struct rrr_message_addr addr_message;
};

void rrr_cmodule_common_loop (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_stats_instance *stats,
		struct rrr_poll_collection *poll,
		pid_t fork_pid,
		int no_polling
);

#endif /* RRR_CMODULE_COMMON_H */
