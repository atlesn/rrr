/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_RAFT_H
#define RRR_RAFT_H

#include <stdint.h>
#include <stdio.h>

#define RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS             \
    void *arg

struct rrr_fork_handler;
struct rrr_raft_channel;
struct rrr_event_queue;

int rrr_raft_fork (
		struct rrr_raft_channel **result,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		const char *name,
		int socketpair[2],
		int server_id,
		const char *dir,
		void (*pong_callback)(RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS),
		void *callback_arg
);
void rrr_raft_cleanup (
		struct rrr_raft_channel *channel
);
int rrr_raft_client_request (
		struct rrr_raft_channel *channel,
		const void *data,
		size_t data_size,
		uint32_t req_index
);

#endif /* RRR_RAFT_H */
