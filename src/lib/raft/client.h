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

#ifndef RRR_RAFT_CLIENT_H
#define RRR_RAFT_CLIENT_H

#include <stdio.h>
#include <stddef.h>

int rrr_raft_client_setup (
		struct rrr_raft_channel *channel
);
int rrr_raft_client_request_put (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size
);
int rrr_raft_client_request_put_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_msg_msg *msg
);
int rrr_raft_client_request_opt (
		uint32_t *req_index,
		struct rrr_raft_channel *channel
);
int rrr_raft_client_request_get (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length
);
int rrr_raft_client_servers_add (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
);
int rrr_raft_client_servers_del (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
);
int rrr_raft_client_servers_assign (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
);
int rrr_raft_client_leadership_transfer (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		int server_id
);

#endif /* RRR_RAFT_CLIENT_H */
