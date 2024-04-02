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

#ifndef RRR_RAFT_CHANNEL_STRUCT_H
#define RRR_RAFT_CHANNEL_STRUCT_H

#include <stdint.h>

#include "channel.h"

#include "../read.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
	
struct rrr_event_queue;

struct rrr_raft_channel {
	int fd_client;
	int fd_server;
	int server_id;
	uint32_t req_index;
	struct rrr_event_queue *queue;
	struct rrr_event_collection events;
	struct rrr_read_session_collection read_sessions;
	struct rrr_raft_channel_callbacks callbacks;
};

#endif /* RRR_RAFT_CHANNEL_STRUCT_H */
