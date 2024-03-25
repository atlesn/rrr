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
#include <stddef.h>

#define RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS             \
    int server_id,                                     \
    void *arg

#define RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS              \
    int server_id,                                     \
    uint32_t req_index,                                \
    int ok,                                            \
    void *arg

#define RRR_RAFT_CLIENT_OPT_CALLBACK_ARGS              \
    int server_id,                                     \
    uint32_t req_index,                                \
    uint64_t is_leader,                                \
    struct rrr_raft_server *servers,                   \
    void *arg

#define RRR_RAFT_CLIENT_MSG_CALLBACK_ARGS              \
    int server_id,                                     \
    uint32_t req_index,                                \
    struct rrr_msg_msg **msg,                          \
    void *arg

#define RRR_RAFT_STATUS_TO_STR(s)                      \
   ((s) == RRR_RAFT_STANDBY ? "STANDBY" :              \
   ((s) == RRR_RAFT_VOTER ? "VOTER" :                  \
   ((s) == RRR_RAFT_SPARE ? "SPARE" : "UNKNOWN")))

enum RRR_RAFT_STATUS {
	RRR_RAFT_STANDBY = 1,
	RRR_RAFT_VOTER,
	RRR_RAFT_SPARE
};

struct rrr_fork_handler;
struct rrr_raft_channel;
struct rrr_event_queue;
struct rrr_msg_msg;

struct rrr_raft_server {
	int64_t id;
	int64_t status;
	char address[64];
} __attribute__((packed));

int rrr_raft_fork (
		struct rrr_raft_channel **result,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		const char *name,
		int socketpair[2],
		const struct rrr_raft_server *servers,
		size_t servers_self,
		const char *dir,
		void (*pong_callback)(RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS),
		void (*ack_callback)(RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS),
		void (*opt_callback)(RRR_RAFT_CLIENT_OPT_CALLBACK_ARGS),
		void (*msg_callback)(RRR_RAFT_CLIENT_MSG_CALLBACK_ARGS),
		void *callback_arg
);
void rrr_raft_cleanup (
		struct rrr_raft_channel *channel
);
int rrr_raft_client_request_put (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		const void *data,
		size_t data_size
);
int rrr_raft_client_request_opt (
		uint32_t *req_index,
		struct rrr_raft_channel *channel
);
int rrr_raft_client_request_get (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic
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

#endif /* RRR_RAFT_H */
