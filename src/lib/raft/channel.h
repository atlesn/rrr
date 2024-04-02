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

#ifndef RRR_RAFT_CHANNEL_H
#define RRR_RAFT_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

#include "common.h"

#define RRR_RAFT_PONG_CALLBACK_ARGS                    \
    int server_id,                                     \
    void *arg

#define RRR_RAFT_ACK_CALLBACK_ARGS                     \
    int server_id,                                     \
    uint32_t req_index,                                \
    enum rrr_raft_code code,                           \
    void *arg

#define RRR_RAFT_OPT_CALLBACK_ARGS                     \
    int server_id,                                     \
    uint32_t req_index,                                \
    int64_t is_leader,                                 \
    int64_t leader_id,                                 \
    const char *leader_address,                        \
    struct rrr_raft_server **servers,                  \
    void *arg

#define RRR_RAFT_MSG_CALLBACK_ARGS                     \
    int server_id,                                     \
    uint32_t req_index,                                \
    struct rrr_msg_msg **msg,                          \
    void *arg

#define RRR_RAFT_STATUS_TO_STR(s)                      \
   ((s) == RRR_RAFT_STANDBY ? "STANDBY" :              \
   ((s) == RRR_RAFT_VOTER ? "VOTER" :                  \
   ((s) == RRR_RAFT_SPARE ? "SPARE" : "UNKNOWN")))

#define RRR_RAFT_CATCH_UP_TO_STR(s)                                  \
    ((s) == RRR_RAFT_CATCH_UP_NONE ? "NONE" :                        \
    ((s) == RRR_RAFT_CATCH_UP_RUNNING ? "RUNNING" :                  \
    ((s) == RRR_RAFT_CATCH_UP_ABORTED ? "ABORTED" :                  \
    ((s) == RRR_RAFT_CATCH_UP_FINISHED ? "FINISHED" : "UNKNOWN"))))

struct rrr_msg_msg;
struct rrr_event_queue;
struct rrr_fork_handler;
struct rrr_raft_channel;

struct rrr_raft_channel_callbacks {
	void (*pong_callback)(RRR_RAFT_PONG_CALLBACK_ARGS);
	void (*ack_callback)(RRR_RAFT_ACK_CALLBACK_ARGS);
	void (*opt_callback)(RRR_RAFT_OPT_CALLBACK_ARGS);
	void (*msg_callback)(RRR_RAFT_MSG_CALLBACK_ARGS);
	void *arg;
};

void rrr_raft_channel_fds_get (
		int fds[2],
		const struct rrr_raft_channel *channel
);
int rrr_raft_channel_fork (
		struct rrr_raft_channel **result,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		const char *name,
		int socketpair[2],
		const struct rrr_raft_server *servers,
		size_t servers_self,
		const char *dir,
		void (*pong_callback)(RRR_RAFT_PONG_CALLBACK_ARGS),
		void (*ack_callback)(RRR_RAFT_ACK_CALLBACK_ARGS),
		void (*opt_callback)(RRR_RAFT_OPT_CALLBACK_ARGS),
		void (*msg_callback)(RRR_RAFT_MSG_CALLBACK_ARGS),
		void *callback_arg
);
void rrr_raft_channel_cleanup (
		struct rrr_raft_channel *channel
);
int rrr_raft_channel_request_put (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size
);
int rrr_raft_channel_request_put_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_msg_msg *msg
);
int rrr_raft_channel_request_opt (
		uint32_t *req_index,
		struct rrr_raft_channel *channel
);
int rrr_raft_channel_request_get (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length
);
int rrr_raft_channel_servers_add (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
);
int rrr_raft_channel_servers_del (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
);
int rrr_raft_channel_servers_assign (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
);
int rrr_raft_channel_leadership_transfer (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		int server_id
);

#endif /* RRR_RAFT_CHANNEL_H */
