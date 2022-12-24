/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MSGDB_CLIENT_H
#define RRR_MSGDB_CLIENT_H

#include "../read.h"
#include "../messages/msg_msg.h"
#include "../event/event_collection.h"

#define RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS \
    struct rrr_msg_msg **msg, short positive_ack, short negative_ack, void *arg

struct rrr_msgdb_client_conn {
	int fd;
	struct rrr_read_session_collection read_sessions;
	struct rrr_event_collection events;
	int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS);
	void *delivery_callback_arg;
};

struct rrr_msg_msg;
struct rrr_event_queue;

int rrr_msgdb_client_await (
		struct rrr_msgdb_client_conn *conn,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_client_send (
		struct rrr_msgdb_client_conn *conn,
		const struct rrr_msg_msg *msg
);
int rrr_msgdb_client_cmd_idx (
		struct rrr_msgdb_client_conn *conn,
		uint32_t min_age_s
);
int rrr_msgdb_client_cmd_tidy (
		struct rrr_msgdb_client_conn *conn,
		uint32_t max_age_s
);
int rrr_msgdb_client_cmd_get (
		struct rrr_msgdb_client_conn *conn,
		const char *topic
);
int rrr_msgdb_client_cmd_del (
		struct rrr_msgdb_client_conn *conn,
		const char *topic
);
int rrr_msgdb_client_open (
		struct rrr_msgdb_client_conn *conn,
		const char *path,
		struct rrr_event_queue *queue,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_client_open_simple (
		struct rrr_msgdb_client_conn *conn,
		const char *path
);
void rrr_msgdb_client_close (
		struct rrr_msgdb_client_conn *conn
);
void rrr_msgdb_client_close_void (
		void *conn
);
int rrr_msgdb_client_conn_ensure_with_callback (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_event_queue *queue,
		int (*callback)(struct rrr_msgdb_client_conn *conn, void *arg),
		void *callback_arg,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);

#endif /* RRR_MSGDB_CLIENT_H */
