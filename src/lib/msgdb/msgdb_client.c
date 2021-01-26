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

#include <stdlib.h>

#include "../log.h"
#include "msgdb_client.h"
#include "msgdb_common.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket_client.h"
#include "../socket/rrr_socket_read.h"

int rrr_msgdb_client_open (
	struct rrr_msgdb_client_conn *conn,
	const char *path
) {
	int ret = 0;

	if (conn->fd != 0) {
		goto out;
	}

	if ((ret = rrr_socket_unix_connect (&conn->fd, "msgdb_client", path, 0)) != 0) {
		goto out;
	}

	RRR_DBG_2("msgdb open '%s' fd is %i\n", path, conn->fd);

	out:
	return ret;
}

void rrr_msgdb_client_close (
	struct rrr_msgdb_client_conn *conn
) {
	if (conn->fd > 0) {
		rrr_socket_close_no_unlink(conn->fd);
		conn->fd = 0;
	}
	rrr_read_session_collection_clear(&conn->read_sessions);
}

void rrr_msgdb_client_close_void (
	void *conn
) {
	rrr_msgdb_client_close(conn);
}

static int __rrr_msgdb_client_await_ack_callback (
	const struct rrr_msg *message,
	void *arg1,
	void *arg2
) {
	struct rrr_msgdb_client_conn *conn = arg1;
	int *positive_ack = arg2;

	if (RRR_MSG_CTRL_FLAGS(message) & RRR_MSGDB_CTRL_F_ACK) {
		RRR_DBG_3("msgdb fd %i recv ACK\n", conn->fd);
		*positive_ack = 1;
	}
	else if (RRR_MSG_CTRL_FLAGS(message) & RRR_MSGDB_CTRL_F_NACK) {
		RRR_DBG_3("msgdb fd %i recv NACK\n", conn->fd);
	}
	else {
		RRR_MSG_0("message database client received unexpected control packet of type %u\n",
			RRR_MSG_CTRL_FLAGS(message));
		return RRR_MSGDB_SOFT_ERROR;
	}

	return RRR_MSGDB_OK;
}

int rrr_msgdb_client_await_ack (
	int *positive_ack,
	struct rrr_msgdb_client_conn *conn
) {
	int ret = 0;

	*positive_ack = 0;

	uint64_t bytes_read;
	if ((ret = rrr_socket_read_message_split_callbacks (
			&bytes_read,
			&conn->read_sessions,
			conn->fd,
			RRR_SOCKET_READ_METHOD_RECV,
			NULL,
			NULL,
			NULL,
			__rrr_msgdb_client_await_ack_callback,
			conn,
			positive_ack
	)) != 0) {
		RRR_MSG_0("msgdb fd %i Error %i while reading from message db server\n", conn->fd, ret);
		goto out;
	}

	out:
	return ret;
}

int rrr_msgdb_client_put (
	struct rrr_msgdb_client_conn *conn,
	const struct rrr_msg_msg *msg
) {
	int ret = 0;

	RRR_DBG_2("msgdb fd %i PUT msg size %li\n", conn->fd, MSG_TOTAL_SIZE(msg));

	if ((ret = rrr_msgdb_common_ctrl_msg_send_blocking (conn->fd, RRR_MSGDB_CTRL_F_PUT)) != 0) {
		goto out;
	}

	if ((ret = rrr_msgdb_common_msg_send_blocking (conn->fd, msg)) != 0) {
		goto out;
	}

	out:
	return ret;
}
