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
#include <string.h>

#include "../log.h"
#include "../allocator.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "msgdb_client.h"
#include "msgdb_common.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket_client.h"
#include "../socket/rrr_socket_read.h"
#include "../socket/rrr_socket_constants.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"
#include "../array.h"

#define RRR_MSGDB_CLIENT_PING_INTERVAL_S (RRR_SOCKET_CLIENT_HARD_TIMEOUT_S / 2)

struct rrr_msgdb_client_await_callback_data {
	int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS);
	void *delivery_callback_arg;
};

static int __rrr_msgdb_client_read_ack_callback (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_msgdb_client_conn *conn = arg1;
	struct rrr_msgdb_client_await_callback_data *callback_data = arg2;

	int ret = 0;

	short positive_ack = 0;
	short negative_ack = 0;

	if (RRR_MSG_CTRL_FLAGS(message) & RRR_MSGDB_CTRL_F_ACK) {
		positive_ack = 1;
		RRR_DBG_3("msgdb fd %i recv ACK\n", conn->fd);
	}
	else if (RRR_MSG_CTRL_FLAGS(message) & RRR_MSGDB_CTRL_F_NACK) {
		negative_ack = 1;
		RRR_DBG_3("msgdb fd %i recv NACK\n", conn->fd);
	}
	else if (RRR_MSG_CTRL_FLAGS(message) & RRR_MSGDB_CTRL_F_PONG) {
		RRR_DBG_3("msgdb fd %i recv PONG\n", conn->fd);
		// Don't pass to delivery callback
		goto out;
	}
	else {
		RRR_MSG_0("message database client received unexpected control packet of type %u\n",
			RRR_MSG_CTRL_FLAGS(message));
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	struct rrr_msg_msg *msg_dummy = NULL;
	if ((ret = callback_data->delivery_callback (&msg_dummy, positive_ack, negative_ack, callback_data->delivery_callback_arg)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_client_read_msg_callback (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_msgdb_client_conn *conn = arg1;
	struct rrr_msgdb_client_await_callback_data *callback_data = arg2;

	RRR_DBG_3("msgdb fd %i recv MSG size %" PRIrrrl "\n", conn->fd, MSG_TOTAL_SIZE(*message));

	return callback_data->delivery_callback (message, 0, 0, callback_data->delivery_callback_arg);
}

static int __rrr_msgdb_client_read (
		struct rrr_msgdb_client_conn *conn,
		short allow_multiple,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	int ret = 0;

	struct rrr_msgdb_client_await_callback_data callback_data = {
		delivery_callback,
		delivery_callback_arg
	};

	uint64_t bytes_read_dummy = 0;
	if ((ret = rrr_socket_read_message_split_callbacks (
			&bytes_read_dummy,
			&conn->read_sessions,
			conn->fd,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | (allow_multiple ? RRR_READ_MESSAGE_FLUSH_OVERSHOOT : 0),
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			__rrr_msgdb_client_read_msg_callback,
			NULL,
			NULL,
			__rrr_msgdb_client_read_ack_callback,
			NULL,
			conn,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_msgdb_client_await (
		struct rrr_msgdb_client_conn *conn,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;

	uint64_t bytes_read = 0;
	uint64_t bytes_read_prev = 0;

	retry:

	if ((ret = __rrr_msgdb_client_read (
			conn,
			0, /* Process at most one message */
			delivery_callback,
			delivery_callback_arg
	)) != 0) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			if (bytes_read == bytes_read_prev) {
				rrr_posix_usleep(50); // 50 us (schedule)
			}
			bytes_read_prev = bytes_read;
			goto retry;
		}
		else if (ret == RRR_SOCKET_READ_EOF) {
			RRR_DBG_7("msgdb fd %i await EOF during await\n", conn->fd);
		}
		else {
			RRR_MSG_0("msgdb fd %i Error %i while reading from message db server\n", conn->fd, ret);
		}
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int __rrr_msgdb_client_send_callback (
		int fd,
		void **data,
		rrr_length data_size,
		void *arg
) {
	(void)(arg);
	return rrr_socket_send_blocking (fd, *data, data_size, NULL, NULL, 0 /* Not silent */);
}

int rrr_msgdb_client_send (
		struct rrr_msgdb_client_conn *conn,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	char *topic_tmp = NULL;

	uint64_t send_start = 0;

	if (RRR_DEBUGLEVEL_3) {
		if (rrr_msg_msg_topic_get(&topic_tmp, msg) == 0) {
			RRR_DBG_3("msgdb fd %i %s size %llu topic '%s'\n",
				conn->fd, MSG_TYPE_NAME(msg), (long long unsigned int) MSG_TOTAL_SIZE(msg), topic_tmp);
		}
		else {
			RRR_MSG_0("Warning: Failed to allocate memory for debug message in %s\n", __func__);
		}

		send_start = rrr_time_get_64();
	}

	if ((ret = rrr_msgdb_common_msg_send (
			conn->fd,
			msg,
			__rrr_msgdb_client_send_callback,
			NULL
	)) != 0) {
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG_3("msgdb fd %i send time %" PRIu64 "ms\n", conn->fd, (rrr_time_get_64() - send_start) / 1000);
	}

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	return ret;
}

static int __rrr_msgdb_client_send_empty (
		struct rrr_msgdb_client_conn *conn,
		rrr_u8 type,
		const char *topic
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = rrr_msg_msg_new_empty (
			&msg,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			0,
			0
	)) != 0) {
		goto out;
	}

	rrr_length topic_len = 0;
	if ((ret = rrr_length_from_size_t_err(&topic_len, strlen(topic))) != 0 || topic_len > UINT16_MAX) {
		RRR_MSG_0("Topic exceeds maximum length in %s (%llu>%llu)\n",
			__func__,
			(unsigned long long) topic_len,
			(unsigned long long) UINT16_MAX
		);
		goto out;
	}

	if ((ret = rrr_msg_msg_topic_set(&msg, topic, (uint16_t) topic_len)) != 0) {
		goto out;
	}

	MSG_SET_TYPE(msg, type);

	if ((ret = rrr_msgdb_client_send(conn, msg)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

int rrr_msgdb_client_cmd_idx (
		struct rrr_msgdb_client_conn *conn,
		uint32_t min_age_s
) {
	return rrr_msgdb_common_ctrl_msg_send_idx (
			conn->fd,
			min_age_s,
			__rrr_msgdb_client_send_callback,
			NULL
	);
}

int rrr_msgdb_client_cmd_tidy (
		struct rrr_msgdb_client_conn *conn,
		uint32_t max_age_s
) {
	return rrr_msgdb_common_ctrl_msg_send_tidy (
			conn->fd,
			max_age_s,
			__rrr_msgdb_client_send_callback,
			NULL
	);
}

int rrr_msgdb_client_cmd_get (
		struct rrr_msgdb_client_conn *conn,
		const char *topic
) {
	return __rrr_msgdb_client_send_empty(conn, MSG_TYPE_GET, topic);
}

int rrr_msgdb_client_cmd_del (
		struct rrr_msgdb_client_conn *conn,
		const char *topic
) {
	return __rrr_msgdb_client_send_empty(conn, MSG_TYPE_DEL, topic);
}

static void __rrr_msgdb_client_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_msgdb_client_conn *conn = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	RRR_DBG_3("msgdb fd %i send PING\n", conn->fd);

	if (rrr_msgdb_common_ctrl_msg_send_ping (
			conn->fd,
			__rrr_msgdb_client_send_callback,
			NULL
	) != 0) {
		RRR_DBG_3("msgdb fd %i ping failed\n", conn->fd);
		goto out_error;
	}

	return;

	out_error:
	/* Application must reconnect */
	rrr_msgdb_client_close(conn);
}

static void __rrr_msgdb_client_event_read (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_msgdb_client_conn *conn = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp = 0;
	int max = 100;

	RRR_EVENT_HOOK();

	again:
	if ((ret_tmp = __rrr_msgdb_client_read (
			conn,
			1, /* Allow multiple messages being processed per round */
			conn->delivery_callback,
			conn->delivery_callback_arg
	)) != 0) {
		ret_tmp &= ~(RRR_MSGDB_INCOMPLETE);
		goto out;
	}

	if (--max) {
		goto again;
	}

	out:
	if (ret_tmp != 0) {
		rrr_msgdb_client_close(conn);
	}
}

int rrr_msgdb_client_open (
		struct rrr_msgdb_client_conn *conn,
		const char *path,
		struct rrr_event_queue *queue,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	int ret = 0;

	if (conn->fd != 0) {
		goto out;
	}

	if ((ret = rrr_socket_unix_connect (&conn->fd, "msgdb_client", path, 1 /* Non-block */)) != 0) {
		goto out;
	}

	/* Always clear regardless of queue argument */
	rrr_event_collection_clear(&conn->events);

	if (queue != NULL) {
		rrr_event_collection_init(&conn->events, queue);

		struct rrr_event_handle event_periodic = {0};
		struct rrr_event_handle event_read = {0};

		if ((ret = rrr_event_collection_push_periodic (
				&event_periodic,
				&conn->events,
				__rrr_msgdb_client_event_periodic,
				conn,
				RRR_MSGDB_CLIENT_PING_INTERVAL_S * 1000 * 1000
		)) != 0) {
			RRR_MSG_0("Failed to create periodic event in %s\n", __func__);
			goto out_close;
		}

		EVENT_ADD(event_periodic);

		if ((ret = rrr_event_collection_push_read (
				&event_read,
				&conn->events,
				conn->fd,
				__rrr_msgdb_client_event_read,
				conn,
				1 * 1000 * 1000 // 1 second
		)) != 0) {
			goto out_close;
		}

		EVENT_ADD(event_read);
	}

	conn->delivery_callback = delivery_callback;
	conn->delivery_callback_arg = delivery_callback_arg;

	RRR_DBG_3("msgdb open '%s' fd is %i\n", path, conn->fd);

	goto out;
	out_close:
		rrr_socket_close(conn->fd);
		conn->fd = 0;
	out:
		return ret;
}

int rrr_msgdb_client_open_simple (
		struct rrr_msgdb_client_conn *conn,
		const char *path
) {
	return rrr_msgdb_client_open (conn, path, NULL, NULL, NULL);
}

void rrr_msgdb_client_close (
		struct rrr_msgdb_client_conn *conn
) {
	rrr_event_collection_clear(&conn->events);
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

int rrr_msgdb_client_conn_ensure_with_callback (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_event_queue *queue,
		int (*callback)(struct rrr_msgdb_client_conn *conn, void *arg),
		void *callback_arg,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	int ret = 0;

	int retries = 1;
	do {
		if ((ret = rrr_msgdb_client_open (
				conn,
				socket,
				queue,
				delivery_callback,
				delivery_callback_arg
		)) != 0) {
			RRR_MSG_0("Connection to msgdb on socket '%s' failed\n",
				socket);
		}
		else if ((ret = callback(conn, callback_arg)) != 0) {
			rrr_msgdb_client_close(conn);
		}
	} while (ret != 0 && retries--);

	return ret;
}
