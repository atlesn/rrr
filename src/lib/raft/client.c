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

#include <unistd.h>

#include "channel_struct.h"

#include "../rrr_strerror.h"
#include "../array.h"
#include "../allocator.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../event/event.h"
#include "../socket/rrr_socket.h"

static int __rrr_raft_client_send_msg (
		struct rrr_raft_channel *channel,
		struct rrr_msg *msg
) {
	rrr_u32 total_size = MSG_TOTAL_SIZE(msg);

	if (RRR_MSG_IS_RRR_MESSAGE(msg)) {
		rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) msg);
	}
	rrr_msg_checksum_and_to_network_endian(msg);

	if (write(channel->fd_client, msg, total_size) != total_size) {
		RRR_MSG_0("Failed to send message in %s: %s\n",
			__func__, rrr_strerror(errno));
		return RRR_READ_HARD_ERROR;
	}

	return RRR_READ_OK;
}

static int __rrr_raft_client_send_ping (
		struct rrr_raft_channel *channel
) {
	struct rrr_msg msg = {0};

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PING, 0);

	return __rrr_raft_client_send_msg(channel, &msg);
}

static void __rrr_raft_client_periodic_cb (evutil_socket_t fd, short flags, void *arg) {
	struct rrr_raft_channel *channel = arg;

	(void)(fd);
	(void)(flags);

	if (__rrr_raft_client_send_ping(channel) != 0) {
		rrr_event_dispatch_break(channel->queue);
	}
}

static int __rrr_raft_client_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_channel *channel = arg2;

	(void)(arg1);

	int ret = 0;

	uint16_t version_dummy;
	struct rrr_array array_tmp = {0};
	int64_t is_leader, leader_id;
	char *leader_address = NULL;
	struct rrr_raft_server *servers = NULL;

	switch (MSG_TYPE(*message)) {
		case MSG_TYPE_OPT: {
			assert(MSG_IS_ARRAY(*message));

			if ((ret = rrr_array_message_append_to_array (
					&version_dummy,
					&array_tmp,
					*message
			)) != 0) {
				RRR_MSG_0("Failed to get array values in %s\n", __func__);
				goto out;
			}

			if (rrr_array_get_value_signed_64_by_tag (
					&is_leader,
					&array_tmp,
					RRR_RAFT_FIELD_IS_LEADER,
					0
			) != 0) {
				RRR_BUG("BUG: Failed to get is leader value from OPT message in %s\n", __func__);
			}

			if (rrr_array_get_value_signed_64_by_tag (
					&leader_id,
					&array_tmp,
					RRR_RAFT_FIELD_LEADER_ID,
					0
			) != 0) {
				RRR_BUG("BUG: Failed to get leader ID value from OPT message in %s\n", __func__);
			}

			if ((ret = rrr_array_get_value_str_by_tag (
					&leader_address,
					&array_tmp,
					RRR_RAFT_FIELD_LEADER_ADDRESS
			)) != 0) {
				RRR_MSG_0("Failed to get leader address value from OPT message in %s\n", __func__);
				goto out;
			}

			if ((ret = rrr_raft_opt_array_field_server_get (
					&servers,
					&array_tmp
			)) != 0) {
				RRR_MSG_0("Failed to get server values from OPT message in %s\n", __func__);
				goto out;
			}

			channel->callbacks.opt_callback (
					channel->server_id,
					(*message)->msg_value,
					is_leader,
					leader_id,
					leader_address,
					&servers,
					channel->callbacks.arg
			);
		} break;
		case MSG_TYPE_PUT: {
			MSG_SET_TYPE(*message, MSG_TYPE_MSG);

			channel->callbacks.msg_callback (
					channel->server_id,
					(*message)->msg_value,
					message,
					channel->callbacks.arg
			);
		} break;
		default: {
			RRR_BUG("BUG: Message type %s not implemented in %s\n", MSG_TYPE_NAME(*message), __func__);
		} break;
	};

	out:
	rrr_array_clear(&array_tmp);
	RRR_FREE_IF_NOT_NULL(leader_address);
	RRR_FREE_IF_NOT_NULL(servers);
	return ret;
}

static int __rrr_raft_client_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_channel *channel = arg2;

	(void)(arg1);

	enum rrr_raft_code code = RRR_MSG_CTRL_REASON(message);

	switch (RRR_MSG_CTRL_FLAGS(message) & ~(RRR_MSG_CTRL_F_RESERVED|RRR_MSG_CTRL_F_NACK_REASON_MASK)) {
		case RRR_MSG_CTRL_F_PONG:
			channel->callbacks.pong_callback(channel->server_id, channel->callbacks.arg);
			break;
		case RRR_MSG_CTRL_F_ACK:
		case RRR_MSG_CTRL_F_NACK:
			channel->callbacks.ack_callback(channel->server_id, message->msg_value, code, channel->callbacks.arg);
			break;
		default:
			RRR_BUG("BUG: Unknown flags %u in %s\n",
				RRR_MSG_CTRL_FLAGS(message), __func__);
	}

	return 0;
}

static void __rrr_raft_client_read_cb (evutil_socket_t fd, short flags, void *arg) {
	struct rrr_raft_channel *channel = arg;

	(void)(fd);

	int ret_tmp;
	uint64_t bytes_read_dummy;

	if (flags & EV_TIMEOUT) {
		RRR_MSG_0("Hard timeout in %s\n", __func__);
		rrr_event_dispatch_break(channel->queue);
		return;
	}

	if ((ret_tmp = rrr_socket_read_message_split_callbacks (
			&bytes_read_dummy,
			&channel->read_sessions,
			channel->fd_client,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			__rrr_raft_client_read_msg_cb,
			NULL,
			NULL,
			__rrr_raft_client_read_msg_ctrl_cb,
			NULL,
			NULL, /* first cb data */
			channel
	)) != 0 && ret_tmp != RRR_READ_INCOMPLETE) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		rrr_event_dispatch_break(channel->queue);
	}
}

int rrr_raft_client_setup (
		struct rrr_raft_channel *channel
) {
	int ret = 0;

	rrr_event_handle event_periodic = {0};
	rrr_event_handle event_read = {0};

	if ((ret = rrr_event_collection_push_periodic (
			&event_periodic,
			&channel->events,
			__rrr_raft_client_periodic_cb,
			channel,
			250 * 1000 // 250 ms
	)) != 0) {
		RRR_MSG_0("Failed to push periodic function in %s\n", __func__);
		goto out;
	}

	EVENT_ADD(event_periodic);

	if ((ret = rrr_event_collection_push_read (
			&event_read,
			&channel->events,
			channel->fd_client,
			__rrr_raft_client_read_cb,
			channel,
			1 * 1000 * 1000 // 1 second hard timeout
	)) != 0) {
		RRR_MSG_0("Failed to push read function in %s\n", __func__);
		goto out;
	}

	EVENT_ADD(event_read);

	out:
	return ret;
}

static int __rrr_raft_client_request_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		struct rrr_msg_msg *msg
) {
	int ret = 0;

	// Counter must begin at 1
	assert(channel->req_index > 0);

	msg->msg_value = channel->req_index;

	RRR_DBG_3("Raft request type %s size %lu fd %i message size %u req %u topic '%.*s'\n",
		MSG_TYPE_NAME(msg),
		MSG_DATA_LENGTH(msg),
		channel->fd_client,
		MSG_TOTAL_SIZE(msg),
		channel->req_index,
		MSG_TOPIC_LENGTH(msg),
		MSG_TOPIC_PTR(msg)
	);

	if ((ret = __rrr_raft_client_send_msg (
			channel,
			(struct rrr_msg *) msg
	)) != 0) {
		goto out;
	}

	*req_index = channel->req_index++;

	out:
	return ret;
}

static int __rrr_raft_client_request (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size,
		uint8_t msg_type,
		const struct rrr_array *array
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	assert((topic_length && topic) || (!topic_length && !topic));
	assert(topic_length <= UINT32_MAX && sizeof(rrr_length) == sizeof(uint32_t));

	if (array != NULL) {
		if ((ret = rrr_array_new_message_from_array (
				&msg,
				array,
				rrr_time_get_64(),
				topic,
				topic_length
		)) != 0) {
			RRR_MSG_0("Failed to create array message in %s\n", __func__);
			goto out;
		}

		MSG_SET_TYPE(msg, msg_type);
	}
	else {
		if ((ret = rrr_msg_msg_new_with_data (
				&msg,
				msg_type,
				MSG_CLASS_DATA,
				rrr_time_get_64(),
				topic,
				topic_length,
				data,
				rrr_u32_from_biglength_bug_const(data_size)
		)) != 0) {
			RRR_MSG_0("Failed to create data message in %s\n", __func__);
			goto out;
		}
	}

	if ((ret = __rrr_raft_client_request_native (
			req_index,
			channel,
			msg
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

int rrr_raft_client_request_put (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size
) {
	return __rrr_raft_client_request (
			req_index,
			channel,
			topic,
			topic_length,
			data,
			data_size,
			MSG_TYPE_PUT,
			NULL
	);
}

int rrr_raft_client_request_patch (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size
) {
	return __rrr_raft_client_request (
			req_index,
			channel,
			topic,
			topic_length,
			data,
			data_size,
			MSG_TYPE_PAT,
			NULL
	);
}

int rrr_raft_client_request_put_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	struct rrr_msg_msg *msg_new;

	if ((msg_new = rrr_msg_msg_duplicate(msg)) == NULL) {
		RRR_MSG_0("Failed to duplicate message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	MSG_SET_TYPE(msg_new, MSG_TYPE_PUT);

	if ((ret = __rrr_raft_client_request_native (
			req_index,
			channel,
			msg_new
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_new);
	return ret;
}

int rrr_raft_client_request_opt (
		uint32_t *req_index,
		struct rrr_raft_channel *channel
) {
	return __rrr_raft_client_request (
			req_index,
			channel,
			NULL,
			0,
			NULL,
			0,
			MSG_TYPE_OPT,
			NULL
	);
}

int rrr_raft_client_request_get (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length
) {
	return __rrr_raft_client_request (
			req_index,
			channel,
			topic,
			topic_length,
			NULL,
			0,
			MSG_TYPE_GET,
			NULL
	);
}

static int __rrr_raft_client_servers_change (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers,
		enum rrr_raft_cmd cmd
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	// One server must be given
	assert(servers[0].id > 0);

	// Only adding or deleting at most one server is supported
	// by raft library.
	assert(servers[1].id == 0);

	if (cmd != RRR_RAFT_CMD_SERVER_ASSIGN) {
		// Status may not be controlled using the add/del functions
		assert(servers[0].status == 0);
	}
	else {
		assert(servers[0].status > 0);
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_CMD,
			cmd
	)) != 0) {
		goto out;
	}

	for (; servers->id > 0; servers++) {
		if ((ret = rrr_raft_opt_array_field_server_push(&array_tmp, servers)) != 0) {
			goto out;
		}
	}

	if ((ret = __rrr_raft_client_request (
			req_index,
			channel,
			NULL,
			0,
			NULL,
			0,
			MSG_TYPE_OPT,
			&array_tmp
	)) != 0) {
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_raft_client_leadership_transfer (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		int server_id
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	// Passing 0 is allowed, this means to
	// pass leadership to a random voter
	assert(server_id >= 0);

	if ((ret = rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_CMD,
			RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_ID,
			server_id
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_raft_client_request (
			req_index,
			channel,
			NULL,
			0,
			NULL,
			0,
			MSG_TYPE_OPT,
			&array_tmp
	)) != 0) {
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

int rrr_raft_client_servers_add (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
) {
	return __rrr_raft_client_servers_change (
			req_index,
			channel,
			servers,
			RRR_RAFT_CMD_SERVER_ADD
	);
}

int rrr_raft_client_servers_del (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
) {
	return __rrr_raft_client_servers_change (
			req_index,
			channel,
			servers,
			RRR_RAFT_CMD_SERVER_DEL
	);
}

int rrr_raft_client_servers_assign (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
) {
	return __rrr_raft_client_servers_change (
			req_index,
			channel,
			servers,
			RRR_RAFT_CMD_SERVER_ASSIGN
	);
}

int rrr_raft_client_leadership_transfer (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		int server_id
) {
	return __rrr_raft_client_leadership_transfer (
			req_index,
			channel,
			server_id
	);
}
