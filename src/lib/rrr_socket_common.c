/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>

#include "../global.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "rrr_socket_common.h"
#include "rrr_socket_read.h"
#include "messages.h"
#include "message_addr.h"
#include "read.h"

struct receive_callback_data {
	struct rrr_socket_common_in_flight_counter *in_flight;
	int (*callback)(struct rrr_read_session *read_session, void *arg);
	void *arg;
};

static int __rrr_socket_common_receive_callback_basic (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct receive_callback_data *data = arg;
	return data->callback(read_session, data->arg);
}

/*
static int __rrr_socket_common_receive_callback_and_check_ctrl (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct receive_callback_data *data = arg;

	int ret = 0;

	struct rrr_socket_msg *msg = (struct rrr_socket_msg *) read_session->rx_buf_ptr;

	if (RRR_SOCKET_MSG_IS_CTRL_NETWORK_ENDIAN(msg)) {
		if (read_session->target_size != sizeof(*msg)) {
			RRR_MSG_ERR("Unknown message size of control message %li vs %lu in __rrr_socket_common_receive_callback_and_check_ctrl\n",
					read_session->target_size, sizeof(*msg));
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		msg->msg_type = be16toh(msg->msg_type);
		msg->msg_value = be64toh(msg->msg_value);

		if (RRR_SOCKET_MSG_CTRL_F_HAS(msg, RRR_SOCKET_MSG_CTRL_F_ACK)) {
			if (data->in_flight == NULL) {
				RRR_MSG_ERR("Received an ACK message in __rrr_socket_common_receive_callback_and_check_ctrl but no in flight counter was set\n");
				ret = RRR_READ_SOFT_ERROR;
				goto out;
			}
			RRR_SOCKET_MSG_CTRL_F_CLEAR(msg, RRR_SOCKET_MSG_CTRL_F_ACK);
		}
		RRR_SOCKET_MSG_CTRL_F_CLEAR(msg, RRR_SOCKET_MSG_CTRL_F_RESERVED);

		if (msg->msg_type != 0) {
			RRR_MSG_ERR("Unknown flags %i received in control message in __rrr_socket_common_receive_callback_and_check_ctrl\n",
					msg->msg_type);
			ret = RRR_READ_SOFT_ERROR;
			goto out;
		}

		data->in_flight->in_flight_to_remote_count -= msg->msg_value;

//		printf ("ACK %" PRIu64 " -> %i\n", msg->msg_value, data->in_flight->in_flight_to_remote_count);
	}
	else {
		ret = data->callback(read_session, data->arg);

		if (data->in_flight != NULL) {
			data->in_flight->not_acknowledged_count++;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
	return ret;
}
*/
int rrr_socket_common_receive_array (
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		int socket_read_flags,
		const struct rrr_array *definition,
		int do_sync_byte_by_byte,
		int (*callback)(struct rrr_read_session *read_session, void *arg),
		void *arg
) {
	struct rrr_read_common_get_session_target_length_from_array_data callback_data_array = {
			definition,
			do_sync_byte_by_byte
	};

	struct receive_callback_data callback_data = {
			NULL,
			callback,
			arg
	};

	int ret = rrr_socket_read_message_default (
			read_session_collection,
			fd,
			sizeof(struct rrr_socket_msg),
			4096,
			read_flags,
			socket_read_flags,
			rrr_read_common_get_session_target_length_from_array,
			&callback_data_array,
			__rrr_socket_common_receive_callback_basic,
			&callback_data
	);

	if (ret != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			return 0;
		}
		else if (ret == RRR_SOCKET_READ_EOF) {
			return ret;
		}
		else if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_DBG_3("Soft error while reading data in rrr_socket_common_receive_array\n");
			return RRR_SOCKET_SOFT_ERROR;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			RRR_MSG_ERR("Hard error while reading data in rrr_socket_common_receive_array\n");
			return 1;
		}
	}

	return 0;
}

/*
 * Apparently not used
int rrr_socket_common_receive_socket_msg (
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		int socket_read_flags,
		struct rrr_socket_common_in_flight_counter *in_flight,
		int (*callback)(struct rrr_read_session *read_session, void *arg),
		void *arg
) {
	int ret = 0;

	struct receive_callback_data callback_data = {
			in_flight,
			callback,
			arg
	};

	ret = rrr_socket_read_message_default (
			read_session_collection,
			fd,
			sizeof(struct rrr_socket_msg),
			4096,
			read_flags,
			socket_read_flags,
			rrr_read_common_get_session_target_length_from_message_and_checksum,
			NULL,
			__rrr_socket_common_receive_callback_and_check_ctrl,
			&callback_data
	);

	if (ret == RRR_SOCKET_OK) {
		if (in_flight != NULL) {
			if (in_flight->not_acknowledged_count > 10) {
				if (RRR_LL_COUNT(read_session_collection) > 1) {
					RRR_BUG("BUG: In flight counter used while receiving data from several remotes in rrr_socket_common_receive_socket_msg\n");
				}

				struct rrr_socket_msg ack_msg = {0};
				rrr_socket_msg_populate_head (
						&ack_msg,
						RRR_SOCKET_MSG_TYPE_CTRL | RRR_SOCKET_MSG_CTRL_F_ACK,
						sizeof(ack_msg),
						in_flight->not_acknowledged_count
				);
				rrr_socket_msg_checksum_and_to_network_endian (&ack_msg);

				if ((ret = rrr_socket_sendto_nonblock(fd, &ack_msg, sizeof(ack_msg), NULL, 0)) != 0) {
					if (ret == RRR_SOCKET_SOFT_ERROR) {
						goto out;
					}
					RRR_MSG_ERR("Error while sending ACK message in rrr_socket_common_receive_socket_msg\n");
					goto out;
				}

				in_flight->not_acknowledged_count = 0;
			}
		}
	}
	else {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			ret = 0;
		}
		else if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_MSG_ERR("Warning: Soft error while reading data in rrr_socket_common_receive_socket_msg\n");
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			RRR_MSG_ERR("Hard error while reading data in rrr_socket_common_receive_socket_msg\n");
		}
		else {
			RRR_BUG("Unknown return value %i from read in rrr_socket_common_receive_socket_msg\n", ret);
		}
	}

	out:
	return ret;
}
*/

int rrr_socket_common_prepare_and_send_socket_msg_blocking (
		struct rrr_socket_msg *socket_msg,
		int fd,
		struct rrr_socket_common_in_flight_counter *in_flight
) {
	int ret = 0;

	if (RRR_SOCKET_MSG_IS_RRR_MESSAGE(socket_msg)) {
		struct rrr_message *message = (struct rrr_message *) socket_msg;

		ssize_t msg_size = MSG_TOTAL_SIZE(message);

		rrr_message_prepare_for_network((struct rrr_message *) message);
		rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message);

		if ((ret = rrr_socket_send_blocking (
				fd,
				message ,
				msg_size
		)) != 0) {
			RRR_MSG_ERR("Error while sending message in rrr_socket_common_prepare_and_send_rrr_message\n");
			goto out;
		}
	}
	else if (RRR_SOCKET_MSG_IS_RRR_MESSAGE_ADDR(socket_msg)) {
		struct rrr_message_addr *message = (struct rrr_message_addr *) socket_msg;

		rrr_message_addr_prepare_for_network(message);
		rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message);

		if ((ret = rrr_socket_send_blocking (
				fd,
				message,
				sizeof(struct rrr_message_addr)
		)) != 0) {
			RRR_MSG_ERR("Error while sending address message in rrr_socket_common_prepare_and_send_rrr_message\n");
			goto out;
		}
	}
	else if (RRR_SOCKET_MSG_IS_CTRL(socket_msg)) {
		rrr_socket_msg_checksum_and_to_network_endian (socket_msg);

		if ((ret = rrr_socket_send_blocking (
				fd,
				socket_msg,
				sizeof(*socket_msg)
		)) != 0) {
			RRR_MSG_ERR("Error while sending control message in rrr_socket_common_prepare_and_send_rrr_message\n");
			goto out;
		}
	}
	else {
		RRR_BUG("Unknown socket msg in rrr_socket_common_prepare_and_socket_msg");
	}

	if (ret == RRR_SOCKET_OK && in_flight != NULL) {
		in_flight->in_flight_to_remote_count++;
	}

	out:
	return ret;
}
