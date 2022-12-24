/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include "../log.h"
#include "../allocator.h"

#include "rrr_socket.h"
#include "rrr_socket_common.h"
#include "rrr_socket_read.h"

#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../read.h"

struct receive_callback_data {
	struct rrr_socket_common_in_flight_counter *in_flight;
	int (*callback)(struct rrr_read_session *read_session, void *arg);
	void *arg;
};

struct receive_array_tree_callback_data {
	struct rrr_socket_common_in_flight_counter *in_flight;
	struct rrr_array *array_final;
	int (*callback)(struct rrr_read_session *read_session, struct rrr_array *array_final, void *arg);
	void *arg;
};

static int __rrr_socket_common_receive_array_tree_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct receive_array_tree_callback_data *data = arg;
	return data->callback(read_session, data->array_final, data->arg);
}

int rrr_socket_common_receive_array_tree (
		uint64_t *bytes_read,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int socket_read_flags,
		struct rrr_array *array_final,
		const struct rrr_array_tree *tree,
		int do_sync_byte_by_byte,
		rrr_biglength read_step_max_size,
		uint64_t ratelimit_interval_us,
		rrr_biglength ratelimit_max_bytes,
		rrr_length message_max_size,
		int (*callback)(struct rrr_read_session *read_session, struct rrr_array *array_final, void *arg),
		void (*error_callback)(struct rrr_read_session *read_session, int is_hard_err, void *arg),
		void *arg
) {
	struct rrr_read_common_get_session_target_length_from_array_tree_data callback_data_array = {
			tree,
			array_final,
			do_sync_byte_by_byte,
			message_max_size
	};

	struct receive_array_tree_callback_data callback_data = {
			NULL,
			array_final,
			callback,
			arg
	};

	int ret = rrr_socket_read_message_default (
			bytes_read,
			read_session_collection,
			fd,
			0, // No initial read size
			read_step_max_size,
			0, // No max size
			socket_read_flags,
			ratelimit_interval_us,
			ratelimit_max_bytes,
			rrr_read_common_get_session_target_length_from_array_tree,
			&callback_data_array,
			error_callback,
			arg,
			__rrr_socket_common_receive_array_tree_callback,
			&callback_data
	);

	if (ret != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			ret = RRR_READ_OK; // Clear INCOMPLETE return value
		}
		else if (ret == RRR_SOCKET_READ_EOF) {
			// OK, return EOF
		}
		else if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_DBG_3("Soft error while reading data in rrr_socket_common_receive_array_tree\n");
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			RRR_MSG_0("Hard error while reading data in rrr_socket_common_receive_array_tree\n");
			ret = RRR_SOCKET_HARD_ERROR;
		}
		else {
			RRR_BUG("Unknown return value %i while reading data in rrr_socket_common_receive_array_tree\n", ret);
		}
	}

	return ret;
}

int rrr_socket_common_prepare_and_send_msg_blocking (
		struct rrr_msg *msg,
		int fd,
		struct rrr_socket_common_in_flight_counter *in_flight,
		int (*wait_callback)(void *arg),
		void *wait_callback_arg
) {
	int ret = 0;

	if (RRR_MSG_IS_RRR_MESSAGE(msg)) {
		struct rrr_msg_msg *message = (struct rrr_msg_msg *) msg;

		const rrr_length msg_size = MSG_TOTAL_SIZE(message);

		rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) message);
		rrr_msg_checksum_and_to_network_endian ((struct rrr_msg *) message);

		if ((ret = rrr_socket_send_blocking (
				fd,
				message,
				msg_size,
				wait_callback,
				wait_callback_arg
		)) != 0) {
			RRR_MSG_0("Error while sending message in rrr_socket_common_prepare_and_send_rrr_msg_msg\n");
			goto out;
		}
	}
	else if (RRR_MSG_IS_RRR_MESSAGE_ADDR(msg)) {
		struct rrr_msg_addr *message = (struct rrr_msg_addr *) msg;

		rrr_msg_addr_prepare_for_network(message);
		rrr_msg_checksum_and_to_network_endian ((struct rrr_msg *) message);

		if ((ret = rrr_socket_send_blocking (
				fd,
				message,
				sizeof(struct rrr_msg_addr),
				wait_callback,
				wait_callback_arg
		)) != 0) {
			RRR_MSG_0("Error while sending address message in rrr_socket_common_prepare_and_send_rrr_msg_msg\n");
			goto out;
		}
	}
	else if (RRR_MSG_IS_CTRL(msg)) {
		rrr_msg_checksum_and_to_network_endian (msg);

		if ((ret = rrr_socket_send_blocking (
				fd,
				msg,
				sizeof(*msg),
				wait_callback,
				wait_callback_arg
		)) != 0) {
			RRR_MSG_0("Error while sending control message in rrr_socket_common_prepare_and_send_rrr_msg_msg\n");
			goto out;
		}
	}
	else {
		RRR_BUG("Unknown socket msg in rrr_socket_common_prepare_and_msg");
	}

	if (ret == RRR_SOCKET_OK && in_flight != NULL) {
		in_flight->in_flight_to_remote_count++;
	}

	out:
	return ret;
}
