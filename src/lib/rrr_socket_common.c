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
#include "read.h"

struct receive_callback_data {
	int (*callback)(struct rrr_read_session *read_session, void *arg);
	void *arg;
};

static int __rrr_socket_common_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct receive_callback_data *data = arg;

	return data->callback(read_session, data->arg);
}

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
			definition, do_sync_byte_by_byte
	};

	struct receive_callback_data callback_data = {
			callback, arg
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
			__rrr_socket_common_receive_callback,
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
			RRR_MSG_ERR("Warning: Soft error while reading data in rrr_socket_common_receive_array\n");
			return RRR_SOCKET_SOFT_ERROR;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			RRR_MSG_ERR("Hard error while reading data in rrr_socket_common_receive_array\n");
			return 1;
		}
	}

	return 0;
}

int rrr_socket_common_receive_socket_msg (
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		int socket_read_flags,
		int (*callback)(struct rrr_read_session *read_session, void *arg),
		void *arg
) {
	int ret = 0;

	struct receive_callback_data callback_data = {
			callback, arg
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
			__rrr_socket_common_receive_callback,
			&callback_data
	);

	if (ret != RRR_SOCKET_OK) {
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

	return ret;
}

int rrr_socket_common_prepare_and_send_rrr_message (struct rrr_message *message, int fd) {
	int ret = 0;

	ssize_t msg_size = MSG_TOTAL_SIZE(message);

	rrr_message_prepare_for_network((struct rrr_message *) message);
	rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message);

	if ((ret = rrr_socket_sendto(fd, message, msg_size, NULL, 0)) != 0) {
		RRR_MSG_ERR("Error while sending message in rrr_socket_common_prepare_and_send_rrr_message\n");
		goto out;
	}

	out:
	return ret;
}
