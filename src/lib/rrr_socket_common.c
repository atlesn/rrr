/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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
#include "array.h"

int rrr_socket_common_receive_message_raw_callback (
		void *data,
		ssize_t data_size,
		void *arg
) {
	struct vl_message *message = data;
	struct rrr_socket_common_receive_message_callback_data *callback_data = arg;

	int ret = 0;

	// Header CRC32 is checked when reading the data from remote and getting size
	if (rrr_socket_msg_head_to_host_and_verify((struct rrr_socket_msg *) message, data_size) != 0) {
		VL_MSG_ERR("Message was invalid in rrr_socket_common_receive_message_raw_callback\n");
		goto out_free;
	}

	if (rrr_socket_msg_check_data_checksum_and_length((struct rrr_socket_msg *) message, data_size) != 0) {
		VL_MSG_ERR ("Message checksum was invalid in rrr_socket_common_receive_message_raw_callback\n");
		goto out_free;
	}

	if (message_to_host_and_verify(message, data_size) != 0) {
		VL_MSG_ERR("Message verification failed in read_message_raw_callback (size: %u<>%u)\n",
				MSG_TOTAL_SIZE(message), message->msg_size);
		ret = 1;
		goto out_free;
	}

	ret = callback_data->callback(message, callback_data->callback_arg);
	data = NULL;

	out_free:
	RRR_FREE_IF_NOT_NULL(data);
	return ret;

}

int rrr_socket_common_receive_message_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	int ret = 0;

	// Memory is always taken care of or freed by this function
	if ((ret = rrr_socket_common_receive_message_raw_callback(read_session->rx_buf_ptr, read_session->rx_buf_wpos, arg)) != 0) {
		goto out;
	}

	out:
	read_session->rx_buf_ptr = NULL;
	return ret;
}

int rrr_socket_common_get_session_target_length_from_message_and_checksum_raw (
		ssize_t *result,
		void *data,
		ssize_t data_size,
		void *arg
) {
	if (arg != NULL) {
		VL_BUG("arg was not NULL in rrr_socket_common_get_session_target_length_from_message_and_checksum_raw\n");
	}

	*result = 0;

	ssize_t target_size = 0;
	int ret = rrr_socket_msg_get_target_size_and_check_checksum(
			&target_size,
			(struct rrr_socket_msg *) data,
			data_size
	);

	if (ret != 0) {
		if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			VL_MSG_ERR("Warning: Header checksum of message failed in rrr_socket_common_get_session_target_length_from_message_and_checksum_raw\n");
		}
		goto out;
	}

	*result = target_size;

	out:
	return ret;
}

int rrr_socket_common_get_session_target_length_from_message_and_checksum (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	int ret = rrr_socket_common_get_session_target_length_from_message_and_checksum_raw (
			&read_session->target_size,
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			arg
	);

	if (ret != 0) {
		if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			VL_MSG_ERR("Warning: Header checksum of message failed in rrr_socket_common_get_session_target_length_from_message_and_checksum\n");
		}
		goto out;
	}

	out:
	return ret;
}

int rrr_socket_common_get_session_target_length_from_array (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	struct rrr_socket_common_get_session_target_length_from_array_data *data = arg;

	ssize_t import_length = 0;
	int ret = rrr_array_get_packed_length_from_buffer (
			&import_length,
			data->definition,
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos
	);

	if (ret != 0) {
		if (ret == RRR_TYPE_PARSE_INCOMPLETE) {
			return RRR_SOCKET_READ_INCOMPLETE;
		}
		return RRR_SOCKET_SOFT_ERROR;
	}

	read_session->target_size = import_length;

	return RRR_SOCKET_OK;
}

struct receive_callback_data {
	int (*callback)(struct rrr_socket_read_session *read_session, void *arg);
	void *arg;
};

static int __rrr_socket_common_receive_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	struct receive_callback_data *data = arg;

	return data->callback(read_session, data->arg);
}

int rrr_socket_common_receive_array (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		const struct rrr_array *definition,
		int (*callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *arg
) {
	struct rrr_socket_common_get_session_target_length_from_array_data callback_data_array = {
			definition
	};

	struct receive_callback_data callback_data = {
			callback, arg
	};

	int ret = rrr_socket_read_message (
			read_session_collection,
			fd,
			sizeof(struct rrr_socket_msg),
			4096,
			read_flags,
			rrr_socket_common_get_session_target_length_from_array,
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
			VL_MSG_ERR("Warning: Soft error while reading data in rrr_socket_common_receive_array\n");
			return 0;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			VL_MSG_ERR("Hard error while reading data in rrr_socket_common_receive_array\n");
			return 1;
		}
	}

	return 0;
}

int rrr_socket_common_receive_socket_msg (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		int (*callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *arg
) {
	int ret = 0;

	struct receive_callback_data callback_data = {
			callback, arg
	};

	ret = rrr_socket_read_message (
			read_session_collection,
			fd,
			sizeof(struct rrr_socket_msg),
			4096,
			read_flags,
			rrr_socket_common_get_session_target_length_from_message_and_checksum,
			NULL,
			__rrr_socket_common_receive_callback,
			&callback_data
	);

	if (ret != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			return 0;
		}
		else if (ret == RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Warning: Soft error while reading data in rrr_socket_common_receive_socket_msg\n");
			return 0;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			VL_MSG_ERR("Hard error while reading data in rrr_socket_common_receive_socket_msg\n");
			return 1;
		}
	}

	return 0;
}
