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

#include "rrr_socket.h"
#include "rrr_socket_msg.h"

#include "../log.h"
#include "../crc32.h"
#include "../rrr_endian.h"

void rrr_socket_msg_populate_head (
		struct rrr_socket_msg *message,
		rrr_u16 type,
		rrr_u32 msg_size,
		rrr_u64 value
) {
	if (msg_size < sizeof(*message)) {
		RRR_BUG("Size was too small in rrr_socket_msg_head_to_network\n");
	}

	message->msg_type = type;
	message->msg_size = msg_size;
	message->msg_value = value;
}

void rrr_socket_msg_populate_control_msg (
		struct rrr_socket_msg *message,
		rrr_u16 flags,
		rrr_u64 value
) {
	if ((flags & RRR_SOCKET_MSG_CTRL_F_RESERVED) != 0) {
		RRR_BUG("Reserved flags were set in rrr_socket_msg_populate_control_msg\n");
	}

	rrr_socket_msg_populate_head (
			message,
			RRR_SOCKET_MSG_TYPE_CTRL | flags,
			sizeof(*message),
			value
	);
}

static int __rrr_socket_msg_head_validate (
		struct rrr_socket_msg *message,
		ssize_t expected_size
) {
	int ret = 0;

	if ((ssize_t) message->msg_size != expected_size) {
		RRR_MSG_0("Message network size mismatch in __rrr_socket_msg_head_validate actual size is %li stated size is %" PRIu32 "\n",
				expected_size, message->msg_size);
		ret = 1;
		goto out;
	}

	if (RRR_SOCKET_MSG_IS_CTRL(message)) {
		// Clear all known control flags
		rrr_u16 type = message->msg_type;
		type = type & ~(RRR_SOCKET_MSG_CTRL_F_ALL);
		if (type != 0) {
			RRR_MSG_0("Unknown control flags in message: %u\n", type);
			ret = 1;
			goto out;
		}
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message) || RRR_SOCKET_MSG_IS_RRR_MESSAGE(message) || RRR_SOCKET_MSG_IS_RRR_MESSAGE_ADDR(message)) {
		// OK
	}
	else {
		RRR_MSG_0("Received message with invalid type %u in __rrr_socket_msg_head_validate\n", message->msg_type);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_socket_msg_head_to_host_and_verify (
		struct rrr_socket_msg *message,
		ssize_t expected_size
) {
	message->header_crc32 = 0;
	message->data_crc32 = rrr_be32toh(message->data_crc32);
	message->msg_type = rrr_be16toh(message->msg_type);
	message->msg_size = rrr_be32toh(message->msg_size);
	message->msg_value = rrr_be32toh(message->msg_value);

	if (__rrr_socket_msg_head_validate (message, expected_size) != 0) {
		RRR_MSG_0("Received socket message was invalid in rrr_socket_msg_head_to_host\n");
		return 1;
	}

	return 0;
}

int rrr_socket_msg_get_target_size_and_check_checksum (
		ssize_t *target_size,
		const struct rrr_socket_msg *socket_msg,
		ssize_t buf_size
) {
	if (buf_size < (ssize_t) sizeof(struct rrr_socket_msg)) {
		return RRR_SOCKET_READ_INCOMPLETE;
	}

	*target_size = 0;

	if (crc32cmp (
			((const char*) socket_msg) + sizeof(socket_msg->header_crc32),
			sizeof(*socket_msg) - sizeof(socket_msg->header_crc32),
			rrr_be32toh(socket_msg->header_crc32)
	) != 0) {
		return RRR_SOCKET_SOFT_ERROR;
	}

	*target_size = rrr_be32toh(socket_msg->msg_size);

	return RRR_SOCKET_OK;
}

int rrr_socket_msg_check_data_checksum_and_length (
		struct rrr_socket_msg *message,
		ssize_t data_size
) {
	if (data_size < (ssize_t) sizeof(*message)) {
		RRR_BUG("rrr_socket_msg_checksum_check called with too short message\n");
	}
	if (message->msg_size != data_size) {
		RRR_MSG_0("Message size mismatch in rrr_socket_msg_checksum_check\n");
		return 1;
	}
	// HEX dumper
/*	for (unsigned int i = 0; i < data_size; i++) {
		unsigned char *buf = (unsigned char *) message;
		printf("%02x-", *(buf+i));
	}
	printf("\n");
	printf ("Check crc32 %lu data size %li\n", message->data_crc32, data_size - sizeof(*message));*/

	rrr_u32 checksum = message->data_crc32;

	char *data_begin = ((char *) message) + sizeof(*message);
	return crc32cmp(data_begin, data_size - sizeof(*message), checksum) != 0;
}
