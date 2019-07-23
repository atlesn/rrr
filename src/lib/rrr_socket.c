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

#include <stddef.h>
#include <endian.h>

#include "crc32.h"
#include "rrr_socket.h"

int rrr_socket_msg_head_to_host (struct rrr_socket_msg *message) {
		if (RRR_SOCKET_MSG_IS_LE(message)) {
			message->endian_two = le16toh(message->endian_two);
			message->crc32 = le32toh(message->crc32);
			message->msg_type = le16toh(message->msg_type);
			message->msg_size = le32toh(message->msg_size);
		}
		else if (RRR_SOCKET_MSG_IS_BE(message)) {
			message->endian_two = be16toh(message->endian_two);
			message->crc32 = be32toh(message->crc32);
			message->msg_type = be16toh(message->msg_type);
			message->msg_size = be32toh(message->msg_size);
		}
		else {
			VL_MSG_ERR("Unknown endianess in rrr_socket_msg_head_to_host\n");
			return 1;
		}
		return 0;
}

void rrr_socket_msg_head_to_network (struct rrr_socket_msg *message, vl_u16 type, vl_u32 msg_size) {
	if (msg_size < sizeof(*message)) {
		VL_BUG("Size was too small in rrr_socket_msg_head_to_network\n");
	}
	message->crc32 = htobe32(message->crc32);
	message->endian_two = htobe16(RRR_SOCKET_MSG_ENDIAN_BYTES);
	message->msg_type = htobe16(type);
	message->msg_size = htobe32(msg_size);
}

void rrr_socket_msg_checksum (
	struct rrr_socket_msg *message,
	ssize_t total_size
) {
	if (total_size < sizeof(*message)) {
		VL_BUG("Size was too small in rrr_socket_msg_checksum\n");
	}
	if (((void*) &message->crc32) != ((void*) message)) {
		VL_BUG("CRC32 was not at beginning of message struct");
	}

	void *start_pos = ((void *) message) + sizeof(message->crc32);
	ssize_t checksum_data_length = total_size - sizeof(message->crc32);

	vl_u32 result = crc32buf((char *) start_pos, checksum_data_length);
	message->crc32 = htobe32(result);
}

int rrr_socket_msg_checksum_check (
	struct rrr_socket_msg *message,
	ssize_t total_size
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < sizeof(*message); i++) {
		unsigned char *buf = (unsigned char *) message;
		VL_DEBUG_MSG_3("%x-", *(buf+i));
	}
	VL_DEBUG_MSG_3("\n");*/

	vl_u32 checksum = message->crc32;
	if (RRR_SOCKET_MSG_IS_LE(message)) {
		checksum = le32toh(checksum);
	}
	else if (RRR_SOCKET_MSG_IS_BE(message)) {
		checksum = be32toh(checksum);
	}
	else {
		VL_MSG_ERR("Unknown endian bytes %u found in message\n", message->endian_two);
		return 1;
	}

	void *start_pos = ((void *) message) + sizeof(message->crc32);
	ssize_t checksum_data_length = total_size - sizeof(message->crc32);

	int res = crc32cmp((char *) start_pos, checksum_data_length, checksum);

	return (res == 0 ? 0 : 1);
}
