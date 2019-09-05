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

#include <endian.h>

#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "../global.h"
#include "crc32.h"

void rrr_socket_msg_populate_head (
		struct rrr_socket_msg *message,
		vl_u16 type,
		vl_u32 msg_size,
		vl_u64 value
) {
	if (msg_size < sizeof(*message)) {
		VL_BUG("Size was too small in rrr_socket_msg_head_to_network\n");
	}

	message->network_size = msg_size;
	message->msg_type = type;
	message->msg_size = msg_size;
	message->msg_value = value;
}

void rrr_socket_msg_checksum_and_to_network_endian (
	struct rrr_socket_msg *message
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < total_size; i++) {
		unsigned char *buf = (unsigned char *) message;
		printf("%x-", *(buf+i));
	}
	printf("\n");*/

	message->header_crc32 = 0;
	message->data_crc32 = 0;

	char *data_begin = ((char *) message) + sizeof(*message);
	ssize_t data_size = message->network_size - sizeof(*message);

	if (data_size > 0) {
		message->data_crc32 = crc32buf(data_begin, data_size);
	}

	message->network_size = htobe32(message->network_size);
	message->msg_type = htobe16(message->msg_type);
	message->msg_size = htobe32(message->msg_size);
	message->msg_value = htobe64(message->msg_value);
	message->data_crc32 = htobe64(message->data_crc32);

	char *head_begin = ((char *) message) + sizeof(message->header_crc32);
	ssize_t head_size = sizeof(*message) - sizeof(message->header_crc32);

	message->header_crc32 = htobe32(crc32buf(head_begin, head_size));
}

void rrr_socket_msg_head_to_host (struct rrr_socket_msg *message) {
	message->header_crc32 = 0;
	message->network_size = be32toh(message->network_size);
	message->data_crc32 = be32toh(message->data_crc32);
	message->msg_type = be16toh(message->msg_type);
	message->msg_size = be32toh(message->msg_size);
	message->msg_value = be64toh(message->msg_value);
}

int rrr_socket_msg_get_packet_target_size (struct rrr_socket_read_session *read_session, void *arg) {
	if (read_session->rx_buf_wpos < (ssize_t) sizeof(struct rrr_socket_msg)) {
		return RRR_SOCKET_READ_INCOMPLETE;
	}

	(void)(arg);

	struct rrr_socket_msg *socket_msg = (struct rrr_socket_msg *) read_session->rx_buf_start;

	if (crc32cmp (
			((char*) socket_msg) + sizeof(socket_msg->header_crc32),
			sizeof(*socket_msg) - sizeof(socket_msg->header_crc32),
			be32toh(socket_msg->header_crc32)
	) != 0) {
		VL_MSG_ERR("Warning: Header checksum of message failed in __ip_get_packet_target_size\n");
		return RRR_SOCKET_SOFT_ERROR;
	}

	read_session->target_size = be32toh(socket_msg->network_size);

	return RRR_SOCKET_OK;
}

int rrr_socket_msg_checksum_check (
	struct rrr_socket_msg *message
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < total_size; i++) {
		unsigned char *buf = (unsigned char *) message;
		printf("%x-", *(buf+i));
	}
	printf("\n");

	printf ("Check crc32 %lu\n", message->crc32);*/

	vl_u32 checksum = be32toh(message->data_crc32);

	char *data_begin = ((char *) message) + sizeof(*message);
	ssize_t data_size = message->network_size - sizeof(*message);

	return crc32cmp(data_begin, data_size, checksum) != 0;
}

int rrr_socket_msg_head_validate (struct rrr_socket_msg *message) {
	int ret = 0;

	if (RRR_SOCKET_MSG_IS_CTRL(message)) {
		// Clear all known control flags
		vl_u16 type = message->msg_type;
		type = type & ~(RRR_SOCKET_MSG_CTRL_F_ALL);
		if (type != 0) {
			VL_MSG_ERR("Unknown control flags in message: %u\n", type);
			ret = 1;
		}
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message) || RRR_SOCKET_MSG_IS_VL_MESSAGE(message)) {
		ret = 0;
	}
	else {
		ret = 1;
	}

	if (ret != 0) {
		VL_MSG_ERR("Received message with invalid type %u in rrr_socket_msg_head_validate\n", message->msg_type);
		ret = 1;
	}

	return ret;
}
