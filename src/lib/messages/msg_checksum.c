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
#include <stdlib.h>

#include "../log.h"
#include "../allocator.h"

#include "msg_checksum.h"
#include "msg_head.h"

#include "../util/rrr_endian.h"
#include "../util/crc32.h"

void rrr_msg_checksum_and_to_network_endian (
		struct rrr_msg *message
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < message->msg_size; i++) {
		unsigned char *buf = (unsigned char *) message;
		printf("%02x-", *(buf+i));
	}
	printf("\n");*/

	message->header_crc32 = 0;
	message->data_crc32 = 0;

	char *data_begin = ((char *) message) + sizeof(*message);
	rrr_length data_size = message->msg_size - (rrr_length) sizeof(*message);

	if (data_size > 0) {
		message->data_crc32 = rrr_crc32buf(data_begin, data_size);
	}

//	printf ("Put crc32 %lu data size %li\n", message->data_crc32, message->network_size - sizeof(*message));

	message->msg_type = rrr_htobe16(message->msg_type);
	message->msg_size = rrr_htobe32(message->msg_size);
	message->msg_value = rrr_htobe32(message->msg_value);
	message->data_crc32 = rrr_htobe32(message->data_crc32);

	char *head_begin = ((char *) message) + sizeof(message->header_crc32);
	rrr_length head_size = (rrr_length) sizeof(*message) - (rrr_length) sizeof(message->header_crc32);

	message->header_crc32 = rrr_htobe32(rrr_crc32buf(head_begin, head_size));
}
