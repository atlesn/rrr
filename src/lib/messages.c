/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <endian.h>

#include "messages.h"
#include "crc32.h"
#include "../global.h"

// {MSG|MSG_ACK|MSG_TAG}:{AVG|MAX|MIN|POINT|INFO}:{CRC32}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}

struct vl_message *message_new_reading (
		uint64_t reading_millis,
		uint64_t time
) {
	struct vl_message *res = malloc(sizeof(*res));

	char buf[64];
	sprintf (buf, "%" PRIu64, reading_millis);

	if (init_message (
			MSG_TYPE_MSG,
			MSG_CLASS_POINT,
			time,
			time,
			reading_millis,
			buf,
			strlen(buf),
			res
	) != 0) {
		free(res);
		VL_MSG_ERR ("Bug: Could not initialize message\n");
		exit (EXIT_FAILURE);
	}

	return res;
}

struct vl_message *message_new_info (
		uint64_t time,
		const char *msg_terminated
) {
	struct vl_message *res = malloc(sizeof(*res));

	if (init_message (
			MSG_TYPE_MSG,
			MSG_CLASS_INFO,
			time,
			time,
			0,
			msg_terminated,
			strlen(msg_terminated),
			res
	) != 0) {
		free(res);
		VL_MSG_ERR ("Bug: Could not initialize info message\n");
		exit (EXIT_FAILURE);
	}

	return res;
}

struct vl_message *message_new_array (
	uint64_t time,
	uint32_t length
) {
	struct vl_message *res = malloc(sizeof(*res));

	if (init_empty_message (
			MSG_TYPE_MSG,
			MSG_CLASS_ARRAY,
			time,
			time,
			0,
			length,
			res
	) != 0) {
		free(res);
		VL_MSG_ERR ("BUG: Could not initialize array message\n");
		exit (EXIT_FAILURE);
	}

	return res;
}

int find_string(const char *str, unsigned long int size, const char *search, const char **result) {
	unsigned long int search_length = strlen(search);

	if (search_length > size) {
		VL_MSG_ERR ("Message was to short\n");
		return 1;
	}
	if (strncmp(str, search, search_length) != 0) {
		return 1;
	}

	*result = str + strlen(search) + 1;

	return 0;
}

int find_number(const char *str, unsigned long int size, const char **end, uint64_t *result) {
	*end = memchr(str, ':', size);
	if (*end == NULL) {
		VL_MSG_ERR ("Missing delimeter in message while searching for number\n");
		return 1;
	}

	if (*end == str) {
		VL_MSG_ERR ("Missing number argument in message\n");
		return 1;
	}

	char tmp[MSG_TMP_SIZE];
	if (*end - str + 1 > MSG_TMP_SIZE) {
		VL_MSG_ERR ("Too long argument while searching for number in message\n");
		return 1;
	}

	strncpy(tmp, str, *end-str);
	tmp[*end-str] = '\0';

	printf ("Orig: '%s', Tmp: '%s'\n", str, tmp);

	char *endptr;
	*result = strtoull(tmp, &endptr, 10);
	if (*endptr != '\0') {
		VL_MSG_ERR ("Invalid characters in number argument of message\n");
		return 1;
	}

	*end = *end + 1;
	return 0;
}

int init_empty_message (
	unsigned long int type,
	unsigned long int class,
	uint64_t timestamp_from,
	uint64_t timestamp_to,
	uint64_t data_numeric,
	unsigned long int data_size,
	struct vl_message *result
) {
	memset(result, '\0', sizeof(*result));

	result->type = type;
	result->class = class;
	result->timestamp_from = timestamp_from;
	result->timestamp_to = timestamp_to;
	result->data_numeric = data_numeric;
	result->endian_two = MSG_ENDIAN_BYTES;

	// Always have a \0 at the end
	if (data_size + 1 > MSG_DATA_MAX_LENGTH) {
		VL_MSG_ERR ("Message length was too long (%lu vs %d)\n", data_size, MSG_DATA_MAX_LENGTH);
		return 1;
	}

	result->length = data_size;
	result->data[0] = '\0';

	return 0;
}

int init_message (
	unsigned long int type,
	unsigned long int class,
	uint64_t timestamp_from,
	uint64_t timestamp_to,
	uint64_t data_numeric,
	const char *data,
	unsigned long int data_size,
	struct vl_message *result
) {
	if (init_empty_message (
		type,
		class,
		timestamp_from,
		timestamp_to,
		data_numeric,
		data_size,
		result
	) != 0) {
		return 1;
	}

	memcpy (result->data, data, data_size);
	result->data[data_size+1] = '\0';

	return 0;
}
/*
int parse_message(const char *msg, unsigned long int size, struct vl_message *result) {
	const char *pos = msg;
	const char *end = msg + size;

	VL_DEBUG_MSG_3("Parse message: %s\n", msg);

	// {MSG|MSG_ACK|MSG_TAG}:{AVG|MAX|MIN|POINT|INFO}:{CRC32}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	if (find_string(pos, end - pos, MSG_TYPE_MSG_STRING, &pos) == 0) {
		result->type = MSG_TYPE_MSG;
	}
	else if (find_string(pos, end - pos, MSG_TYPE_ACK_STRING, &pos) == 0) {
		result->type = MSG_TYPE_ACK;
	}
	else if (find_string(pos, end - pos, MSG_TYPE_TAG_STRING, &pos) == 0) {
		result->type = MSG_TYPE_TAG;
	}
	else {
		char buf[16];
		snprintf(buf, 16, "%s", msg);
		VL_MSG_ERR ("Unknown message type '%s' of size %lu\n", buf, size);
		return 1;
	}

	// {AVG|MAX|MIN|POINT|INFO|ARRAY}:{CRC32}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	if (find_string (pos, end - pos, MSG_CLASS_AVG_STRING, &pos) == 0) {
		result->class = MSG_CLASS_AVG;
	}
	else if (find_string (pos, end - pos, MSG_CLASS_MAX_STRING, &pos) == 0) {
		result->class = MSG_CLASS_MAX;
	}
	else if (find_string (pos, end - pos, MSG_CLASS_MIN_STRING, &pos) == 0) {
		result->class = MSG_CLASS_MIN;
	}
	else if (find_string (pos, end - pos, MSG_CLASS_POINT_STRING, &pos) == 0) {
		result->class = MSG_CLASS_POINT;
	}
	else if (find_string (pos, end - pos, MSG_CLASS_INFO_STRING, &pos) == 0) {
		result->class = MSG_CLASS_INFO;
	}
	else if (find_string (pos, end - pos, MSG_CLASS_ARRAY_STRING, &pos) == 0) {
		result->class = MSG_CLASS_ARRAY;
	}
	else {
		VL_MSG_ERR ("Unknown message class\n");
		return 1;
	}

	// {CRC32}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	uint64_t tmp;
	VL_DEBUG_MSG_3("Parse message pos: %s\n", pos);
	if (find_number(pos, end-pos, &pos, &tmp) != 0) {
		VL_MSG_ERR ("Could not parse CRC32 of message '%s'\n", msg);
		return 1;
	}
	result->crc32 = tmp;

	// {LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	VL_DEBUG_MSG_3("Parse message pos: %s\n", pos);
	if (find_number(pos, end-pos, &pos, &tmp) != 0) {
		VL_MSG_ERR ("Could not parse length of message '%s'\n", msg);
		return 1;
	}
	result->length = tmp;

	// {TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	VL_DEBUG_MSG_3("Parse message pos: %s\n", pos);
	if (find_number(pos, end-pos, &pos, &result->timestamp_from) != 0) {
		VL_MSG_ERR ("Could not parse timestamp from of message '%s'\n", msg);
		return 1;
	}

	// {TIMESTAMP_TO}:{DATA}
	VL_DEBUG_MSG_3("Parse message pos: %s\n", pos);
	if (find_number(pos, end-pos, &pos, &result->timestamp_to) != 0) {
		VL_MSG_ERR ("Could not parse timestamp to of message '%s'\n", msg);
		return 1;
	}

	// {DATA}
	if (result->length > MSG_DATA_MAX_LENGTH) {
		VL_MSG_ERR ("Message data size was too long\n");
		return 1;
	}
	// Ignore this, just accept what's there if it's enough
	if (result->length != data_length) {
		VL_MSG_ERR ("Message reported data length did not match actual length\n");
		return 1;
	}

	memcpy(result->data, pos, result->length);

	return 0;
}

int message_to_string (
	struct vl_message *message,
	char *target,
	unsigned long int target_size
) {
	if (target_size < MSG_STRING_MAX_LENGTH) {
		VL_MSG_ERR ("Message target size was too small when converting to string\n");
		return 1;
	}

	const char *type;
	switch (message->type) {
	case MSG_TYPE_MSG:
		type = MSG_TYPE_MSG_STRING;
		break;
	case MSG_TYPE_ACK:
		type = MSG_TYPE_ACK_STRING;
		break;
	case MSG_TYPE_TAG:
		type = MSG_TYPE_TAG_STRING;
		break;
	default:
		VL_MSG_ERR ("Unknown type %" PRIu32 " in message while converting to string\n", message->type);
		return 1;
	}

	const char *class;
	switch (message->class) {
	case MSG_CLASS_POINT:
		class = MSG_CLASS_POINT_STRING;
		break;
	case MSG_CLASS_AVG:
		class = MSG_CLASS_AVG_STRING;
		break;
	case MSG_CLASS_MAX:
		class = MSG_CLASS_MAX_STRING;
		break;
	case MSG_CLASS_MIN:
		class = MSG_CLASS_MIN_STRING;
		break;
	case MSG_CLASS_INFO:
		class = MSG_CLASS_INFO_STRING;
		break;
	case MSG_CLASS_ARRAY:
		class = MSG_CLASS_ARRAY_STRING;
		break;
	default:
		VL_MSG_ERR ("Unknown class %" PRIu32 " in message while converting to string\n", message->class);
		return 1;
	}

	sprintf(target, "%s:%s:%" PRIu32 ":%" PRIu32 ":%" PRIu64 ":%" PRIu64 ":",
			type, class,
			message->crc32,
			message->length,
			message->timestamp_from,
			message->timestamp_to
	);

	int length = strlen(target);
	memcpy(target + length, message->data, message->length);
	target[length + message->length + 1] = '\0';

	return 0;
}
*/

void flip_endianess_64(uint64_t *value) {
	uint64_t result = 0;

	result |= (*value & 0x00000000000000ff) << 56;
	result |= (*value & 0x000000000000ff00) << 40;
	result |= (*value & 0x0000000000ff0000) << 24;
	result |= (*value & 0x00000000ff000000) << 8;
	result |= (*value & 0x000000ff00000000) >> 8;
	result |= (*value & 0x0000ff0000000000) >> 24;
	result |= (*value & 0x00ff000000000000) >> 40;
	result |= (*value & 0xff00000000000000) >> 56;

	*value = result;
}

void flip_endianess_32(uint32_t *value) {
	uint32_t result = 0;

	result |= (*value & 0x000000ff) << 24;
	result |= (*value & 0x0000ff00) << 8;
	result |= (*value & 0x00ff0000) >> 8;
	result |= (*value & 0xff000000) >> 24;

	*value = result;
}


void message_checksum (
	struct vl_message *message
) {
	if (((void*) &message->crc32) != ((void*) message)) {
		VL_MSG_ERR("CRC32 was not at beginning of message struct");
		exit(EXIT_FAILURE);
	}

	void *start_pos = ((void *) message) + sizeof(message->crc32);
	ssize_t checksum_data_length = sizeof(*message) - sizeof(message->crc32);

	uint32_t result = crc32buf((char *) start_pos, checksum_data_length);
	message->crc32 = result;
}

int message_checksum_check (
	struct vl_message *message
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < sizeof(*message); i++) {
		unsigned char *buf = (unsigned char *) message;
		VL_DEBUG_MSG_3("%x-", *(buf+i));
	}
	VL_DEBUG_MSG_3("\n");*/

	uint32_t checksum = message->crc32;
	if (MSG_IS_LE(message)) {
		checksum = le32toh(checksum);
	}
	else if (MSG_IS_BE(message)) {
		checksum = be32toh(checksum);
	}
	else {
		VL_MSG_ERR("Unknown endian bytes %u found in message\n", message->endian_two);
		return 1;
	}

	void *start_pos = ((void *) message) + sizeof(message->crc32);
	ssize_t checksum_data_length = sizeof(*message) - sizeof(message->crc32);

	int res = crc32cmp((char *) start_pos, checksum_data_length, checksum);

	return (res == 0 ? 0 : 1);
}

int message_convert_endianess (
		struct vl_message *message
) {
	if (MSG_IS_LE(message)) {
		message->endian_two = le16toh(message->endian_two);
		message->crc32 = le32toh(message->crc32);
		message->type = le32toh(message->type);
		message->class = le32toh(message->class);
		message->timestamp_from = le64toh(message->timestamp_from);
		message->timestamp_to = le64toh(message->timestamp_to);
		message->data_numeric = le64toh(message->data_numeric);
		message->length = le32toh(message->length);
	}
	else if (MSG_IS_BE(message)) {
		message->endian_two = be16toh(message->endian_two);
		message->crc32 = be32toh(message->crc32);
		message->type = be32toh(message->type);
		message->class = be32toh(message->class);
		message->timestamp_from = be64toh(message->timestamp_from);
		message->timestamp_to = be64toh(message->timestamp_to);
		message->data_numeric = be64toh(message->data_numeric);
		message->length = be32toh(message->length);
	}
	else {
		VL_MSG_ERR("Unknown endian bytes found in message\n");
		return 1;
	}

	return 0;
}
/*
struct vl_message {
	// Used by ipclient and ipserver for network transfer. CRC must be first
	// as we skip the first 4 bytes of the message when calculating.
	uint32_t crc32;
	union {
		uint16_t endian_two;
		uint8_t endian_one;
	};
	uint16_t reserved;

	uint32_t type;
	uint32_t class;
	uint64_t timestamp_from;
	uint64_t timestamp_to;
	uint64_t data_numeric;

	uint32_t length;
	char data[MSG_DATA_MAX_LENGTH+2];
} __attribute__((packed));
*/

void message_prepare_for_network (
	struct vl_message *message
) {
	message->crc32 = 0;
	message->data_numeric = 0;
	message->endian_two = MSG_ENDIAN_BYTES;

	message->endian_two = htobe16(message->endian_two);
	message->type = htobe32(message->type);
	message->class = htobe32(message->class);
	message->timestamp_from = htobe64(message->timestamp_from);
	message->timestamp_to = htobe64(message->timestamp_to);
	message->data_numeric = htobe64(message->data_numeric);
	message->length = htobe32(message->length);

	message_checksum(message);

	message->crc32 = htobe32(message->crc32);

	if (VL_DEBUGLEVEL_6) {
		VL_DEBUG_MSG("Message prepared for network: ");
		for (unsigned int i = 0; i < sizeof(*message); i++) {
			unsigned char *buf = (unsigned char *) message;
			VL_DEBUG_MSG("%x-", *(buf + i));
		}
		VL_DEBUG_MSG("\n");
	}
/*
	if (message_to_string (message, buf+1, buf_size) != 0) {
		VL_MSG_ERR ("ipclient: Error while converting message to string\n");
		return 1;
	}
*/
}

struct vl_message *message_duplicate(struct vl_message *message) {
	struct vl_message *ret = malloc(sizeof(*ret));
	memcpy(ret, message, sizeof(*ret));
	return ret;
}
