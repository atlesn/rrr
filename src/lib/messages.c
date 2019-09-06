/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#include "rrr_socket.h"
#include "messages.h"
#include "../global.h"

// {MSG|MSG_ACK|MSG_TAG}:{AVG|MAX|MIN|POINT|INFO}:{CRC32}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}

struct vl_message *message_new_reading (
		vl_u64 reading_millis,
		vl_u64 time
) {
	struct vl_message *res;

	char buf[64];
	sprintf (buf, "%" PRIu64, reading_millis);

	if (new_message (
			&res,
			MSG_TYPE_MSG,
			0,
			MSG_CLASS_POINT,
			time,
			time,
			reading_millis,
			buf,
			strlen(buf)
	) != 0) {
		return NULL;
	}

	return res;
}

struct vl_message *message_new_info (
		vl_u64 time,
		const char *msg_terminated
) {
	struct vl_message *res;

	if (new_message (
			&res,
			MSG_TYPE_MSG,
			0,
			MSG_CLASS_INFO,
			time,
			time,
			0,
			msg_terminated,
			strlen(msg_terminated) + 1
	) != 0) {
		return NULL;
	}

	return res;
}

struct vl_message_array *message_new_array (
	vl_u64 time,
	vl_u32 length
) {
	struct vl_message_array *res;

	if (new_empty_message (
			(struct vl_message **) &res,
			MSG_TYPE_MSG,
			0,
			MSG_CLASS_ARRAY,
			time,
			time,
			0,
			length + sizeof(res->type_head) - 1
	) != 0) {
		return NULL;
	}

	return res;
}
/*
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

int find_number(const char *str, unsigned long int size, const char **end, vl_u64 *result) {
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
*/
int new_empty_message (
		struct vl_message **final_result,
		vl_u16 type,
		vl_u16 type_flags,
		vl_u32 class,
		vl_u64 timestamp_from,
		vl_u64 timestamp_to,
		vl_u64 data_numeric,
		vl_u32 data_size
) {
	// -1 because the char which points to the data holds 1 byte
	struct vl_message *result = malloc(sizeof(*result) + data_size - 1);
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in new_empty_message\n");
		return 1;
	}

	memset(result, '\0', sizeof(*result) + data_size - 1);

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) result,
			RRR_SOCKET_MSG_TYPE_VL_MESSAGE,
			sizeof(struct vl_message) + data_size - 1,
			0
	);

	result->type = type;
	result->type_flags = type_flags;
	result->class = class;
	result->timestamp_from = timestamp_from;
	result->timestamp_to = timestamp_to;
	result->data_numeric = data_numeric;
	result->length = data_size;

	*final_result = result;

	return 0;
}

int new_message (
		struct vl_message **final_result,
		vl_u16 type,
		vl_u16 type_flags,
		vl_u32 class,
		vl_u64 timestamp_from,
		vl_u64 timestamp_to,
		vl_u64 data_numeric,
		const char *data,
		vl_u32 data_size
) {
	if (new_empty_message (
			final_result,
			type,
			type_flags,
			class,
			timestamp_from,
			timestamp_to,
			data_numeric,
			data_size
	) != 0) {
		return 1;
	}

	memcpy ((*final_result)->data_, data, data_size);

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
	vl_native_64 tmp;
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

void flip_endianess_64(vl_u64 *value) {
	vl_u64 result = 0;

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

void flip_endianess_32(vl_u32 *value) {
	vl_u32 result = 0;

	result |= (*value & 0x000000ff) << 24;
	result |= (*value & 0x0000ff00) << 8;
	result |= (*value & 0x00ff0000) >> 8;
	result |= (*value & 0xff000000) >> 24;

	*value = result;
}

void message_to_host (struct vl_message *message) {
	message->type = be16toh(message->type);
	message->type_flags = be16toh(message->type_flags);
	message->class = be32toh(message->class);
	message->timestamp_from = be64toh(message->timestamp_from);
	message->timestamp_to = be64toh(message->timestamp_to);
	message->data_numeric = be64toh(message->data_numeric);
	message->length = be32toh(message->length);
}

void message_prepare_for_network (struct vl_message *message) {
	message->type = htobe16(message->type);
	message->type_flags = htobe16(message->type);
	message->class = htobe32(message->class);
	message->timestamp_from = htobe64(message->timestamp_from);
	message->timestamp_to = htobe64(message->timestamp_to);
	message->data_numeric = htobe64(message->data_numeric);
	message->length = htobe32(message->length);

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
	struct vl_message *ret = malloc(sizeof(*ret) + message->length - 1);
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory in message_duplicate\n");
		return NULL;
	}
	memcpy(ret, message, sizeof(*ret) + message->length - 1);
	return ret;
}

int message_validate (const struct vl_message *message){
	int ret = 0;

	if (message->msg_size < sizeof(*message) - 1) {
		VL_MSG_ERR("Received a message in message_validate with invalid header size field (%u)\n", message->msg_size);
		ret = 1;
	}
	if (!MSG_CLASS_OK(message)) {
		VL_MSG_ERR("Invalid class %u in message to message_validate\n", message->class);
		ret = 1;
	}
	if (!MSG_TYPE_OK(message)) {
		VL_MSG_ERR("Invalid type %u in message to message_validate\n", message->type);
		ret = 1;
	}

	return ret;
}
