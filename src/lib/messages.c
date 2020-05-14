/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "utf8.h"
#include "rrr_endian.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "messages.h"
#include "log.h"

struct rrr_message *rrr_message_new_array (
	rrr_u64 time,
	rrr_u16 topic_length,
	rrr_u32 data_length
) {
	struct rrr_message *res;

	if (rrr_message_new_empty (
			(struct rrr_message **) &res,
			MSG_TYPE_MSG,
			MSG_CLASS_ARRAY,
			time,
			topic_length,
			data_length
	) != 0) {
		return NULL;
	}

	return res;
}

int rrr_message_new_empty (
		struct rrr_message **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		rrr_u16 topic_length,
		rrr_u32 data_length
) {
	ssize_t total_size = sizeof(struct rrr_message) - 1 + topic_length + data_length;
	// -1 because the char which points to the data holds 1 byte
	struct rrr_message *result = malloc(total_size);
	if (result == NULL) {
		RRR_MSG_ERR("Could not allocate memory in new_empty_message\n");
		return 1;
	}

	memset(result, '\0', total_size);

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) result,
			RRR_SOCKET_MSG_TYPE_MESSAGE,
			total_size,
			0
	);

	MSG_SET_TYPE(result, type);
	MSG_SET_CLASS(result, class);

	result->timestamp = timestamp;
	result->topic_length = topic_length;

	*final_result = result;

	return 0;
}

int rrr_message_new_with_data (
		struct rrr_message **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		const char *topic,
		rrr_u16 topic_length,
		const char *data,
		rrr_u32 data_length
) {
	if (rrr_message_new_empty (
			final_result,
			type,
			class,
			timestamp,
			topic_length,
			data_length
	) != 0) {
		return 1;
	}

	memcpy (MSG_TOPIC_PTR(*final_result), topic, topic_length);
	memcpy (MSG_DATA_PTR(*final_result), data, data_length);

	return 0;
}

int rrr_message_to_string (
	char **final_target,
	struct rrr_message *message
) {
	int ret = 0;

	char *target = malloc(128);
	if (target == NULL) {
		RRR_MSG_ERR("Could not allocate memory in message_to_string\n");
		ret = 1;
		goto out;
	}

	const char *type;
	switch (MSG_TYPE(message)) {
	case MSG_TYPE_MSG:
		type = MSG_TYPE_MSG_STRING;
		break;
	case MSG_TYPE_TAG:
		type = MSG_TYPE_TAG_STRING;
		break;
	default:
		RRR_MSG_ERR ("Unknown type %" PRIu32 " in message while converting to string\n", MSG_TYPE(message));
		ret = 1;
		goto out;
	}

	const char *class;
	switch (MSG_CLASS(message)) {
	case MSG_CLASS_DATA:
		class = MSG_CLASS_DATA_STRING;
		break;
	case MSG_CLASS_ARRAY:
		class = MSG_CLASS_ARRAY_STRING;
		break;
	default:
		RRR_MSG_ERR ("Unknown class %" PRIu32 " in message while converting to string\n", MSG_CLASS(message));
		ret = 1;
		goto out;
	}

	sprintf(target, "%s:%s:%" PRIu64,
			type,
			class,
			message->timestamp
	);

	*final_target = target;
	target = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(target);
	return ret;
}

void flip_endianess_64(rrr_u64 *value) {
	rrr_u64 result = 0;

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

void flip_endianess_32(rrr_u32 *value) {
	rrr_u32 result = 0;

	result |= (*value & 0x000000ff) << 24;
	result |= (*value & 0x0000ff00) << 8;
	result |= (*value & 0x00ff0000) >> 8;
	result |= (*value & 0xff000000) >> 24;

	*value = result;
}

static int __message_validate (const struct rrr_message *message){
	int ret = 0;

	if (message->msg_size < sizeof(*message) - 1 ||
			MSG_TOTAL_SIZE(message) != message->msg_size
	) {
		RRR_MSG_ERR("Received a message in message_validate with invalid header size fields (%" PRIu32 " and %" PRIu32 ")\n",
				message->msg_size, MSG_TOTAL_SIZE(message));
		ret = 1;
		goto out;
	}
	if (!MSG_CLASS_OK(message)) {
		RRR_MSG_ERR("Invalid class %u in message to message_validate\n", MSG_CLASS(message));
		ret = 1;
	}
	if (!MSG_TYPE_OK(message)) {
		RRR_MSG_ERR("Invalid type %u in message to message_validate\n", MSG_TYPE(message));
		ret = 1;
	}
	if (rrr_utf8_validate(MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message)) != 0) {
		RRR_MSG_ERR("Invalid topic for message in message_validate, not valid UTF-8\n");
		ret = 1;
	}

	out:
	return ret;
}

int rrr_message_to_host_and_verify (struct rrr_message *message, ssize_t expected_size) {
	if (expected_size < ((ssize_t) sizeof(*message)) - 1) {
		RRR_MSG_ERR("Message was too short in message_to_host_and_verify\n");
		return 1;
	}
	message->timestamp = be64toh(message->timestamp);
	message->topic_length = be16toh(message->topic_length);

	if (MSG_TOTAL_SIZE(message) != (unsigned int) expected_size) {
		RRR_MSG_ERR("Size mismatch of message in message_to_host_and_verify actual size was %li stated size was %u\n",
				expected_size, MSG_TOTAL_SIZE(message));
		return 1;
	}

	return __message_validate(message);
}

void rrr_message_prepare_for_network (struct rrr_message *message) {
	MSG_TO_BE(message);

	if (RRR_DEBUGLEVEL_6) {
		RRR_DBG("Message prepared for network: ");
		for (unsigned int i = 0; i < sizeof(*message); i++) {
			unsigned char *buf = (unsigned char *) message;
			RRR_DBG("%x-", *(buf + i));
		}
		RRR_DBG("\n");
	}
/*
	if (message_to_string (message, buf+1, buf_size) != 0) {
		VL_MSG_ERR ("ipclient: Error while converting message to string\n");
		return 1;
	}
*/
}

struct rrr_message *rrr_message_duplicate_no_data_with_size (
		const struct rrr_message *message,
		ssize_t topic_length,
		ssize_t data_length
) {
	ssize_t new_total_size = (sizeof (struct rrr_message) - 1 + topic_length + data_length);

	struct rrr_message *ret = malloc(new_total_size);
	if (ret == NULL) {
		RRR_MSG_ERR("Could not allocate memory in message_duplicate\n");
		return NULL;
	}

	memset(ret, '\0', new_total_size);
	memcpy(ret, message, sizeof(*ret) - 2);

	ret->topic_length = topic_length;
	ret->msg_size = new_total_size;

	return ret;
}

struct rrr_message *rrr_message_duplicate (
		const struct rrr_message *message
) {
	struct rrr_message *ret = malloc(MSG_TOTAL_SIZE(message));
	if (ret == NULL) {
		RRR_MSG_ERR("Could not allocate memory in message_duplicate\n");
		return NULL;
	}
	memcpy(ret, message, MSG_TOTAL_SIZE(message));
	return ret;
}

struct rrr_message *rrr_message_duplicate_no_data (
		struct rrr_message *message
) {
	ssize_t new_size = sizeof(struct rrr_message) - 1 + MSG_TOPIC_LENGTH(message);
	struct rrr_message *ret = malloc(new_size);
	if (ret == NULL) {
		RRR_MSG_ERR("Could not allocate memory in message_duplicate\n");
		return NULL;
	}
	memcpy(ret, message, new_size);
	ret->msg_size = new_size;
	return ret;
}

int rrr_message_set_topic (
		struct rrr_message **message,
		const char *topic,
		ssize_t topic_len
) {
	struct rrr_message *ret = rrr_message_duplicate_no_data_with_size(*message, topic_len, MSG_DATA_LENGTH(*message));
	if (ret == NULL) {
		RRR_MSG_ERR("Could not allocate memory in message_set_topic\n");
		return 1;
	}

	memcpy(MSG_TOPIC_PTR(ret), topic, topic_len);
	memcpy(MSG_DATA_PTR(ret), MSG_DATA_PTR(*message), MSG_DATA_LENGTH(*message));

	free(*message);
	*message = ret;

	return 0;
}

int rrr_message_timestamp_compare (struct rrr_message *message_a, struct rrr_message *message_b) {
	// Assume network order if crc32 is set
	uint64_t timestamp_a = (message_a->header_crc32 != 0 ? be64toh(message_a->timestamp) : message_a->timestamp);
	uint64_t timestamp_b = (message_b->header_crc32 != 0 ? be64toh(message_b->timestamp) : message_b->timestamp);

	return (timestamp_a > timestamp_b) - (timestamp_a < timestamp_b);
}

int rrr_message_timestamp_compare_void (void *message_a, void *message_b) {
	return rrr_message_timestamp_compare(message_a, message_b);
}
