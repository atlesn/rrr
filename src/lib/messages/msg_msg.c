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

#include "../log.h"
#include "../allocator.h"

#include "msg.h"
#include "msg_msg.h"
#include "../allocator.h"
#include "../rrr_types.h"
#include "../string_builder.h"
#include "../util/utf8.h"
#include "../util/rrr_endian.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"
#include "../mqtt/mqtt_topic.h"

struct rrr_msg_msg *rrr_msg_msg_new_array (
	rrr_u64 time,
	rrr_u16 topic_length,
	rrr_u32 data_length
) {
	struct rrr_msg_msg *res;

	if (rrr_msg_msg_new_empty (
			(struct rrr_msg_msg **) &res,
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

int rrr_msg_msg_new_empty (
		struct rrr_msg_msg **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		rrr_u16 topic_length,
		rrr_u32 data_length
) {
	ssize_t total_size = sizeof(struct rrr_msg_msg) - 1 + topic_length + data_length;
	// -1 because the char which points to the data holds 1 byte
	struct rrr_msg_msg *result = rrr_allocate_group(total_size, RRR_ALLOCATOR_GROUP_MSG);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in new_empty_message\n");
		return 1;
	}

	memset(result, '\0', total_size);

	rrr_msg_populate_head (
			(struct rrr_msg *) result,
			RRR_MSG_TYPE_MESSAGE,
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

int rrr_msg_msg_new_with_data (
		struct rrr_msg_msg **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		const char *topic,
		rrr_u16 topic_length,
		const char *data,
		rrr_u32 data_length
) {
	if (rrr_msg_msg_new_empty (
			final_result,
			type,
			class,
			timestamp,
			topic_length,
			data_length
	) != 0) {
		return 1;
	}

	if (topic_length > 0 && topic != NULL) {
		memcpy (MSG_TOPIC_PTR(*final_result), topic, topic_length);
	}
	if (data_length > 0 && data != 0) {
		memcpy (MSG_DATA_PTR(*final_result), data, data_length);
	}

	return 0;
}

struct rrr_msg_msg_new_with_data_nullsafe_callback_data {
	struct rrr_msg_msg **final_result;
	rrr_u8 type;
	rrr_u8 class;
	rrr_u64 timestamp;
	const char *topic;
	rrr_u16 topic_length;
};

static int __rrr_msg_msg_new_with_data_nullsafe_callback (
		const void *str,
		rrr_length len,
		void *arg
) {
	struct rrr_msg_msg_new_with_data_nullsafe_callback_data *callback_data = arg;
	return rrr_msg_msg_new_with_data (
			callback_data->final_result,
			callback_data->type,
			callback_data->class,
			callback_data->timestamp,
			callback_data->topic,
			callback_data->topic_length,
			str,
			len
	);
}

int rrr_msg_msg_new_with_data_nullsafe (
		struct rrr_msg_msg **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		const char *topic,
		rrr_u16 topic_length,
		const struct rrr_nullsafe_str *str
) {
	struct rrr_msg_msg_new_with_data_nullsafe_callback_data callback_data = {
			final_result,
			type,
			class,
			timestamp,
			topic,
			topic_length
	};
	return rrr_nullsafe_str_with_raw_do_const (
			str,
			__rrr_msg_msg_new_with_data_nullsafe_callback,
			&callback_data
	);
}

int rrr_msg_msg_to_string (
	char **final_target,
	const struct rrr_msg_msg *message
) {
	int ret = 0;

	char *target = rrr_allocate(128);
	if (target == NULL) {
		RRR_MSG_0("Could not allocate memory in message_to_string\n");
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
		RRR_MSG_0 ("Unknown type %" PRIu32 " in message while converting to string\n", MSG_TYPE(message));
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
		RRR_MSG_0 ("Unknown class %" PRIu32 " in message while converting to string\n", MSG_CLASS(message));
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

static int __message_validate (const struct rrr_msg_msg *message){
	int ret = 0;

	if (message->msg_size < sizeof(*message) - 1 ||
			MSG_TOTAL_SIZE(message) != message->msg_size
	) {
		RRR_DBG_1("Received a message in message_validate with invalid header size fields (%" PRIu32 " and %" PRIu32 ")\n",
				message->msg_size, MSG_TOTAL_SIZE(message));
		ret = 1;
		goto out;
	}
	if (!MSG_CLASS_OK(message)) {
		RRR_DBG_1("Invalid class %u in message to message_validate\n", MSG_CLASS(message));
		ret = 1;
	}
	if (!MSG_TYPE_OK(message)) {
		RRR_DBG_1("Invalid type %u in message to message_validate\n", MSG_TYPE(message));
		ret = 1;
	}
	if (rrr_utf8_validate(MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message)) != 0) {
		RRR_DBG_1("Invalid topic for message in message_validate, not valid UTF-8\n");
		ret = 1;
	}

	out:
	return ret;
}

int rrr_msg_msg_to_host_and_verify (struct rrr_msg_msg *message, rrr_biglength expected_size) {
	if (expected_size < sizeof(*message) - 1) {
		RRR_DBG_1("Message was too short in message_to_host_and_verify\n");
		return 1;
	}

	if (RRR_DEBUGLEVEL_6) {
		struct rrr_string_builder str_tmp = {0};
		for (unsigned int i = 0; i < MSG_TOTAL_SIZE(message); i++) {
			unsigned char *buf = (unsigned char *) message;
			rrr_string_builder_append_format(&str_tmp, "%02x-", *(buf + i));
		}
		RRR_DBG("Message from network: %s\n", rrr_string_builder_buf(&str_tmp));
		rrr_string_builder_clear(&str_tmp);
	}

	message->timestamp = rrr_be64toh(message->timestamp);
	message->topic_length = rrr_be16toh(message->topic_length);

	if (MSG_TOTAL_SIZE(message) != expected_size) {
		RRR_DBG_1("Size mismatch of message in message_to_host_and_verify actual size was %" PRIrrrbl " stated size was %u\n",
				expected_size, MSG_TOTAL_SIZE(message));
		return 1;
	}

	return __message_validate(message);
}

void rrr_msg_msg_prepare_for_network (struct rrr_msg_msg *message) {
	MSG_TO_BE(message);

	if (RRR_DEBUGLEVEL_6) {
		struct rrr_string_builder str_tmp = {0};
		for (unsigned int i = 0; i < MSG_TOTAL_SIZE(message); i++) {
			unsigned char *buf = (unsigned char *) message;
			rrr_string_builder_append_format(&str_tmp, "%02x-", *(buf + i));
		}
		RRR_DBG("Message prepared for network: %s\n", rrr_string_builder_buf(&str_tmp));
		rrr_string_builder_clear(&str_tmp);
	}
/*
	if (message_to_string (message, buf+1, buf_size) != 0) {
		VL_MSG_0 ("ipclient: Error while converting message to string\n");
		return 1;
	}
*/
}

struct rrr_msg_msg *rrr_msg_msg_duplicate_no_data_with_size (
		const struct rrr_msg_msg *message,
		ssize_t topic_length,
		ssize_t data_length
) {
	ssize_t new_total_size = (sizeof (struct rrr_msg_msg) - 1 + topic_length + data_length);

	struct rrr_msg_msg *ret = rrr_allocate_group(new_total_size, RRR_ALLOCATOR_GROUP_MSG);
	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory in message_duplicate\n");
		return NULL;
	}

	memset(ret, '\0', new_total_size);
	memcpy(ret, message, sizeof(*ret) - 2);

	ret->topic_length = topic_length;
	ret->msg_size = new_total_size;

	return ret;
}

struct rrr_msg_msg *rrr_msg_msg_duplicate (
		const struct rrr_msg_msg *message
) {
	struct rrr_msg_msg *ret = rrr_allocate_group(MSG_TOTAL_SIZE(message), RRR_ALLOCATOR_GROUP_MSG);
	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory in message_duplicate\n");
		return NULL;
	}
	memcpy(ret, message, MSG_TOTAL_SIZE(message));
	return ret;
}

struct rrr_msg_msg *rrr_msg_msg_duplicate_no_data (
		struct rrr_msg_msg *message
) {
	ssize_t new_size = sizeof(struct rrr_msg_msg) - 1 + MSG_TOPIC_LENGTH(message);
	struct rrr_msg_msg *ret = rrr_allocate_group(new_size, RRR_ALLOCATOR_GROUP_MSG);
	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory in message_duplicate\n");
		return NULL;
	}
	memcpy(ret, message, new_size);
	ret->msg_size = new_size;
	return ret;
}

int rrr_msg_msg_topic_set (
		struct rrr_msg_msg **message,
		const char *topic,
		ssize_t topic_len
) {
	struct rrr_msg_msg *ret = rrr_msg_msg_duplicate_no_data_with_size(*message, topic_len, MSG_DATA_LENGTH(*message));
	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory in message_set_topic\n");
		return 1;
	}

	memcpy(MSG_TOPIC_PTR(ret), topic, topic_len);
	memcpy(MSG_DATA_PTR(ret), MSG_DATA_PTR(*message), MSG_DATA_LENGTH(*message));

	rrr_free(*message);
	*message = ret;

	return 0;
}

int rrr_msg_msg_topic_get (
		char **result,
		const struct rrr_msg_msg *message
) {
	if ((*result = rrr_allocate(MSG_TOPIC_LENGTH(message) + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_msg_msg_topic_get\n");
		return 1;
	}

	if (MSG_TOPIC_LENGTH(message) > 0) {
		memcpy(*result, MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message));
	}

	*((*result) + MSG_TOPIC_LENGTH(message)) = '\0';

	return 0;
}

int rrr_msg_msg_topic_equals (
		const struct rrr_msg_msg *message,
		const char *topic
) {
	const size_t len_a = MSG_TOPIC_LENGTH(message);
	const size_t len_b = strlen(topic);

	if (len_a != len_b) {
		return 0;
	}

	if (len_a == 0) {
		return 1;
	}

	// Return 1 for equals
	return (memcmp(MSG_TOPIC_PTR(message), topic, len_a) == 0);
}

int rrr_msg_msg_topic_match (
		int *does_match,
		const struct rrr_msg_msg *message,
		const struct rrr_mqtt_topic_token *filter_first_token
) {
	int ret = 0;

	char *topic_tmp = NULL;

	*does_match = 0;

	struct rrr_mqtt_topic_token *entry_first_token = NULL;

	if (rrr_mqtt_topic_validate_name_with_end (
			MSG_TOPIC_PTR(message),
			MSG_TOPIC_PTR(message) + MSG_TOPIC_LENGTH(message)
	) != 0) {
		RRR_MSG_0("Warning: Invalid syntax found in message while matching topic of length %u\n", MSG_TOPIC_LENGTH(message));
		ret = 0;
		goto out;
	}

	if (rrr_mqtt_topic_tokenize_with_end (
			&entry_first_token,
			MSG_TOPIC_PTR(message),
			MSG_TOPIC_PTR(message) + MSG_TOPIC_LENGTH(message)
	) != 0) {
		RRR_MSG_0("Tokenizing of topic failed in rrr_msg_msg_topic_match\n");
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_topic_match_tokens_recursively(filter_first_token, entry_first_token) == RRR_MQTT_TOKEN_MATCH) {
		*does_match = 1;
	}

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	rrr_mqtt_topic_token_destroy(entry_first_token);
	return ret;
}

int rrr_msg_msg_timestamp_compare (struct rrr_msg_msg *message_a, struct rrr_msg_msg *message_b) {
	// Assume network order if crc32 is set
	uint64_t timestamp_a = (message_a->header_crc32 != 0 ? rrr_be64toh(message_a->timestamp) : message_a->timestamp);
	uint64_t timestamp_b = (message_b->header_crc32 != 0 ? rrr_be64toh(message_b->timestamp) : message_b->timestamp);

	return (timestamp_a > timestamp_b) - (timestamp_a < timestamp_b);
}

int rrr_msg_msg_timestamp_compare_void (void *message_a, void *message_b) {
	return rrr_msg_msg_timestamp_compare(message_a, message_b);
}

int rrr_msg_msg_ttl_ok (const struct rrr_msg_msg *msg, uint64_t ttl) {
	uint64_t limit = rrr_time_get_64() - ttl;
	if (msg->timestamp < limit) {
		return 0;
	}
	return 1;
}
