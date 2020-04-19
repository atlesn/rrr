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

#ifndef RRR_MESSAGES_H
#define RRR_MESSAGES_H

#include "rrr_socket_msg.h"

#define MSG_TYPE_MSG 1
//#define MSG_TYPE_ACK 2
#define MSG_TYPE_TAG 2

#define MSG_CLASS_DATA 1
#define MSG_CLASS_ARRAY 11

#define MSG_TYPE_MSG_STRING "MSG"
#define MSG_TYPE_TAG_STRING "TAG"

#define MSG_CLASS_DATA_STRING "DATA"
#define MSG_CLASS_ARRAY_STRING "ARRAY"

#define MSG_TYPE(message)			((message)->type_and_class & 0x0f)
#define MSG_CLASS(message)			(((message)->type_and_class & 0xf0) >> 4)

#define MSG_SET_TYPE(message,n)		(message)->type_and_class = ((message)->type_and_class & 0xf0) | (n & 0x0f)
#define MSG_SET_CLASS(message,n)	(message)->type_and_class = ((message)->type_and_class & 0x0f) | (n << 4)

#define MSG_CLASS_OK(message) \
	((MSG_CLASS(message) == MSG_CLASS_DATA || MSG_CLASS(message) == MSG_CLASS_ARRAY))

#define MSG_TYPE_OK(message) \
	(MSG_TYPE(message) >= MSG_TYPE_MSG && MSG_TYPE(message) <= MSG_TYPE_TAG)

#define MSG_IS_MSG(message)			(MSG_TYPE(message) == MSG_TYPE_MSG)
//#define MSG_IS_ACK(message)			((message)->type == MSG_TYPE_ACK)
#define MSG_IS_TAG(message)			(MSG_TYPE(message) == MSG_TYPE_TAG)

#define MSG_IS_DATA(message)		(MSG_CLASS(message) == MSG_CLASS_DATA)
#define MSG_IS_ARRAY(message)		(MSG_CLASS(message) == MSG_CLASS_ARRAY)

#define MSG_IS_MSG_DATA(message)	(MSG_IS_MSG(message) && MSG_IS_DATA(message))
#define MSG_IS_MSG_ARRAY(message)	(MSG_IS_MSG(message) && MSG_IS_ARRAY(message))

#define MSG_TOTAL_SIZE(message)		((message)->msg_size)
#define MSG_TOPIC_LENGTH(message)	((message)->topic_length)
#define MSG_TOPIC_PTR(message)		((message)->data + 0)
#define MSG_DATA_LENGTH(message)	((message)->msg_size - (sizeof(*message) - 1) - (message)->topic_length)
#define MSG_DATA_PTR(message)		((message)->data + (message)->topic_length)

#define RRR_MESSAGE_HEAD 	\
	rrr_u64 timestamp;		\
	rrr_u8 type_and_class;	\
	rrr_u8 version;			\
	rrr_u16 topic_length

struct rrr_message {
	RRR_SOCKET_MSG_HEAD;
	RRR_MESSAGE_HEAD;
	char data[1];
} __attribute__((packed));

static inline struct rrr_socket_msg *rrr_message_safe_cast (struct rrr_message *message) {
	struct rrr_socket_msg *ret = (struct rrr_socket_msg *) message;
	ret->msg_type = RRR_SOCKET_MSG_TYPE_MESSAGE;
	ret->msg_size = MSG_TOTAL_SIZE(message);
	ret->msg_value = 0;
	return ret;
}
struct rrr_message *rrr_message_new_array (
	rrr_u64 time,
	rrr_u16 topic_length,
	rrr_u32 data_length
);
int rrr_message_new_empty (
		struct rrr_message **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		rrr_u16 topic_length,
		rrr_u32 data_length
);
int rrr_message_new_with_data (
		struct rrr_message **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		const char *topic,
		rrr_u16 topic_length,
		const char *data,
		rrr_u32 data_length
);
int rrr_message_to_string (
	char **final_target,
	struct rrr_message *message
);
int rrr_message_to_host_and_verify (struct rrr_message *message, ssize_t expected_size);
void rrr_message_prepare_for_network (struct rrr_message *message);
struct rrr_message *rrr_message_duplicate_no_data_with_size (
		const struct rrr_message *message,
		ssize_t topic_length,
		ssize_t data_length
);
struct rrr_message *rrr_message_duplicate (
		const struct rrr_message *message
);
struct rrr_message *rrr_message_duplicate_no_data (
		struct rrr_message *message
);
int rrr_message_set_topic (
		struct rrr_message **message,
		const char *topic,
		ssize_t topic_len
);

#endif
