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

#ifndef VL_MESSAGES_H
#define VL_MESSAGES_H

#include "rrr_socket_msg.h"

#define MSG_TYPE_MSG 1
//#define MSG_TYPE_ACK 2
#define MSG_TYPE_TAG 2

#define MSG_TYPE_OK(msg) \
	((msg)->type >= MSG_TYPE_MSG && (msg)->type <= MSG_TYPE_TAG)

#define MSG_CLASS_POINT 1
#define MSG_CLASS_AVG 2
#define MSG_CLASS_MAX 3
#define MSG_CLASS_MIN 4
#define MSG_CLASS_INFO 10
#define MSG_CLASS_ARRAY 11

#define MSG_CLASS_OK(msg) \
	(((msg)->class >= MSG_CLASS_POINT && (msg)->class <= MSG_CLASS_MIN) || ((msg)->class >= MSG_CLASS_INFO && (msg)->class <= MSG_CLASS_ARRAY))

#define MSG_TYPE_MSG_STRING "MSG"
//#define MSG_TYPE_ACK_STRING "ACK"
#define MSG_TYPE_TAG_STRING "TAG"

#define MSG_CLASS_POINT_STRING "POINT"
#define MSG_CLASS_AVG_STRING "AVG"
#define MSG_CLASS_MAX_STRING "MAX"
#define MSG_CLASS_MIN_STRING "MIN"
#define MSG_CLASS_INFO_STRING "INFO"
#define MSG_CLASS_ARRAY_STRING "ARRAY"

#define MSG_IS_MSG(message)			((message)->type == MSG_TYPE_MSG)
//#define MSG_IS_ACK(message)			((message)->type == MSG_TYPE_ACK)
#define MSG_IS_TAG(message)			((message)->type == MSG_TYPE_TAG)

#define MSG_IS_POINT(message)		((message)->class == MSG_CLASS_POINT)
#define MSG_IS_INFO(message)		((message)->class == MSG_CLASS_INFO)
#define MSG_IS_ARRAY(message)		((message)->class == MSG_CLASS_ARRAY)

#define MSG_IS_MSG_POINT(message)	(MSG_IS_MSG(message) && MSG_IS_POINT(message))
#define MSG_IS_MSG_INFO(message)	(MSG_IS_MSG(message) && MSG_IS_INFO(message))
#define MSG_IS_MSG_ARRAY(message)	(MSG_IS_MSG(message) && MSG_IS_ARRAY(message))

#define MSG_TOTAL_SIZE(message)		((message)->msg_size)
#define MSG_TOPIC_LENGTH(message)	((message)->topic_length)
#define MSG_TOPIC_PTR(message)		((message)->data + 0)
#define MSG_DATA_LENGTH(message)	((message)->msg_size - (sizeof(*message) - 1) - (message)->topic_length)
#define MSG_DATA_PTR(message)		((message)->data + (message)->topic_length)

#define VL_MESSAGE_HEAD 	\
	vl_u16 type;			\
	vl_u16 type_flags;		\
	vl_u16 class;			\
	vl_u16 version;			\
	vl_u64 timestamp_from;	\
	vl_u64 timestamp_to;	\
	vl_u64 data_numeric;	\
	vl_u16 topic_length;	\
	vl_u16 reserved

struct vl_message {
	RRR_SOCKET_MSG_HEAD;
	VL_MESSAGE_HEAD;
	char data[1];
} __attribute__((packed));

static inline struct rrr_socket_msg *rrr_vl_message_safe_cast (struct vl_message *message) {
	struct rrr_socket_msg *ret = (struct rrr_socket_msg *) message;
	ret->msg_type = RRR_SOCKET_MSG_TYPE_VL_MESSAGE;
	ret->msg_size = MSG_TOTAL_SIZE(message);
	ret->msg_value = 0;
	return ret;
}
struct vl_message *message_new_reading (
	vl_u64 reading_millis,
	vl_u64 time
);
struct vl_message *message_new_array (
	vl_u64 time,
	vl_u16 topic_length,
	vl_u32 data_length
);
int message_new_empty (
		struct vl_message **final_result,
		vl_u16 type,
		vl_u16 type_flags,
		vl_u32 class,
		vl_u64 timestamp_from,
		vl_u64 timestamp_to,
		vl_u64 data_numeric,
		vl_u16 topic_length,
		vl_u32 data_length
);
int message_new_with_data (
		struct vl_message **final_result,
		vl_u16 type,
		vl_u16 type_flags,
		vl_u32 class,
		vl_u64 timestamp_from,
		vl_u64 timestamp_to,
		vl_u64 data_numeric,
		const char *topic,
		vl_u16 topic_length,
		const char *data,
		vl_u32 data_length
);
int message_to_string (
	char **final_target,
	struct vl_message *message
);
int message_to_host_and_verify (struct vl_message *message, ssize_t expected_size);
void message_prepare_for_network (struct vl_message *message);
struct vl_message *message_duplicate_no_data_with_size (
		const struct vl_message *message,
		ssize_t topic_length,
		ssize_t data_length
);
struct vl_message *message_duplicate (
		const struct vl_message *message
);
struct vl_message *message_duplicate_no_data (
		struct vl_message *message
);
int message_set_topic (
		struct vl_message **message,
		const char *topic,
		ssize_t topic_len
);

#endif
