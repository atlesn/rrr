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
#define MSG_TYPE_ACK 2
#define MSG_TYPE_TAG 3

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
#define MSG_TYPE_ACK_STRING "ACK"
#define MSG_TYPE_TAG_STRING "TAG"

#define MSG_CLASS_POINT_STRING "POINT"
#define MSG_CLASS_AVG_STRING "AVG"
#define MSG_CLASS_MAX_STRING "MAX"
#define MSG_CLASS_MIN_STRING "MIN"
#define MSG_CLASS_INFO_STRING "INFO"
#define MSG_CLASS_ARRAY_STRING "ARRAY"

#define MSG_IS_MSG(message)			(message->type == MSG_TYPE_MSG)
#define MSG_IS_ACK(message)			(message->type == MSG_TYPE_ACK)
#define MSG_IS_TAG(message)			(message->type == MSG_TYPE_TAG)

#define MSG_IS_POINT(message)		(message->class == MSG_CLASS_POINT)
#define MSG_IS_INFO(message)		(message->class == MSG_CLASS_INFO)
#define MSG_IS_ARRAY(message)		(message->class == MSG_CLASS_ARRAY)

#define MSG_IS_MSG_POINT(message)	(MSG_IS_MSG(message) && MSG_IS_POINT(message))
#define MSG_IS_MSG_INFO(message)	(MSG_IS_MSG(message) && MSG_IS_INFO(message))
#define MSG_IS_MSG_ARRAY(message)	(MSG_IS_MSG(message) && MSG_IS_ARRAY(message))

#define MSG_TOTAL_LENGTH(message)	(sizeof(*(message)) + (message)->length - 1)

#define VL_MESSAGE_HEAD 	\
	vl_u16 type;			\
	vl_u16 type_flags;		\
	vl_u32 class;			\
	vl_u64 timestamp_from;	\
	vl_u64 timestamp_to;	\
	vl_u64 data_numeric;	\
	vl_u32 length

struct vl_message {
	RRR_SOCKET_MSG_HEAD;
	VL_MESSAGE_HEAD;
	char data_[1];
} __attribute__((packed));

struct vl_message_type_head {
	uint16_t version;
	union {
		uint16_t endian_two;
		uint8_t endian_one;
	};
	char data_[1];
};

struct vl_message_array {
	RRR_SOCKET_MSG_HEAD;
	VL_MESSAGE_HEAD;
	struct vl_message_type_head type_head;
} __attribute__((packed));

static inline struct rrr_socket_msg *rrr_vl_message_safe_cast (struct vl_message *message) {
	struct rrr_socket_msg *ret = (struct rrr_socket_msg *) message;
	ret->msg_type = RRR_SOCKET_MSG_TYPE_VL_MESSAGE;
	ret->msg_size = sizeof(*message);
	ret->msg_value = 0;
	return ret;
}
struct vl_message *message_new_reading (
	vl_u64 reading_millis,
	vl_u64 time
);
struct vl_message *message_new_info (
	vl_u64 time,
	const char *msg_terminated
);
struct vl_message_array *message_new_array (
	vl_u64 time,
	vl_u32 length
);
int new_empty_message (
		struct vl_message **final_result,
		vl_u16 type,
		vl_u16 type_flags,
		vl_u32 class,
		vl_u64 timestamp_from,
		vl_u64 timestamp_to,
		vl_u64 data_numeric,
		vl_u32 data_size
);
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
);
void message_to_host (struct vl_message *message);
void message_prepare_for_network (struct vl_message *message);
struct vl_message *message_duplicate (struct vl_message *message);
int message_validate (const struct vl_message *message);

#endif
