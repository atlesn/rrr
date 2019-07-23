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

#include "rrr_socket.h"

#define MSG_TYPE_MSG 1
#define MSG_TYPE_ACK 2
#define MSG_TYPE_TAG 3

#define MSG_CLASS_POINT 1
#define MSG_CLASS_AVG 2
#define MSG_CLASS_MAX 3
#define MSG_CLASS_MIN 4
#define MSG_CLASS_INFO 10
#define MSG_CLASS_ARRAY 11

#define MSG_TYPE_MSG_STRING "MSG"
#define MSG_TYPE_ACK_STRING "ACK"
#define MSG_TYPE_TAG_STRING "TAG"

#define MSG_CLASS_POINT_STRING "POINT"
#define MSG_CLASS_AVG_STRING "AVG"
#define MSG_CLASS_MAX_STRING "MAX"
#define MSG_CLASS_MIN_STRING "MIN"
#define MSG_CLASS_INFO_STRING "INFO"
#define MSG_CLASS_ARRAY_STRING "ARRAY"

#define MSG_EXTRA_MAX_LENGTH 8
#define MSG_DATA_MAX_LENGTH 1024
#define MSG_DATA_MAX_LENGTH_STR "1024"

#define MSG_SEND_MAX_LENGTH (6 + 10*2 + 32*5 + MSG_DATA_MAX_LENGTH + 1)

#define MSG_TMP_SIZE 64

#define MSG_IS_MSG(message)			(message->type == MSG_TYPE_MSG)
#define MSG_IS_ACK(message)			(message->type == MSG_TYPE_ACK)
#define MSG_IS_TAG(message)			(message->type == MSG_TYPE_TAG)

#define MSG_IS_POINT(message)		(message->class == MSG_CLASS_POINT)
#define MSG_IS_INFO(message)		(message->class == MSG_CLASS_INFO)
#define MSG_IS_ARRAY(message)		(message->class == MSG_CLASS_ARRAY)

#define MSG_IS_MSG_POINT(message)	(MSG_IS_MSG(message) && MSG_IS_POINT(message))
#define MSG_IS_MSG_INFO(message)	(MSG_IS_MSG(message) && MSG_IS_INFO(message))
#define MSG_IS_MSG_ARRAY(message)	(MSG_IS_MSG(message) && MSG_IS_ARRAY(message))

struct vl_message {
	RRR_SOCKET_MSG_HEAD;

	vl_u32 type;
	vl_u32 class;
	vl_u64 timestamp_from;
	vl_u64 timestamp_to;
	vl_u64 data_numeric;

	vl_u32 length;
	char data[MSG_DATA_MAX_LENGTH+2];
	char extra[MSG_EXTRA_MAX_LENGTH];
} __attribute__((packed));

static inline struct rrr_socket_msg *rrr_vl_message_safe_cast (struct vl_message *message) {
	struct rrr_socket_msg *ret = (struct rrr_socket_msg *) message;
	ret->msg_type = RRR_SOCKET_MSG_TYPE_VL_MESSAGE;
	ret->msg_size = sizeof(*message);
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
struct vl_message *message_new_array (
	vl_u64 time,
	vl_u32 length
);
int init_empty_message (
	unsigned long int type,
	unsigned long int class,
	vl_u64 timestamp_from,
	vl_u64 timestamp_to,
	vl_u64 data_numeric,
	unsigned long int data_size,
	struct vl_message *result
);
int init_message (
	unsigned long int type,
	unsigned long int class,
	vl_u64 timestamp_from,
	vl_u64 timestamp_to,
	vl_u64 data_numeric,
	const char *data,
	unsigned long int data_size,
	struct vl_message *result
);
int message_checksum_check (
	struct vl_message *message
);
int message_convert_endianess (
	struct vl_message *message
);
void message_prepare_for_network (
	struct vl_message *message
);
struct vl_message *message_duplicate (
	struct vl_message *message
);

#endif
