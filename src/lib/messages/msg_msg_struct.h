/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MESSAGES_HEAD_H
#define RRR_MESSAGES_HEAD_H

#include "msg_head.h"

enum rrr_msg_msg_type {
	MSG_TYPE_MSG = 1,
	MSG_TYPE_TAG = 2,
	MSG_TYPE_GET = 3,
	MSG_TYPE_PUT = 4,
	MSG_TYPE_DEL = 5
};

enum rrr_msg_msg_class {
	MSG_CLASS_DATA  =  1,
	MSG_CLASS_ARRAY = 11
};

#define MSG_TYPE_MSG_STRING "MSG"
#define MSG_TYPE_TAG_STRING "TAG"
#define MSG_TYPE_GET_STRING "GET"
#define MSG_TYPE_PUT_STRING "PUT"
#define MSG_TYPE_DEL_STRING "DEL"

#define MSG_CLASS_DATA_STRING "DATA"
#define MSG_CLASS_ARRAY_STRING "ARRAY"

#define MSG_TYPE(message)             ((message)->type_and_class & 0x0f)
#define MSG_CLASS(message)            (((message)->type_and_class & 0xf0) >> 4)

#define MSG_SET_TYPE(message,n)       (message)->type_and_class = (rrr_u8) (((message)->type_and_class & 0xf0) | (n & 0x0f))
#define MSG_SET_CLASS(message,n)      (message)->type_and_class = (rrr_u8) (((message)->type_and_class & 0x0f) | (n << 4))

#define MSG_IS_MSG(message)           (MSG_TYPE(message) == MSG_TYPE_MSG)
#define MSG_IS_TAG(message)           (MSG_TYPE(message) == MSG_TYPE_TAG)
#define MSG_IS_GET(message)           (MSG_TYPE(message) == MSG_TYPE_GET)
#define MSG_IS_PUT(message)           (MSG_TYPE(message) == MSG_TYPE_PUT)
#define MSG_IS_DEL(message)           (MSG_TYPE(message) == MSG_TYPE_DEL)

#define MSG_TYPE_NAME(message) \
	(MSG_IS_MSG(message) ? MSG_TYPE_MSG_STRING : \
	(MSG_IS_TAG(message) ? MSG_TYPE_TAG_STRING : \
	(MSG_IS_GET(message) ? MSG_TYPE_GET_STRING : \
	(MSG_IS_PUT(message) ? MSG_TYPE_PUT_STRING : \
	(MSG_IS_DEL(message) ? MSG_TYPE_DEL_STRING : \
	"(unknown)" )))))

#define MSG_CLASS_OK(message) \
    ((MSG_CLASS(message) == MSG_CLASS_DATA || MSG_CLASS(message) == MSG_CLASS_ARRAY))

#define MSG_TYPE_OK(message) \
    (MSG_TYPE(message) >= MSG_TYPE_MSG && MSG_TYPE(message) <= MSG_TYPE_DEL)

#define MSG_IS_DATA(message)          (MSG_CLASS(message) == MSG_CLASS_DATA)
#define MSG_IS_ARRAY(message)         (MSG_CLASS(message) == MSG_CLASS_ARRAY)

#define MSG_IS_MSG_DATA(message)      (MSG_IS_MSG(message) && MSG_IS_DATA(message))
#define MSG_IS_MSG_ARRAY(message)     (MSG_IS_MSG(message) && MSG_IS_ARRAY(message))

#define MSG_MIN_SIZE(message)         ((rrr_u32) sizeof(*(message))-1)
#define MSG_TOTAL_SIZE(message)       ((message)->msg_size)
#define MSG_TOPIC_LENGTH(message)     ((message)->topic_length)
#define MSG_TOPIC_PTR(message)        ((message)->data + 0)
#define MSG_DATA_LENGTH(message)      ((message)->msg_size - ((rrr_u32) sizeof(*message) - 1) - (message)->topic_length)
#define MSG_DATA_PTR(message)         ((message)->data + (message)->topic_length)

#define MSG_TOPIC_IS(message,topic)   (rrr_msg_msg_topic_equals(message,topic))

#define MSG_TO_BE(message)                                          \
    (message)->timestamp = rrr_htobe64((message)->timestamp);       \
    (message)->topic_length = rrr_htobe16((message)->topic_length)

#define RRR_MSG_MSG_HEAD       \
    rrr_u64 timestamp;         \
    rrr_u8 type_and_class;     \
    rrr_u8 version;            \
    rrr_u16 topic_length

#define RRR_MSG_TOPIC_MAX (0xffff)

struct rrr_msg_msg {
	RRR_MSG_HEAD;
	RRR_MSG_MSG_HEAD;
	char data[1];
} __attribute__((packed));

static inline struct rrr_msg *rrr_msg_msg_safe_cast (struct rrr_msg_msg *message) {
	struct rrr_msg *ret = (struct rrr_msg *) message;
	ret->msg_type = RRR_MSG_TYPE_MESSAGE;
	ret->msg_size = MSG_TOTAL_SIZE(message);
	ret->msg_value = 0;
	return ret;
}


#endif /* RRR_MESSAGES_HEAD */
