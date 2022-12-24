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

#include <stdio.h>

#include "msg_msg_struct.h"
#include "../rrr_types.h"

struct rrr_nullsafe_str;
struct rrr_mqtt_topic_token;

struct rrr_msg_msg *rrr_msg_msg_new_array (
	rrr_u64 time,
	rrr_u16 topic_length,
	rrr_u32 data_length
);
int rrr_msg_msg_new_empty (
		struct rrr_msg_msg **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		rrr_u16 topic_length,
		rrr_u32 data_length
);
int rrr_msg_msg_new_with_data (
		struct rrr_msg_msg **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		const char *topic,
		rrr_u16 topic_length,
		const char *data,
		rrr_u32 data_length
);
int rrr_msg_msg_new_with_data_nullsafe (
		struct rrr_msg_msg **final_result,
		rrr_u8 type,
		rrr_u8 class,
		rrr_u64 timestamp,
		const char *topic,
		rrr_u16 topic_length,
		const struct rrr_nullsafe_str *str
);
int rrr_msg_msg_to_string (
	char **final_target,
	const struct rrr_msg_msg *message
);
int rrr_msg_msg_to_host_and_verify (struct rrr_msg_msg *message, rrr_biglength expected_size);
void rrr_msg_msg_prepare_for_network (struct rrr_msg_msg *message);
struct rrr_msg_msg *rrr_msg_msg_duplicate_no_data_with_size (
		const struct rrr_msg_msg *message,
		rrr_u16 topic_length,
		rrr_u32 data_length
);
struct rrr_msg_msg *rrr_msg_msg_duplicate (
		const struct rrr_msg_msg *message
);
struct rrr_msg_msg *rrr_msg_msg_duplicate_no_data (
		struct rrr_msg_msg *message
);
int rrr_msg_msg_topic_set (
		struct rrr_msg_msg **message,
		const char *topic,
		rrr_u16 topic_len
);
int rrr_msg_msg_topic_and_length_get (
		char **result,
		uint16_t *result_length,
		const struct rrr_msg_msg *message
);
int rrr_msg_msg_topic_get (
		char **result,
		const struct rrr_msg_msg *message
);
int rrr_msg_msg_topic_equals (
		const struct rrr_msg_msg *message,
		const char *topic
);
int rrr_msg_msg_topic_match (
		int *does_match,
		const struct rrr_msg_msg *message,
		const struct rrr_mqtt_topic_token *filter_first_token
);
int rrr_msg_msg_ttl_ok (const struct rrr_msg_msg *msg, uint64_t ttl);

#endif /* RRR_MESSAGES_H */
