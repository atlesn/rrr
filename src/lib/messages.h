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

#include "socket/rrr_socket_msg_head.h"
#include "messages_head.h"

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
int rrr_message_timestamp_compare (struct rrr_message *message_a, struct rrr_message *message_b);
int rrr_message_timestamp_compare_void (void *message_a, void *message_b);

#endif /* RRR_MESSAGES_H */
