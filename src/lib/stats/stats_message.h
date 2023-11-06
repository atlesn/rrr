/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_STATS_MESSAGE_H
#define RRR_STATS_MESSAGE_H

#include <stdint.h>
#include <stdio.h>

#include "../messages/msg.h"
#include "../util/linked_list.h"

#define RRR_STATS_MESSAGE_TYPE_KEEPALIVE	0
#define RRR_STATS_MESSAGE_TYPE_TEXT			1
#define RRR_STATS_MESSAGE_TYPE_BASE10_TEXT	2
#define RRR_STATS_MESSAGE_TYPE_DOUBLE_TEXT	3
#define RRR_STATS_MESSAGE_TYPE_RRR_MSG		4

#define RRR_STATS_MESSAGE_PATH_INSTANCE_NAME		"name"
#define RRR_STATS_MESSAGE_PATH_GLOBAL_LOG_JOURNAL	"log_journal"
#define RRR_STATS_MESSAGE_PATH_GLOBAL_MSG "hook"

#define RRR_STATS_MESSAGE_FLAGS_STICKY (1<<0)

#define RRR_STATS_MESSAGE_FLAGS_ALL (RRR_STATS_MESSAGE_FLAGS_STICKY)

#define RRR_STATS_MESSAGE_FLAGS_IS_STICKY(message) ((message->flags & RRR_STATS_MESSAGE_FLAGS_STICKY) != 0)

#define RRR_STATS_MESSAGE_PATH_MAX_LENGTH 512
#define RRR_STATS_MESSAGE_DATA_MAX_SIZE 512

struct rrr_read_session;

struct rrr_msg_stats {
	RRR_LL_NODE(struct rrr_msg_stats);
	uint8_t type;
	uint32_t flags;
	uint32_t data_size;
	uint64_t timestamp;
	char path[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1];
	char data[RRR_STATS_MESSAGE_DATA_MAX_SIZE];
};

// msg_value of rrr_msg-struct is used for timestamp
struct rrr_msg_stats_packed {
	RRR_MSG_HEAD;
	uint8_t type;
	uint32_t flags;

	// Data begins after path_size and it's length is calculated
	// from msg_size and path_size
	uint16_t path_size;
	char path_and_data[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1 + RRR_STATS_MESSAGE_DATA_MAX_SIZE];
} __attribute((packed));

int rrr_msg_stats_unpack (
		struct rrr_msg_stats *target,
		const struct rrr_msg_stats_packed *source,
		rrr_length expected_size
);
void rrr_msg_stats_pack_and_flip (
		struct rrr_msg_stats_packed *target,
		rrr_length *total_size,
		const struct rrr_msg_stats *source
);

int rrr_msg_stats_init (
		struct rrr_msg_stats *message,
		uint8_t type,
		uint32_t flags,
		const char *path_postfix,
		const void *data,
		uint32_t data_size
);

int rrr_msg_stats_new_empty (
		struct rrr_msg_stats **message
);

int rrr_msg_stats_new (
		struct rrr_msg_stats **message,
		uint8_t type,
		uint32_t flags,
		const char *path_postfix,
		const void *data,
		uint32_t data_size
);

int rrr_msg_stats_new_with_rrr_msg (
		struct rrr_msg_stats **message,
		const char *path_postfix,
		const struct rrr_msg_msg *msg
);

int rrr_msg_stats_set_path (
		struct rrr_msg_stats *message,
		const char *path
);

int rrr_msg_stats_duplicate (
		struct rrr_msg_stats **target,
		const struct rrr_msg_stats *source
);

int rrr_msg_stats_destroy (
		struct rrr_msg_stats *message
);

#endif /* RRR_STATS_MESSAGE_H */
