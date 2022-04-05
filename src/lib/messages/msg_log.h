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

#ifndef RRR_MESSAGE_LOG_H
#define RRR_MESSAGE_LOG_H

#include "msg.h"
#include "../socket/rrr_socket.h"
#include "../util/rrr_endian.h"

#define RRR_MSG_LOG_PREFIX_SIZE(msg)										\
	((msg)->prefix_size)

#define RRR_MSG_LOG_MSG_SIZE(msg)											\
	((msg)->msg_size - (sizeof(*(msg)) - 1) - (msg)->prefix_size)

#define RRR_MSG_LOG_MSG_POS(msg)											\
	((msg->prefix_and_message) + (msg)->prefix_size)

#define RRR_MSG_LOG_SIZE_OK(msg)											\
	((msg)->prefix_size > (msg)->msg_size - sizeof(*(msg)) - 1 ? 0 : 1)

struct rrr_msg_log {
	RRR_MSG_HEAD;
	char file[128];
	uint32_t line;
	uint8_t is_stdout;
	uint8_t loglevel_translated;
	uint8_t loglevel_orig;
	uint16_t prefix_size;
	char prefix_and_message[1];
} __attribute((__packed__));

void rrr_msg_msg_log_prepare_for_network (struct rrr_msg_log *msg);
int rrr_msg_msg_log_to_host (struct rrr_msg_log *msg);
void rrr_msg_msg_log_init_head (struct rrr_msg_log *target, uint16_t prefix_size, uint32_t data_size);
int rrr_msg_msg_log_new (
		struct rrr_msg_log **target,
		const char *file,
		int line,
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
		const char *prefix,
		const char *message
);
int rrr_msg_msg_log_to_str (
	char **target_prefix,
	char **target_message,
	const struct rrr_msg_log *msg
);

#endif /* RRR_MESSAGE_LOG_H */
