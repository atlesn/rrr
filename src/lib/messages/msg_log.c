/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "msg_log.h"
#include "msg.h"

void rrr_msg_msg_log_prepare_for_network (struct rrr_msg_log *msg) {
	msg->prefix_size = rrr_htobe16(msg->prefix_size);
}

int rrr_msg_msg_log_to_host (struct rrr_msg_log *msg) {
	msg->prefix_size = rrr_be16toh(msg->prefix_size);

	if (!RRR_MSG_LOG_SIZE_OK(msg)) {
		RRR_MSG_0("Invalid size of message in rrr_msg_msg_log_to_host\n");
		return 1;
	}

	if (msg->prefix_size > 0 && *(msg->prefix_and_message - 1 + msg->prefix_size - 1) != '\0') {
		RRR_MSG_0("Prefix was not 0-terminated in rrr_msg_msg_log_to_host\n");
		return 1;
	}

	if (*((char *) msg + msg->msg_size - 1) != '\0') {
		RRR_MSG_0("Message was not 0-terminated in rrr_msg_msg_log_to_host\n");
		return 1;
	}

	return 0;
}

void rrr_msg_msg_log_init_head (struct rrr_msg_log *target, uint16_t prefix_size, uint32_t data_size) {
	rrr_msg_populate_head (
			(struct rrr_msg *) target,
			RRR_MSG_TYPE_MESSAGE_LOG,
			sizeof(*target) - 1 + prefix_size + data_size,
			0
	);

	target->prefix_size = prefix_size;
}

int rrr_msg_msg_log_new (
		struct rrr_msg_log **target,
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
		const char *prefix,
		const char *message
) {
	*target = NULL;

	size_t prefix_size = strlen(prefix) + 1;
	size_t message_size = strlen(message) + 1;

	if (prefix_size > 0xffff) {
		prefix_size = 0xffff;
	}

	size_t total_data_size = prefix_size + message_size;

	struct rrr_msg_log *result = malloc(sizeof(*result) - 1 + total_data_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memorty in rrr_msg_msg_log_new");
		return 1;
	}

	rrr_msg_msg_log_init_head(result, prefix_size, message_size);
/*
	printf("init message ppos %p mpos %p\n", result->prefix_and_message, RRR_MSG_LOG_MSG_POS(result));

	printf ("msg size: %u, msg prefix size: %u, msg data size: %u, data size calculated: %u\n",
			result->msg_size,
			result->prefix_size,
			message_size,
			RRR_MSG_LOG_MSG_SIZE(result)
	);
*/
	memcpy(result->prefix_and_message, prefix, prefix_size);
	*(result->prefix_and_message + prefix_size - 1) = '\0';

	memcpy(RRR_MSG_LOG_MSG_POS(result), message, message_size);

	result->loglevel_translated = loglevel_translated;
	result->loglevel_orig = loglevel_orig;

	*target = result;

	return 0;
}
