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

#include <stdlib.h>
#include <string.h>

#include "../log.h"

#include "message_holder.h"
#include "message_holder_util.h"
#include "message_holder_struct.h"

#include "../messages/msg_msg.h"

int rrr_msg_holder_util_new_with_empty_message (
		struct rrr_msg_holder **result,
		ssize_t message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		int protocol
) {
	int ret = 0;

	struct rrr_msg_holder *entry = NULL;
	struct rrr_msg_msg *message = NULL;

	// XXX : Callers treat this function as message_data_length is an absolute value

	ssize_t message_size = sizeof(*message) - 1 + message_data_length;

	message = malloc(message_size);
	if (message == NULL) {
		RRR_MSG_0("Could not allocate message in message_holder_new_with_message\n");
		goto out;
	}

	if (rrr_msg_holder_new (
			&entry,
			message_size,
			addr,
			addr_len,
			protocol,
			message
	) != 0) {
		RRR_MSG_0("Could not allocate ip buffer entry in message_holder_new_with_message\n");
		ret = 1;
		goto out;
	}

	rrr_msg_holder_lock(entry);
	memset(message, '\0', message_size);
	rrr_msg_holder_unlock(entry);

	message = NULL;

	*result = entry;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int rrr_msg_holder_util_clone_no_locking (
		struct rrr_msg_holder **result,
		const struct rrr_msg_holder *source
) {
	// Note : Do calculation correctly, not incorrect
	ssize_t message_data_length = source->data_length - (sizeof(struct rrr_msg_msg) - 1);

	if (message_data_length < 0) {
		RRR_BUG("Message too small in rrr_msg_msg_holder_clone_no_locking\n");
	}

	int ret = rrr_msg_holder_util_new_with_empty_message (
			result,
			message_data_length,
			(struct sockaddr *) &source->addr,
			source->addr_len,
			source->protocol
	);

	if (ret == 0) {
		rrr_msg_holder_lock(*result);
		(*result)->buffer_time = source->buffer_time;
		(*result)->send_time = source->send_time;
		memcpy((*result)->message, source->message, source->data_length);
		rrr_msg_holder_unlock(*result);
	}

	return ret;
}
