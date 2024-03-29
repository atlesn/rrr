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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"

#include "message_holder.h"
#include "message_holder_util.h"
#include "message_holder_struct.h"

#include "../messages/msg_msg.h"

int rrr_msg_holder_util_new_with_empty_message (
		struct rrr_msg_holder **result,
		rrr_biglength message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol
) {
	int ret = 0;

	struct rrr_msg_holder *entry = NULL;
	struct rrr_msg_msg *message = NULL;

	// XXX : Callers treat this function as message_data_length is an absolute value

	rrr_biglength message_size = sizeof(*message) - 1 + message_data_length;

	if (message_size < message_data_length) {
		RRR_MSG_0("Overflow in while creating message holder with empty message\n");
		ret = 1;
		goto out;
	}

	if ((message = rrr_allocate(message_size)) == NULL) {
		RRR_MSG_0("Could not allocate message in message_holder_new_with_message\n");
		ret = 1;
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
	rrr_memset(message, '\0', message_size);
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
	rrr_biglength message_data_length = source->data_length - (sizeof(struct rrr_msg_msg) - 1);

	int ret = 0;

	*result = NULL;

	struct rrr_msg_holder *entry = NULL;

	if ((ret = rrr_msg_holder_util_new_with_empty_message (
			&entry,
			message_data_length,
			(struct sockaddr *) &source->addr,
			source->addr_len,
			source->protocol
	)) != 0) {
		goto out;
	}

	rrr_msg_holder_lock(entry);

	entry->buffer_time = source->buffer_time;
	entry->send_time = source->send_time;
	rrr_memcpy(entry->message, source->message, source->data_length);

	ret = rrr_instance_friend_collection_append_from (&entry->nexthops, &source->nexthops);

	rrr_msg_holder_unlock(entry);

	if (ret != 0) {
		goto out;
	}

	*result = entry;
	entry = NULL;

	out:
	if (entry != NULL) {
		rrr_msg_holder_decref(entry);
	}
	return ret;
}

int rrr_msg_holder_util_clone_no_locking_no_metadata (
		struct rrr_msg_holder **result,
		const struct rrr_msg_holder *source
) {
	// Note : Do calculation correctly, not incorrect
	rrr_biglength message_data_length = source->data_length - (sizeof(struct rrr_msg_msg) - 1);

	int ret = rrr_msg_holder_util_new_with_empty_message (
			result,
			message_data_length,
			NULL,
			0,
			0
	);

	if (ret == 0) {
		rrr_msg_holder_lock(*result);
		rrr_memcpy((*result)->message, source->message, source->data_length);
		rrr_msg_holder_unlock(*result);
	}

	return ret;
}

int rrr_msg_holder_util_index_compare (
		const struct rrr_msg_holder *a,
		const struct rrr_msg_holder *b
) {
	return (a->send_index > b->send_index) - (a->send_index < b->send_index);
}

void rrr_msg_holder_util_timeout_check (
		int *ttl_timeout,
		int *timeout,
		uint64_t ttl_us,
		uint64_t timeout_us,
		struct rrr_msg_holder *entry
) {
	// TTL timeout takes precedence if both times have expired

	if (ttl_us > 0 && !rrr_msg_msg_ttl_ok(entry->message, ttl_us)) {
		*ttl_timeout = 1;
		*timeout = 0;
	}
	else if (timeout_us > 0 && entry->send_time > 0 && entry->send_time < (rrr_time_get_64() - timeout_us)) {
		*ttl_timeout = 0;
		*timeout = 1;
	}
	else {
		*ttl_timeout = 0;
		*timeout = 0;
	}
}
