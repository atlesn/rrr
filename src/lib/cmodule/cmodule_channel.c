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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"

#include "cmodule_channel.h"
#include "cmodule_defines.h"

#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../mmap_channel.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"

struct rrr_cmodule_mmap_channel_write_simple_callback_data {
	const struct rrr_msg *message;
};

static int __rrr_cmodule_mmap_channel_write_simple_callback (void *target, void *arg) {
	struct rrr_cmodule_mmap_channel_write_simple_callback_data *callback_data = arg;
	memcpy(target, callback_data->message, sizeof(*(callback_data->message)));
	return 0;
}

int rrr_cmodule_channel_count (
		int *count,
		struct rrr_mmap_channel *channel
) {
	return rrr_mmap_channel_count(count, channel);
}

int rrr_cmodule_channel_send_message_simple (
		struct rrr_mmap_channel *channel,
		struct rrr_event_queue *notify_queue,
		const struct rrr_msg *message,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	struct rrr_cmodule_mmap_channel_write_simple_callback_data callback_data = {
			message
	};

	if ((ret = rrr_mmap_channel_write_using_callback (
			channel,
			notify_queue,
			sizeof(*message),
			__rrr_cmodule_mmap_channel_write_simple_callback,
			&callback_data,
			check_cancel_callback,
			check_cancel_callback_arg
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct rrr_cmodule_mmap_channel_write_callback_data {
	const struct rrr_msg_addr *addr_msg;
	const struct rrr_msg_msg *msg;
};

static int __rrr_cmodule_mmap_channel_write_callback (void *target, void *arg) {
	struct rrr_cmodule_mmap_channel_write_callback_data *data = arg;

	void *msg_pos = target;
	void *msg_addr_pos = target + MSG_TOTAL_SIZE(data->msg);

	memcpy(msg_pos, data->msg, MSG_TOTAL_SIZE(data->msg));
	memcpy(msg_addr_pos, data->addr_msg, sizeof(*(data->addr_msg)));

	return 0;
}

int rrr_cmodule_channel_send_message_and_address (
		struct rrr_mmap_channel *channel,
		struct rrr_event_queue *notify_queue,
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr,
		rrr_time_us_t full_wait_time,
		int wait_attempts_max,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	if (message == NULL) {
		RRR_BUG("BUG: message was NULL in rrr_cmodule_channel_send_message_and_address\n");
	}

	struct rrr_cmodule_mmap_channel_write_callback_data callback_data = {
		message_addr,
		message
	};

	while (wait_attempts_max--) {
		if ((ret = rrr_mmap_channel_write_using_callback (
				channel,
				notify_queue,
				MSG_TOTAL_SIZE(message) + sizeof(*message_addr),
				__rrr_cmodule_mmap_channel_write_callback,
				&callback_data,
				check_cancel_callback,
				check_cancel_callback_arg
		)) == 0) {
			break;
		}
		else if (ret == RRR_MMAP_CHANNEL_FULL) {
			// OK, retry
		}
		else {
			RRR_MSG_0("Could not send address message on mmap channel in rrr_cmodule_channel_send_message_and_addres return was %i\n", ret);
			goto out;
		}

		if (!rrr_time_us_zero(full_wait_time)) {
			rrr_posix_sleep_us(full_wait_time);
		}
	}

	out:
	return ret;
}

int rrr_cmodule_channel_receive_messages (
		uint16_t *amount,
		struct rrr_mmap_channel *channel,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int did_read = 0;
	int max = 100;
	do {
		did_read = 0;
		ret = rrr_mmap_channel_read_with_callback (
				&did_read,
				channel,
				callback,
				callback_arg
		);
		if (did_read) {
			(*amount)--;
		}
	} while (--max >= 0 && *amount > 0 && ret == 0 && did_read);

	return ret;
}

void rrr_cmodule_channel_maintenance (
		struct rrr_mmap_channel *channel
) {
	rrr_mmap_channel_maintenance(channel);
}
