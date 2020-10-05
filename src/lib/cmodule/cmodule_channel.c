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

#include "../log.h"

#include "cmodule_channel.h"
#include "cmodule_defines.h"

#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../mmap_channel.h"
#include "../util/linked_list.h"
#include "../util/macro_utils.h"


struct rrr_cmodule_mmap_channel_write_simple_callback_data {
	const struct rrr_msg *message;
};

static int __rrr_cmodule_mmap_channel_write_simple_callback (void *target, void *arg) {
	struct rrr_cmodule_mmap_channel_write_simple_callback_data *callback_data = arg;
	memcpy(target, callback_data->message, sizeof(*(callback_data->message)));
	return 0;
}

int rrr_cmodule_channel_send_message_simple (
		struct rrr_mmap_channel *channel,
		const struct rrr_msg *message
) {
	int ret = 0;

	struct rrr_cmodule_mmap_channel_write_simple_callback_data callback_data = {
			message
	};

	if ((ret = rrr_mmap_channel_write_using_callback (
			channel,
			sizeof(*message),
			0,
			__rrr_cmodule_mmap_channel_write_simple_callback,
			&callback_data
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
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr,
		unsigned int wait_time_us
) {
	int ret = 0;

	if (message == NULL) {
		RRR_BUG("BUG: message was NULL in rrr_cmodule_channel_send_message_and_address\n");
	}

	struct rrr_cmodule_mmap_channel_write_callback_data callback_data = {
		message_addr,
		message
	};

	if ((ret = rrr_mmap_channel_write_using_callback (
			channel,
			MSG_TOTAL_SIZE(message) + sizeof(*message_addr),
			wait_time_us,
			__rrr_cmodule_mmap_channel_write_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_MMAP_CHANNEL_FULL) {
			goto out;
		}
		RRR_MSG_0("Could not send address message on mmap channel in __rrr_cmodule_send_message name\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_cmodule_channel_receive_messages (
		struct rrr_mmap_channel *channel,
		unsigned int empty_wait_time_us,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int retry_max = 100;
	int retry_sleep_start = 90;

	do {
		ret = rrr_mmap_channel_read_with_callback (
				channel,
				(--retry_sleep_start > 0 ? 0 : empty_wait_time_us),
				callback,
				callback_arg
		);
	} while (--retry_max >= 0 && ret != 0 && ret != RRR_MMAP_CHANNEL_EMPTY);

	return ret;
}

void rrr_cmodule_channel_bubblesort (
		struct rrr_mmap_channel *channel
) {
	int was_sorted = 0;
	int max_rounds = 100;

	do {
		rrr_mmap_channel_bubblesort_pointers (channel, &was_sorted);
	} while (was_sorted == 0 && --max_rounds > 0);
}
