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

#include "cmodule_channel.h"
#include "cmodule_defines.h"
#include "cmodule_main.h"
#include "cmodule_defer_queue.h"

#include "../log.h"
#include "../messages.h"
#include "../message_addr.h"
#include "../linked_list.h"
#include "../mmap_channel.h"

struct rrr_cmodule_mmap_channel_callback_data {
	const struct rrr_message_addr *addr_msg;
	const struct rrr_message *msg;
};

static int __rrr_cmodule_mmap_channel_write_callback (void *target, void *arg) {
	struct rrr_cmodule_mmap_channel_callback_data *data = arg;

	void *msg_pos = target;
	void *msg_addr_pos = target + MSG_TOTAL_SIZE(data->msg);

	memcpy(msg_pos, data->msg, MSG_TOTAL_SIZE(data->msg));
	memcpy(msg_addr_pos, data->addr_msg, sizeof(*(data->addr_msg)));

	return 0;
}

int rrr_cmodule_channel_send_message (
		int *sent_total,
		int *retries,
		struct rrr_mmap_channel *channel,
		struct rrr_cmodule_deferred_message_collection *deferred_queue,
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr,
		unsigned int wait_time_us
) {
	int ret = 0;

	*sent_total = 0;
	*retries = 0;

	// When adjusting retry and usleep, test for throughput afterwards. These numbers
	// have no implication in low-traffic situations.
	int retry_max_ = 50;

	// Enable conditional wait in mmap after this many retries
	int retry_sleep_start_max_ = 40;

	// Extracted from deferred queue, freed every time before it is used and at out
	struct rrr_message_addr *message_addr_to_free = NULL;

	{
		int count_before_cleanup = RRR_LL_COUNT(deferred_queue);

		while (RRR_LL_COUNT(deferred_queue) > RRR_CMODULE_DEFERRED_QUEUE_MAX) {
			struct rrr_cmodule_deferred_message *msg = RRR_LL_SHIFT(deferred_queue);
			rrr_cmodule_deferred_message_destroy(msg);
		}

		int count_after_cleanup = RRR_LL_COUNT(deferred_queue);
		if (count_after_cleanup != count_before_cleanup) {
			RRR_MSG_0("Warning: %i messages cleared from over-filled cmodule deferred queue in %s. Messages were lost.\n", count_before_cleanup - count_after_cleanup, channel->name);
		}
	}

	// If there are deferred messages, immediately push the new message to
	// deferred queue and instead process the first one in the queue
	if (RRR_LL_COUNT(deferred_queue) > 0) {
		goto defer_message;
	}

	goto send_message;

	defer_message:
		if (rrr_cmodule_deferred_message_new_and_push(deferred_queue, message, message_addr) != 0) {
			RRR_MSG_0("Error while pushing deferred message in __rrr_cmodule_send_message\n");
			ret = 1;
			goto out;
		}

		// Ownership taken by queue
		message = NULL;

		// Not to be used anymore for now
		message_addr = NULL;

		if (retry_max_ <= 0) {
			RRR_DBG_2("Note: Retries exceeded in __rrr_cmodule_send_message\n");
			ret = 0;
			goto out;
		}

	// We allow the function to be called with NULL message, in which case
	// we just try to read from the deferred queue
	send_message:
		if (message == NULL) {
			if (RRR_LL_COUNT(deferred_queue) > 0) {
				struct rrr_cmodule_deferred_message *deferred_message = RRR_LL_SHIFT(deferred_queue);
				RRR_FREE_IF_NOT_NULL(message_addr_to_free);
				rrr_cmodule_deferred_message_extract(&message, &message_addr_to_free, deferred_message);
				rrr_cmodule_deferred_message_destroy(deferred_message);
				message_addr = message_addr_to_free;
			}
		}

		if (message == NULL) {
			// Nothing to do if message still is NULL
			goto out;
		}

		struct rrr_cmodule_mmap_channel_callback_data callback_data = {
			message_addr,
			message
		};

		while ((--retry_max_) >= 0) {
			if ((ret = rrr_mmap_channel_write_using_callback (
					channel,
					MSG_TOTAL_SIZE(message) + sizeof(*message_addr),
					(--retry_sleep_start_max_ <= 0 ? wait_time_us : 0),
					__rrr_cmodule_mmap_channel_write_callback,
					&callback_data
			)) != 0) {
				if (ret == RRR_MMAP_CHANNEL_FULL) {
//					rrr_posix_usleep(5); // Symbolic sleep
					(*retries)++;
					ret = 0;
					goto defer_message;
				}
				RRR_MSG_0("Could not send address message on mmap channel in __rrr_cmodule_send_message name\n");
				ret = 1;
				goto out;
			}
			else {
				break;
			}
		}

		(*sent_total)++;

		RRR_FREE_IF_NOT_NULL(message_addr_to_free);
		RRR_FREE_IF_NOT_NULL(message);

		if (RRR_LL_COUNT(deferred_queue) > 0) {
			goto send_message;
		}

		out:
		RRR_FREE_IF_NOT_NULL(message_addr_to_free);
		RRR_FREE_IF_NOT_NULL(message);
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

//	if (was_sorted != 0) {
//		printf("was sorted\n");
//	}
}
