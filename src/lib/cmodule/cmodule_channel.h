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

#ifndef RRR_CMODULE_CHANNEL_H
#define RRR_CMODULE_CHANNEL_H

#include <sys/types.h>

#include "../util/linked_list.h"

struct rrr_msg;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_setting_packed;
struct rrr_mmap_channel;

int rrr_cmodule_channel_send_message_simple (
		int *sent_total,
		struct rrr_mmap_channel *channel,
		const struct rrr_msg *message
);
int rrr_cmodule_channel_send_message_and_address (
		struct rrr_mmap_channel *channel,
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr,
		unsigned int wait_time_us
);
int rrr_cmodule_channel_receive_messages (
		struct rrr_mmap_channel *channel,
		unsigned int empty_wait_time_us,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
);
void rrr_cmodule_channel_bubblesort (
		struct rrr_mmap_channel *channel
);

#endif /* RRR_CMODULE_CHANNEL_H */
