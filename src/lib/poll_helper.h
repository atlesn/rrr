/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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


#ifndef RRR_POLL_HELPER_H
#define RRR_POLL_HELPER_H

#include <stdint.h>

#include "instance_friends.h"
#include "poll_defines.h"
#include "util/linked_list.h"

#define RRR_POLL_BREAK_ON_ERR	(1<<10)
#define RRR_POLL_NO_SENDERS_OK	(1<<11)

#define RRR_POLL_ERR 1
#define RRR_POLL_NOT_FOUND 2

struct rrr_message_broker;
struct rrr_instance_runtime_data;

struct rrr_poll_helper_counters {
	uint64_t total_message_count;
	uint64_t prev_message_count;
	unsigned int poll_count_tmp;
};

#define RRR_POLL_HELPER_COUNTERS_UPDATE_POLLED(data)           \
    data->counters.total_message_count++;                      \
    data->counters.poll_count_tmp++;

#define RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(data)      \
    data->counters.poll_count_tmp = 0;

#define RRR_POLL_HELPER_COUNTERS_UPDATE_PERIODIC(count, data)                                            \
	uint64_t count = raw_data->counters.total_message_count - raw_data->counters.prev_message_count; \
	data->counters.prev_message_count = data->counters.total_message_count 

int rrr_poll_do_poll_delete_custom_arg (
		uint16_t *amount,
		struct rrr_instance_runtime_data *thread_data,
		int (*callback)(RRR_POLL_CALLBACK_SIGNATURE),
		void *callback_arg
);
int rrr_poll_do_poll_delete (
		uint16_t *amount,
		struct rrr_instance_runtime_data *thread_data,
		int (*callback)(RRR_POLL_CALLBACK_SIGNATURE)
);
int rrr_poll_add_senders_to_broker (
		struct rrr_instance **faulty_sender,
		struct rrr_message_broker *broker,
		struct rrr_instance *instance
);

#endif /* RRR_POLL_HELPER_H */
