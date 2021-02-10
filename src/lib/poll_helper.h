/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include "instance_friends.h"
#include "modules.h"
#include "util/linked_list.h"

#define RRR_POLL_BREAK_ON_ERR	(1<<10)
#define RRR_POLL_NO_SENDERS_OK	(1<<11)

#define RRR_POLL_ERR 1
#define RRR_POLL_NOT_FOUND 2

typedef void rrr_message_broker_costumer_handle;

struct rrr_poll_collection_entry {
	RRR_LL_NODE(struct rrr_poll_collection_entry);
	struct rrr_message_broker *message_broker;
	rrr_message_broker_costumer_handle *message_broker_handle;
};

struct rrr_poll_collection {
	RRR_LL_HEAD(struct rrr_poll_collection_entry);
};

void rrr_poll_collection_clear (
		struct rrr_poll_collection *collection
);
int rrr_poll_collection_add (
		unsigned int *flags_result,
		struct rrr_poll_collection *collection,
		struct rrr_message_broker *message_broker,
		const char *costumer_name
);
int rrr_poll_do_poll_discard (
		int *discarded_count,
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_poll_collection *collection
);
int rrr_poll_do_poll_delete (
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
);
int rrr_poll_do_poll_search (
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg,
		unsigned int wait_milliseconds
);
int rrr_poll_collection_count (
		struct rrr_poll_collection *collection
);
int rrr_poll_add_from_thread_senders (
		struct rrr_instance **faulty_sender,
		struct rrr_poll_collection *collection,
		struct rrr_instance_runtime_data *thread_data
);

#endif /* RRR_POLL_HELPER_H */
