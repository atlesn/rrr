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

#include "instance_collection.h"
#include "modules.h"
#include "linked_list.h"

#define RRR_POLL_BREAK_ON_ERR	(1<<10)
#define RRR_POLL_NO_SENDERS_OK	(1<<11)

#define RRR_POLL_ERR 1
#define RRR_POLL_NOT_FOUND 2

typedef void rrr_message_broker_costumer_handle;

struct rrr_poll_collection_entry {
	RRR_LL_NODE(struct rrr_poll_collection_entry);
	struct rrr_instance_thread_data *thread_data;
};

struct rrr_poll_collection {
	RRR_LL_HEAD(struct rrr_poll_collection_entry);
};

void rrr_poll_collection_clear(struct rrr_poll_collection *collection);
void rrr_poll_collection_clear_void(void *data);
void rrr_poll_collection_init(struct rrr_poll_collection *collection);

int rrr_poll_collection_new(struct rrr_poll_collection **target);
void rrr_poll_collection_destroy(struct rrr_poll_collection *collection);
void rrr_poll_collection_destroy_void(void *data);

void rrr_poll_collection_remove (struct rrr_poll_collection *collection, struct rrr_instance_thread_data *find);

int rrr_poll_collection_has (struct rrr_poll_collection *collection, struct rrr_instance_thread_data *find);

int rrr_poll_collection_add (
		unsigned int *flags_result,
		struct rrr_poll_collection *collection,
		struct instance_metadata *instance
);

int rrr_poll_collection_add_from_senders (
		struct rrr_poll_collection *poll_collection,
		struct instance_metadata **faulty_instance,
		struct rrr_instance_collection *senders
);

int rrr_poll_do_poll_delete (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
);

int rrr_poll_collection_count (
		struct rrr_poll_collection *collection
);

void rrr_poll_add_from_thread_senders (
		struct rrr_poll_collection *collection,
		struct rrr_instance_thread_data *thread_data
);

void rrr_poll_remove_senders_also_in (
		struct rrr_poll_collection *target,
		const struct rrr_poll_collection *source
);

#endif /* RRR_POLL_HELPER_H */
