/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "../global.h"
#include "instance_collection.h"
#include "modules.h"
#include "linked_list.h"

#define RRR_POLL_POLL			(1<<0)
#define RRR_POLL_POLL_DELETE	(1<<1)
#define RRR_POLL_POLL_DELETE_IP	(1<<2)
#define RRR_POLL_PRINT			(1<<3)
#define RRR_POLL_BREAK_ON_ERR	(1<<10)
#define RRR_POLL_NO_SENDERS_OK	(1<<11)

#define RRR_POLL_ERR 1
#define RRR_POLL_NOT_FOUND 2

struct poll_collection_entry {
	RRR_LL_NODE(struct poll_collection_entry);
	int (*poll)(RRR_MODULE_POLL_SIGNATURE);
	int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE);
	int (*print)(RRR_MODULE_PRINT_SIGNATURE);
	struct rrr_instance_thread_data *thread_data;
	unsigned int flags;
};

struct poll_collection {
	RRR_LL_HEAD(struct poll_collection_entry);
};

void poll_collection_clear(struct poll_collection *collection);
void poll_collection_clear_void(void *data);
void poll_collection_init(struct poll_collection *collection);

void poll_collection_remove (struct poll_collection *collection, struct rrr_instance_thread_data *find);

int poll_collection_has (struct poll_collection *collection, struct rrr_instance_thread_data *find);

int poll_collection_add (
		unsigned int *flags_result,
		struct poll_collection *collection,
		unsigned int flags,
		struct instance_metadata *instance
);

int poll_collection_add_from_senders (
		struct poll_collection *poll_collection,
		struct instance_metadata **faulty_instance,
		struct rrr_instance_collection *senders,
		unsigned int flags
);

int poll_do_poll (
		struct poll_collection *collection,
		struct rrr_instance_thread_data **faulty_instance,
		unsigned int flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		const struct rrr_fifo_callback_args *poll_data,
		unsigned int wait_milliseconds
);

int poll_do_poll_delete (
		struct poll_collection *collection,
		struct rrr_instance_thread_data **faulty_instance,
		unsigned int flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		const struct rrr_fifo_callback_args *poll_data,
		unsigned int wait_milliseconds
);

int poll_do_poll_delete_simple_final (
		struct poll_collection *poll,
		struct rrr_instance_thread_data *thread_data,
		int (*poll_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int flags,
		unsigned int wait_milliseconds
);

static inline int poll_do_poll_delete_simple (
		struct poll_collection *poll,
		struct rrr_instance_thread_data *thread_data,
		int (*poll_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) { return poll_do_poll_delete_simple_final(poll, thread_data, poll_callback, RRR_POLL_POLL_DELETE, wait_milliseconds); }

static inline int poll_do_poll_delete_ip_simple (
		struct poll_collection *poll,
		struct rrr_instance_thread_data *thread_data,
		int (*poll_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) { return poll_do_poll_delete_simple_final(poll, thread_data, poll_callback, RRR_POLL_POLL_DELETE_IP, wait_milliseconds); }

static inline int poll_do_poll_delete_combined_simple (
		struct poll_collection *poll,
		struct rrr_instance_thread_data *thread_data,
		int (*poll_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) { return poll_do_poll_delete_simple_final(poll, thread_data, poll_callback, RRR_POLL_POLL_DELETE_IP|RRR_POLL_POLL_DELETE, wait_milliseconds); }

int poll_collection_count (struct poll_collection *collection);

int poll_add_from_thread_senders_and_count (
		struct poll_collection *collection,
		struct rrr_instance_thread_data *thread_data,
		unsigned int flags
);

void poll_add_from_thread_senders_ignore_error (
		struct poll_collection *collection,
		struct rrr_instance_thread_data *thread_data,
		unsigned int flags
);

void poll_remove_senders_also_in (
		struct poll_collection *target,
		const struct poll_collection *source
);

#endif /* RRR_POLL_HELPER_H */
