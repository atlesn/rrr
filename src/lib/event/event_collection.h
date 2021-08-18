/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_EVENT_COLLECTION
#define RRR_EVENT_COLLECTION

#include <stddef.h>

#include "event.h"

#define RRR_EVENT_COLLECTION_MAX 8

struct event_base;
struct event;

struct rrr_event_collection {
	struct event_base *event_base;
	struct event *events[RRR_EVENT_COLLECTION_MAX];
	size_t event_count;
};

void rrr_event_collection_init (
		struct rrr_event_collection *collection,
		struct rrr_event_queue *queue
);
void rrr_event_collection_clear (
		struct rrr_event_collection *collection
);
void rrr_event_collection_clear_void (
		void *arg
);
int rrr_event_collection_push_oneshot (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg
);
int rrr_event_collection_push_periodic (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
);
int rrr_event_collection_push_read (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		int fd,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
);
int rrr_event_collection_push_write (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		int fd,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
);

#endif /* RRR_EVENT_COLLECTION */
