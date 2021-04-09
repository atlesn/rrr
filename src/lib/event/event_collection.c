
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

#include <string.h>
#include <stdlib.h>

#include "../log.h"
#include "event.h"
#include "event_struct.h"
#include "event_collection.h"
#include "../util/rrr_time.h"

void rrr_event_collection_init (
		struct rrr_event_collection *collection,
		struct rrr_event_queue *queue
) {
	if (collection->event_base != NULL) {
		RRR_BUG("BUG: Double call of rrr_event_collection_init()\n");
	}
	memset(collection, '\0', sizeof(*collection));
	collection->event_base = queue->event_base;
}

void rrr_event_collection_clear (
		struct rrr_event_collection *collection
) {
	for (size_t i = 0; i < collection->event_count; i++) {
		event_free(collection->events[i]);
	}
	memset(collection, '\0', sizeof(*collection));
}

static int __rrr_event_collection_push (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		int fd,
		short flags,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
) {
	int ret = 0;

	if (collection->event_base == NULL) {
		RRR_BUG("BUG: Collection not initialized in __rrr_event_collection_push\n");
	}

	struct event *event;

	struct timeval tv;
	rrr_time_from_usec(&tv, interval_us);

	if ((event = event_new (
			collection->event_base,
			fd,
			flags,
			callback,
			arg
	)) == NULL) {
		RRR_MSG_0("Failed to create event in rrr_event_collection_push_and_add_periodic\n");
		ret = 1;
		goto out;
	}

	if (collection->event_count == RRR_EVENT_COLLECTION_MAX) {
		RRR_BUG("BUG: No more room in event collection in rrr_event_collection_push\n");
	}

	collection->events[collection->event_count++] = event;

	struct rrr_event_handle result = {
		event,
		{0}
	};

	rrr_time_from_usec(&result.interval, interval_us);

	*target = result;

	goto out;
//	out_free:
//		event_free(event);
	out:
		return ret;
}

int rrr_event_collection_push_oneshot (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg
) {
	return __rrr_event_collection_push(target, collection, -1, 0, callback, arg, 0);
}

int rrr_event_collection_push_periodic (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
) {
	return __rrr_event_collection_push(target, collection, -1, EV_PERSIST, callback, arg, interval_us);
}

int rrr_event_collection_push_read (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		int fd,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
) {
	return __rrr_event_collection_push(target, collection, fd, EV_READ|EV_PERSIST, callback, arg, interval_us);
}

int rrr_event_collection_push_write (
		struct rrr_event_handle *target,
		struct rrr_event_collection *collection,
		int fd,
		void (callback)(evutil_socket_t fd, short flags, void *arg),
		void *arg,
		uint64_t interval_us
) {
	return __rrr_event_collection_push(target, collection, fd, EV_WRITE|EV_PERSIST, callback, arg, interval_us);
}

