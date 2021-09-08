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

#ifndef RRR_EVENT_COLLECTION_HPP
#define RRR_EVENT_COLLECTION_HPP

extern "C" {
#include "event_collection.h"
}

namespace rrr::event {
	class collection {
		struct rrr_event_collection event_collection;

		public:
		collection (
			struct rrr_event_queue *queue
		) {
			rrr_event_collection_init(&this->event_collection, queue);
		}

		~collection() {
			rrr_event_collection_clear(&this->event_collection);
		}

		int push_oneshot (
				struct rrr_event_handle *target,
				void (*callback)(evutil_socket_t fd, short flags, void *arg),
				void *arg
		) {
			return rrr_event_collection_push_oneshot(target, &this->event_collection, callback, arg);
		}

		int push_periodic (
				struct rrr_event_handle *target,
				void (*callback)(evutil_socket_t fd, short flags, void *arg),
				void *arg,
				uint64_t interval_us
		) {
			return rrr_event_collection_push_periodic(target, &this->event_collection, callback, arg, interval_us);
		}

		int push_read (
				struct rrr_event_handle *target,
				int fd,
				void (*callback)(evutil_socket_t fd, short flags, void *arg),
				void *arg,
				uint64_t interval_us
		) {
			return rrr_event_collection_push_read(target, &this->event_collection, fd, callback, arg, interval_us);
		}

		int push_write (
				struct rrr_event_handle *target,
				int fd,
				void (*callback)(evutil_socket_t fd, short flags, void *arg),
				void *arg,
				uint64_t interval_us
		) {
			return rrr_event_collection_push_write(target, &this->event_collection, fd, callback, arg, interval_us);
		}
	};
}

#endif /* RRR_EVENT_COLLECTION_HPP */
