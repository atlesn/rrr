/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "Event.hxx"

extern "C" {
#include "event.h"
#include "event_collection.h"
#include "../log.h"
#include "../util/rrr_time.h"
};

#include <string>
#include <cassert>

namespace RRR::Event {
	void HandleBase::set_handle(rrr_event_handle handle) {
		assert(!EVENT_INITIALIZED(this->handle));
		this->handle = handle;
	}

	HandleBase::HandleBase(CollectionActions &actions) :
		actions(actions),
		handle(RRR_EVENT_HANDLE_STRUCT_INITIALIZER)
	{}

	void HandleBase::base_run() noexcept {
		try {
			run();
		}
		catch (E e) {
			RRR_MSG_0("Event exception in %s: %s\n", __func__, std::string(e).c_str());
			actions.dispatch_break();
		}
		catch (RRR::util::E e) {
			RRR_MSG_0("RRR exception in %s: %s\n", __func__, std::string(e).c_str());
			actions.dispatch_break();
		}
		catch (...) {
			RRR_MSG_0("Unknown exception in %s\n", __func__);
			actions.dispatch_break();
		}
	}

	void HandleBase::set_interval(uint64_t interval_us) {
		EVENT_INTERVAL_SET(handle, interval_us);
	}

	void HandleBase::add() {
		EVENT_ADD(handle);
	}

	CollectionActions::CollectionActions(Collection &collection) :
		collection(collection)
	{
	}

	void CollectionActions::dispatch_break() {
		collection.dispatch_break();
	}

	void __handle_callback(evutil_socket_t fd, short flags, void *arg) noexcept {
		((HandleBase *) arg)->base_run();
	}

	rrr_event_handle Collection::push_periodic(HandleBase *base, uint64_t interval_us) {
		rrr_event_handle handle = RRR_EVENT_HANDLE_STRUCT_INITIALIZER;
		if (rrr_event_collection_push_periodic (
				&handle,
				&collection,
				__handle_callback,
				base,
				interval_us
		)) {
			throw E(std::string("Failed to push event in ") + __func__);
		}
		return handle;
	}

	void Collection::dispatch_break() {
		rrr_event_dispatch_break(queue);
	}

	Collection::Collection(struct rrr_event_queue *queue) :
		queue(queue),
		collection(RRR_EVENT_COLLECTION_STRUCT_INITIALIZER),
		handles(),
		actions(*this)
	{
		rrr_event_collection_init(&collection, queue);
	}

	Collection::~Collection() {
		rrr_event_collection_clear(&collection);
	}
}; // namespace RRR::Event
