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

#include "EventQueue.hxx"
#include "Js.hxx"

namespace RRR::JS {
	void EventQueue::dispatch() {
		const int64_t now = RRR::util::time_get_i64();
		int64_t next_exec_time = now + (int64_t) default_interval_us;

		for (auto it = timeout_events.begin(); it != timeout_events.end();) {
			bool erase = false;
			if (!it->is_alive()) {
				erase = true;
			}
			else if (now >= it->get_exec_time()) {
				Scope scope(ctx);
				it->acknowledge();
				if (ctx.trycatch_ok([](auto msg){
					throw E(std::string("Error while running event: ") + msg);
				})) {
					// OK
				}
				erase = true;
			}
			
			if (erase) {
				it = timeout_events.erase(it);
			}
			else {
				// List is sorted by execution time, and no more timers has expired
				next_exec_time = it->get_exec_time();
				break;
			}
		}

		const int64_t next_interval = next_exec_time - now;
		assert (next_interval > 0);
		handle->set_interval((uint64_t) next_interval > default_interval_us
			? default_interval_us
			: (uint64_t) next_interval
		);
		handle->add();
	}

	bool EventQueue::accept(std::weak_ptr<Persistable> object, const char *identifier, void *arg) {
		if (strcmp(identifier, MSG_SET_TIMEOUT) == 0) {
			timeout_events.emplace(object, RRR::util::time_get_i64() + * (int64_t *) arg, arg);
			return true;
		}
		return false;
	}

	std::function<void(EventQueue *)> EventQueue::callback([](EventQueue *queue){
		queue->dispatch();
	});

	EventQueue::EventQueue(CTX &ctx, PersistentStorage &persistent_storage, RRR::Event::Collection &collection) :
		timeout_events(),
		ctx(ctx),
		collection(collection),
		handle()
	{
		persistent_storage.register_sniffer(this);
		handle = collection.push_periodic(callback, this, initial_interval_us);
		handle->add();
	}
}; // namespace RRR::JS
