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

//#define RRR_JS_EVENT_QUEUE_DEBUG

namespace RRR::JS {
	void EventQueue::dispatch() {
		int64_t now = RRR::util::time_get_i64();
		int64_t next_exec_time = now + (int64_t) default_interval_us;

#ifdef RRR_JS_EVENT_QUEUE_DEBUG
		RRR_MSG_1("%s there are %llu timeout events\n", __PRETTY_FUNCTION__, (unsigned long long) timeout_events.size());
#endif

		int i = -1;
		const int max = 50;

		// The event list must be sorted by execution time.

		while (i < max) {
			// Start iteration from the beginning every time the list is modified
			for (auto it = timeout_events.begin(); it != timeout_events.end() && i < max; it = timeout_events.begin()) {
				i++;
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
				RRR_MSG_1("%s - [%i] {%s} exec time %lli (in %lli us)\n",
					__PRETTY_FUNCTION__, i, it->get_identifier(), (long long) it->get_exec_time(), (long long) it->get_exec_time() - now);
#endif

				if (!it->is_alive()) {
					timeout_events.erase(it);
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
					RRR_MSG_1("%s - [%i] erase, object is not alive\n", __PRETTY_FUNCTION__, i);
					goto again;
#endif
				}

				if (now >= it->get_exec_time()) {
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
					RRR_MSG_1("%s - [%i] acknowledge and erase, exec time has passed\n", __PRETTY_FUNCTION__, i);
#endif
					// New elements may be inserted during acknowledgement, and possibly at the beginning
					// of the event list. Take the event out of the list now to prevent the erase function
					// erasing any newly event.
					const auto event = *it;
					timeout_events.erase(it);

					Scope scope(ctx);
					event.acknowledge();
					if (ctx.trycatch_ok([](auto msg){
						throw E(std::string("Error while running event: ") + msg);
					})) {
						// OK
					}

					// Get now time again in case callback is slow			
					now = RRR::util::time_get_i64();
					goto again;
				}

				// No more timers have possibly expired
				next_exec_time = it->get_exec_time();
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
				RRR_MSG_1("%s - [%i] set next exec time in %lli us\n", __PRETTY_FUNCTION__, i, next_exec_time - now);
#endif
				goto done;
			}

			again:
		}

		done:

		if (i >= max) {
			RRR_MSG_0("Warning: Max iterations reached in %s\n", __PRETTY_FUNCTION__);
		}

		const int64_t next_interval = next_exec_time - now;
		assert (next_interval > 0);
		handle->set_interval((uint64_t) next_interval > default_interval_us
			? default_interval_us
			: (uint64_t) next_interval
		);

#ifdef RRR_JS_EVENT_QUEUE_DEBUG
		RRR_MSG_1("%s - Next dispatch in %lli us (default is %lli)\n",
			__PRETTY_FUNCTION__, next_exec_time - now, (long long) default_interval_us);
#endif

		handle->add();
	}

	bool EventQueue::accept(std::weak_ptr<Persistable> object, const char *identifier, void *arg) {
		if (strcmp(identifier, MSG_SET_TIMEOUT) == 0) {
			timeout_events.emplace(object, RRR::util::time_get_i64() + * (int64_t *) arg, identifier, arg);
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
