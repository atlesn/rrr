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

#define RRR_JS_EVENT_INACCURACY_TOLERANCE_MS 500
//#define RRR_JS_EVENT_QUEUE_DEBUG

namespace RRR::JS {
	void EventQueue::set_next_exec_time() {
		int64_t now = RRR::util::time_get_i64();
		int64_t next_exec_time = now + (int64_t) default_interval_us;

#ifdef RRR_JS_EVENT_QUEUE_DEBUG
		int i = 0;
		for (auto it = timeout_events.begin(); it != timeout_events.end(); ++it) {
			RRR_MSG_1("%s - exec time for timer %i in %lli us\n",
				__PRETTY_FUNCTION__, i++, it->get_exec_time() - now);
		}
#endif

		if (!timeout_events.empty()) {
			next_exec_time = timeout_events.begin()->get_exec_time();
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
			RRR_MSG_1("%s - set next exec time in %lli us\n",
				__PRETTY_FUNCTION__, next_exec_time - now);
#endif
		}

		int64_t next_interval = next_exec_time - now;
		if (next_interval < 1) {
			if (next_interval < -(RRR_JS_EVENT_INACCURACY_TOLERANCE_MS * 1000)) {
				RRR_MSG_0("Warning: Inaccurate timer dispatch detected in %s, not able to run all timeout events fast enough.\n",
					__PRETTY_FUNCTION__);
			}
			next_interval = 1;
		}
		else if ((uint64_t) next_interval > default_interval_us) {
			next_interval = default_interval_us;
		}

#ifdef RRR_JS_EVENT_QUEUE_DEBUG
		RRR_MSG_1("%s - Next dispatch in %lli us (default is %lli)\n",
			__PRETTY_FUNCTION__, next_interval, (long long) default_interval_us);
#endif
		handle->set_interval(next_interval);
		handle->add();
	}

	void EventQueue::dispatch() {
		// The event list must be sorted by execution time.
		const int max = 10;
		int i = -1;
		while (i++ < max) {

			// Get now time each round in case callback is slow
			int64_t now = RRR::util::time_get_i64();

#ifdef RRR_JS_EVENT_QUEUE_DEBUG
			RRR_MSG_1("%s loop %i there are %llu timeout events\n", __PRETTY_FUNCTION__, i, (unsigned long long) timeout_events.size());
#endif

			// Start iteration from the beginning every time the list is modified
			int j = -1;
			for (auto it = timeout_events.begin(); it != timeout_events.end() && j++ < max; it = timeout_events.begin()) {
				const int64_t it_exec_time = it->get_exec_time();

#ifdef RRR_JS_EVENT_QUEUE_DEBUG
				RRR_MSG_1("%s - [%i] {%s} exec time %lli (in %lli us)\n",
					__PRETTY_FUNCTION__, j, it->get_identifier(), (long long) it_exec_time, (long long) it_exec_time - now);
#endif

				if (!it->is_alive()) {
					timeout_events.erase(it);
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
					RRR_MSG_1("%s - [%i] erase, object is not alive\n", __PRETTY_FUNCTION__, j);

					// Restart iteration from the beginning, list has changed
					break;
#endif
				}

				if (now >= it_exec_time) {
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
					RRR_MSG_1("%s - [%i] acknowledge and erase, exec time has passed\n", __PRETTY_FUNCTION__, j);
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

					// Restart iteration from the beginning, list has changed
					break;
				}

				// The following events cannot have lower execution time
				goto done;
			}

			if (j == -1)
				break;
			if (j >= max)
				RRR_MSG_0("Warning: Max inner iterations reached in %s\n", __PRETTY_FUNCTION__);
		}

		done:

		if (i >= max) {
			RRR_MSG_0("Warning: Max outer iterations reached in %s\n", __PRETTY_FUNCTION__);
		}

		set_next_exec_time();
	}

	bool EventQueue::accept(std::weak_ptr<Persistable> object, const char *identifier, void *arg) {
		if (strcmp(identifier, MSG_SET_TIMEOUT) == 0) {
			int64_t interval = * (int64_t *) arg;
#ifdef RRR_JS_EVENT_QUEUE_DEBUG
			RRR_MSG_1("%s push timer exec in %lli us\n",
				__PRETTY_FUNCTION__, interval);
#endif
			timeout_events.emplace(object, RRR::util::time_get_i64() + interval, identifier, arg);
			set_next_exec_time();
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
