/*

Read Route Record

Copyright (C) 2023-2024 Atle Solbakken atle@goliathdns.no

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

#include "Persistent.hxx"
#include <utility>
#include <map>

extern "C" {
#include "../rrr_types.h"
};

#include <v8.h>

// Print noisy debug messages
// #define RRR_JS_PERSISTENT_DEBUG_GC

namespace RRR::JS {
	unsigned long Persistable::push_persistent(v8::Local<v8::Value> value) {
		return holder->push_value(value);
	}

	v8::Local<v8::Value> Persistable::pull_persistent(unsigned long i) {
		return holder->pull_value(i);
	}

	void Persistable::clear_persistents() {
		holder->clear_values();
	}

	PersistableHolder::ValueHolder::ValueHolder(v8::Isolate *isolate, v8::Local<v8::Value> value) :
		done(false),
		value(new v8::Persistent<v8::Value>(isolate, value))
	{
	}

	unsigned long PersistableHolder::push_value(v8::Local<v8::Value> value) {
		values.emplace_back(isolate, value);
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
		RRR_MSG_1("%s %p ValueHolder created index %llu\n", __PRETTY_FUNCTION__, &values.back(), (unsigned long long) values.size() - 1);
#endif
		return values.size() - 1;
	}

	v8::Local<v8::Value> PersistableHolder::pull_value(unsigned long i) {
		return (*values[i].value).Get(isolate);
	}

	void PersistableHolder::clear_values() {
		values.clear();
	}

	void PersistableHolder::pass(const char *identifier, void *arg) {
		bus->pass(t, identifier, arg);
	}

	int64_t PersistableHolder::get_unreported_memory() {
		return t->get_unreported_memory();
	}

	int64_t PersistableHolder::get_total_memory_finalize() {
		return t->get_total_memory_finalize();
	}

	bool PersistableHolder::is_done() const {
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
		int total_count = 0;
		int done_count = 0;
#endif
		bool all_done = true;
		std::for_each(values.begin(), values.end(), [&](auto &holder){
			if (!holder.done)
				all_done = false;
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
			else {
				RRR_MSG_1("%s %p Persistent value %i is done name is %s\n",
					__PRETTY_FUNCTION__, this, total_count, name.c_str());
				done_count++;
			}
			total_count++;
#endif
		});
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
		if (done_count > 0) {
			RRR_MSG_1("%s %p Persistent %i of %i values are done name is %s\n",
				__PRETTY_FUNCTION__, this, done_count, total_count, name.c_str());
		}
		if (all_done) {
			RRR_MSG_1("%s %p Persistent all done! name is %s\n",
				__PRETTY_FUNCTION__, this, name.c_str());
		}
#endif
		return all_done;
	}

	void PersistableHolder::check_complete() {
		if (is_weak) {
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
			int64_t time_limit = RRR::util::time_get_i64() - 10 * 1000 * 1000; // 10 seconds
			if (creation_time < time_limit) {
				RRR_MSG_1("Persistent is still present 10 seconds after weak was set, possible memory leak. Name is %s.\n",
					__PRETTY_FUNCTION__, this, name.c_str());
			}
#else
			// Already weak, nothing to do
#endif
		}
		else if (t->is_complete()) {
			assert(values.size() >= 1);

#ifdef RRR_JS_PERSISTENT_DEBUG_GC
			RRR_MSG_1("%s %p Persistent is complete, setting weak for the first value name is %s\n",
				__PRETTY_FUNCTION__, this, name.c_str());
#endif
			// SetWeak will cause us to be notified in the
			// gc() callback after all other references to
			// the object in the JS code are gone and just
			// before the JS object is destroyed.
			auto &holder = values[0];
			holder.value->template SetWeak<void>(&holder, gc, v8::WeakCallbackType::kParameter);

			// Remove all but the first element (the main object) to prevent dangling references
			while (values.size() > 1) {
				values.back().value->Reset();
				values.pop_back();
			}

			is_weak = true;
		}
	}

	void PersistableHolder::gc(const v8::WeakCallbackInfo<void> &info) {
		auto holder = (ValueHolder *) info.GetParameter();
		holder->done = true;
		holder->value->Reset();
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
		RRR_MSG_1("%s %p ValueHolder Now GCed by V8\n",
			__PRETTY_FUNCTION__, holder);
#endif
	}

	PersistableHolder::PersistableHolder(v8::Isolate *isolate, v8::Local<v8::Object> obj, const std::string &name, Persistable *t, PersistentBus *bus) :
		t(t),
		isolate(isolate),
		values(),
		bus(bus),
		is_weak(false),
		creation_time(RRR::util::time_get_i64()),
		name(name)
	{
		push_value(obj);
		t->register_bus(this);
		t->register_holder(this);
	}

	PersistentStorage::PersistentStorage(v8::Isolate *isolate) :
		isolate(isolate),
		persistents(),
		bus()
	{
	}

	void PersistentStorage::report_memory(int64_t memory) {
		isolate->AdjustAmountOfExternalAllocatedMemory(memory);
		total_memory += memory;
		assert(total_memory >= 0);
	}

	void PersistentStorage::push(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t, const std::string &name) {
		persistents.emplace_front(new PersistableHolder(isolate, obj, name, t, &bus));
		entries++;
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
		RRR_MSG_1("%s %p Persistent with name %s is pushed, %lli entries now in storeage\n",
			__PRETTY_FUNCTION__, persistents.front().get(), name.c_str(), entries);
#endif
	}

	void PersistentStorage::register_sniffer(PersistentSniffer *sniffer) {
		bus.push_sniffer(sniffer);
	}

	void PersistentStorage::gc() {
		std::for_each(persistents.begin(), persistents.end(), [&](auto &p){
			int64_t memory = p->get_unreported_memory();
			if (memory != 0) {
				report_memory(memory);
			}
			p->check_complete();
		});

		if (entries > entries_max) {
			std::map<std::string, int> map;
			RRR_MSG_0("Maximum number of JS persistents (%i>%i) reached in %s, possible memory leak. Dumping count of different persistables by their name:\n",
				entries, entries_max, __PRETTY_FUNCTION__);
			std::for_each(persistents.begin(), persistents.end(), [&](auto &p){
				map[p->name]++;
			});
			std::for_each(map.begin(), map.end(), [&](auto &e){
				RRR_MSG_0("- %s: %i\n", e.first.c_str(), e.second);
			});
			RRR_BUG("Refusing to continue.\n");
		}

		persistents.remove_if([this](auto &p){
			if (p->is_done()) {
				entries--;
#ifdef RRR_JS_PERSISTENT_DEBUG_GC
				RRR_MSG_1("%s %p Persistent is done, %lli entries left in storage\n", __PRETTY_FUNCTION__, p.get(), entries);
#endif
				// Report negative value as memory is now being freed up
				report_memory(/* Remember negation minus sign */ - p->get_total_memory_finalize());
				return true;
			}
			return false;
		});
	}
} // namespace RRR::JS
