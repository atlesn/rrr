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

#include "Persistent.hxx"
#include <utility>

extern "C" {
#include "../rrr_types.h"
};

#include <v8.h>

namespace RRR::JS {
	int Persistable::push_persistent(v8::Local<v8::Value> value) {
		return holder->push_value(value);
	}

	v8::Local<v8::Value> Persistable::pull_persistent(int i) {
		return holder->pull_value(i);
	}

	PersistableHolder::DoneState::DoneState() :
		done(false),
		persistent(nullptr)
	{
	}

	PersistableHolder::DoneState::DoneState(bool done, v8::Persistent<v8::Value> *persistent) :
		done(done),
		persistent(persistent)
	{
	}

	int PersistableHolder::push_value(v8::Local<v8::Value> value) {
		values.emplace(std::pair(value_pos, new v8::Persistent<v8::Value>(isolate, value)));
		values_done.emplace(std::pair(value_pos, DoneState(value_pos, values[value_pos].get())));
		return value_pos++;
	}

	v8::Local<v8::Value> PersistableHolder::pull_value(int i) {
		return (*values[i]).Get(isolate);
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
		int done_pos = 0;
		std::for_each(values_done.begin(), values_done.end(), [&done_pos](auto &pair){
			if (pair.second.done)
				done_pos++;
		});
		return value_pos == done_pos;
	}

	void PersistableHolder::check_complete() {
		if (!is_weak && t->is_complete()) {
			std::for_each(values.begin(), values.end(), [this](auto &pair){
				(*pair.second).template SetWeak<void>(&values_done[pair.first], gc, v8::WeakCallbackType::kParameter);
			});
			is_weak = true;
		}
	}

	void PersistableHolder::gc(const v8::WeakCallbackInfo<void> &info) {
		auto done_info = (DoneState *) info.GetParameter();
		done_info->done = true;
		done_info->persistent->Reset();
	}

	PersistableHolder::PersistableHolder(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t, PersistentBus *bus) :
		t(t),
		isolate(isolate),
		values(),
		bus(bus),
		value_pos(0),
		is_weak(false)
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

	void PersistentStorage::push(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t) {
		persistents.emplace_front(new PersistableHolder(isolate, obj, t, &bus));
		entries++;
	}

	void PersistentStorage::register_sniffer(PersistentSniffer *sniffer) {
		bus.push_sniffer(sniffer);
	}

	void PersistentStorage::gc(rrr_biglength *entries_, rrr_biglength *memory_size_) {
		std::for_each(persistents.begin(), persistents.end(), [this](auto &p){
			int64_t memory = p->get_unreported_memory();
			if (memory != 0) {
				report_memory(memory);
			}
			p->check_complete();
		});
		persistents.remove_if([this](auto &p){
			if (p->is_done()) {
				entries--;
				// Report negative value as memory is now being freed up
				report_memory(-p->get_total_memory_finalize());
			}
			return p->is_done();
		});

		*entries_ = (rrr_biglength) entries;
		*memory_size_ = (rrr_biglength) total_memory;
	}
} // namespace RRR::JS
