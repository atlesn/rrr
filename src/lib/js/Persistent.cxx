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
	void Persistable::pass(const char *identifier, void *arg) {
		forwarder->pass(identifier, arg);
	}
	int Persistable::push_persistent(v8::Local<v8::Value> value) {
		return holder->push_value(value);
	}

	v8::Local<v8::Value> Persistable::pull_persistent(int i) {
		return holder->pull_value(i);
	}

	int PersistableHolder::push_value(v8::Local<v8::Value> value) {
		values.emplace(std::pair(value_pos, v8::Persistent<v8::Value>(isolate, value)));
		return value_pos++;
	}

	v8::Local<v8::Value> PersistableHolder::pull_value(int i) {
		return (*values[i]).Get(isolate);
	}

	void PersistableHolder::check_complete() {
		if (!is_weak && t->is_complete()) {
			printf("Setting weak\n");
			std::for_each(values.begin(), values.end(), [this](auto &pair){
				(*pair.second).SetWeak();
			});
			is_weak = true;
		}
	}
	void PersistableHolder::gc(const v8::WeakCallbackInfo<void> &info) {
		auto self = (PersistableHolder *) info.GetParameter();
		std::for_each(self->values.begin(), self->values.end(), [self](auto &pair){
			printf("Reset\n");
			(*pair.second).Reset();
		});
		self->done = true;
	}
	PersistableHolder::PersistableHolder(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t, PersistentBus *bus) :
		t(t),
		isolate(isolate),
		values(),
		done(false),
		bus(bus)
	{
		push_value(obj);
		t->register_bus(this);
		t->register_holder(this);
	}
	void PersistentStorage::gc(rrr_biglength *entries_, rrr_biglength *memory_size_) {
		rrr_biglength entries_acc = 0;
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
