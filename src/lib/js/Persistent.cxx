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

extern "C" {
#include "../rrr_types.h"
};

#include <v8.h>

namespace RRR::JS {
	void PersistentStorage::Persistent::gc(const v8::WeakCallbackInfo<void> &info) {
		auto self = (Persistent *) info.GetParameter();
		self->persistent.Reset();
		self->done = true;
	}
	PersistentStorage::Persistent::Persistent(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t, PersistentBus *bus) :
		t(t),
		persistent(isolate, obj),
		done(false),
		bus(bus)
	{
		persistent.SetWeak<void>(this, gc, v8::WeakCallbackType::kParameter);
		t->register_bus(this);
	}
	void PersistentStorage::gc(rrr_biglength *entries_, rrr_biglength *memory_size_) {
		rrr_biglength entries_acc = 0;
		std::for_each(persistents.begin(), persistents.end(), [this](auto &p){
			int64_t memory = p->get_unreported_memory();
			if (memory != 0) {
				report_memory(memory);
			}
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
