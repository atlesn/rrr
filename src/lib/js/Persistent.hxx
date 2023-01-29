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

#pragma once

extern "C" {
#include "../rrr_types.h"
};

#include <v8.h>
#include <algorithm>
#include <forward_list>
#include <cassert>

namespace RRR::JS {
	class Persistable {
		private:
		int64_t total_memory = 0;

		protected:
		// Derived classes must implement this and report the current
		// estimated size of the object so that we can report changes
		// to V8.
		virtual int64_t get_total_memory() = 0;

		public:
		// Called reguralerly by storage
		int64_t get_unreported_memory() {
			int64_t total_memory_new = get_total_memory();
			int64_t diff = total_memory_new - total_memory;
			total_memory = total_memory_new;
			return diff;
		}
		// Called by storage before object is destroyed
		int64_t get_total_memory_finalize() {
			assert(total_memory >= 0);
			int64_t ret = total_memory;
			total_memory = 0;
			return ret;
		}
		// Called for statistics purposes
		int64_t get_total_memory_stats() const {
			return total_memory;
		}
		virtual ~Persistable() = default;
	};

	template <class T> class PersistentStorage {
		private:
		template <class U> class Persistent {
			private:
			v8::Persistent<v8::Object> persistent;
			bool done;
			std::unique_ptr<U> t;

			public:
			int64_t get_unreported_memory() {
				return t->get_unreported_memory();
			}
			int64_t get_total_memory_finalize() {
				return t->get_total_memory_finalize();
			}
			static void gc(const v8::WeakCallbackInfo<void> &info) {
				auto self = (Persistent<U> *) info.GetParameter();
				self->persistent.Reset();
				self->done = true;
			}
			Persistent(v8::Isolate *isolate, v8::Local<v8::Object> obj, U *t) :
				t(t),
				persistent(isolate, obj),
				done(false)
			{
				persistent.SetWeak<void>(this, gc, v8::WeakCallbackType::kParameter);
			}
			Persistent(const Persistent &p) = delete;
			bool is_done() const {
				return done;
			}
		};

		v8::Isolate *isolate;
		std::forward_list<std::unique_ptr<Persistent<T>>> persistents;
		int64_t entries = 0;
		int64_t total_memory = 0;

		public:
		PersistentStorage(v8::Isolate *isolate) :
			isolate(isolate),
			persistents()
		{
		}
		PersistentStorage(const PersistentStorage &p) = delete;
		void report_memory(int64_t memory) {
			isolate->AdjustAmountOfExternalAllocatedMemory(memory);
			total_memory += memory;
			assert(total_memory > 0);
		}
		void push(v8::Isolate *isolate, v8::Local<v8::Object> obj, T *t) {
			persistents.emplace_front(new Persistent(isolate, obj, t));
			entries++;
		}
		void gc(rrr_biglength *entries_, rrr_biglength *memory_size_) {
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
	};
} // namespace RRR::JS
