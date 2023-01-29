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

#include "Js.hxx"

extern "C" {
#include "../rrr_types.h"
};

#include <v8.h>
#include <string.h>
#include <memory>

namespace RRR::JS {
#ifdef RRR_HAVE_V8_BACKINGSTORE
	class BackingStore {
		private:
		std::shared_ptr<v8::BackingStore> store;
		v8::Local<v8::ArrayBuffer> array;

		BackingStore(v8::Isolate *isolate, const void *data, size_t size) :
			store(v8::ArrayBuffer::NewBackingStore(isolate, size)),
			array(v8::ArrayBuffer::New(isolate, store))
		{
			memcpy(store->Data(), data, size);
		}

		BackingStore(v8::Isolate *isolate, v8::Local<v8::ArrayBuffer> array) :
			store(array->GetBackingStore()),
			array(array)
		{
		}
		public:
		static Duple<BackingStore, v8::Local<v8::ArrayBuffer>> create(v8::Isolate *isolate, const void *data, size_t size) {
			auto store = BackingStore(isolate, data, size);
			return Duple(store, store.array);
		}
		static Duple<BackingStore,v8::Local<v8::ArrayBuffer>> create(v8::Isolate *isolate, v8::Local<v8::ArrayBuffer> array) {
			auto store = BackingStore(isolate, array);
			return Duple(store, store.array);
		}
		size_t size() {
			return store->ByteLength();
		}
		void *data() {
			return store->Data();
		}
	};
#else
	class BackingStore {
		private:
		v8::Local<v8::ArrayBuffer> array;
		v8::ArrayBuffer::Contents contents;

		BackingStore(v8::Isolate *isolate, const void *data, size_t size) :
			array(v8::ArrayBuffer::New(isolate, size)),
			contents(array->GetContents())
		{
			memcpy(contents.Data(), data, size);
		}

		BackingStore(v8::Isolate *isolate, v8::Local<v8::ArrayBuffer> array) :
			array(array),
			contents(array->GetContents())
		{
		}

		public:
		static Duple<BackingStore, v8::Local<v8::ArrayBuffer>> create(v8::Isolate *isolate, const void *data, size_t size) {
			auto store = BackingStore(isolate, data, size);
			return Duple(store, store.array);
		}
		static Duple<BackingStore,v8::Local<v8::ArrayBuffer>> create(v8::Isolate *isolate, v8::Local<v8::ArrayBuffer> array) {
			auto store = BackingStore(isolate, array);
			return Duple(store, store.array);
		}
		size_t size() {
			return contents.ByteLength();
		}
		void *data() {
			return contents.Data();
		}
	};
#endif
} // namespace RRR::JS
