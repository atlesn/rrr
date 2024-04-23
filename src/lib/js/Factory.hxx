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

#include "Persistent.hxx"
#include "Js.hxx"
#include "../util/E.hxx"

namespace RRR::JS {
	template <class T> class Factory {
		private:
		std::string name;
		v8::Local<v8::FunctionTemplate> function_tmpl_base;
		v8::Local<v8::FunctionTemplate> function_tmpl_internal;
		v8::Local<v8::FunctionTemplate> function_tmpl_external;

		PersistentStorage &persistent_storage;

		protected:
		virtual void new_internal_precheck () {}
		virtual T* new_native(v8::Isolate *isolate) = 0;
		virtual void construct (T *t, const v8::FunctionCallbackInfo<v8::Value> &info) {};

		v8::Local<v8::Object> new_external_function(v8::Isolate *isolate);
		v8::Local<v8::ObjectTemplate> get_object_template();
		Duple<v8::Local<v8::Object>, T *> new_internal (v8::Isolate *isolate, v8::Local<v8::Object> obj);

		static void cb_construct_base(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_construct_internal(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_construct_external(const v8::FunctionCallbackInfo<v8::Value> &info);

		Factory(std::string name, CTX &ctx, PersistentStorage &persistent_storage);

		public:
		static const int INTERNAL_INDEX_THIS = 0;

		void register_as_global(CTX &ctx);
	};

	template <class T> v8::Local<v8::Object> Factory<T>::new_external_function(v8::Isolate *isolate) {
		return function_tmpl_external->GetFunction(isolate->GetCurrentContext()).ToLocalChecked()->NewInstance(isolate->GetCurrentContext()).ToLocalChecked();
	}

	template <class T> v8::Local<v8::ObjectTemplate> Factory<T>::get_object_template() {
		return function_tmpl_base->InstanceTemplate();
	}

	template <class T> Duple<v8::Local<v8::Object>, T *> Factory<T>::new_internal (
			v8::Isolate *isolate,
			v8::Local<v8::Object> obj
	) {
		auto ctx = isolate->GetCurrentContext();
		auto native_obj = std::unique_ptr<T>(new_native(isolate));
		auto duple = Duple(obj, native_obj.get());
		auto base = function_tmpl_base->InstanceTemplate()->NewInstance(ctx).ToLocalChecked();

		// The accessor functions seem to receive the base object as This();
		base->SetInternalField(INTERNAL_INDEX_THIS, v8::External::New(isolate, native_obj.get()));

		// The other functions seem to receive the derived object as This();
		obj->SetInternalField(INTERNAL_INDEX_THIS, v8::External::New(isolate, native_obj.get()));

		obj->SetPrototype(ctx, base).Check();

		persistent_storage.push(isolate, obj, native_obj.release(), name);

		return duple;
	}

	template <class T> void Factory<T>::cb_construct_base(const v8::FunctionCallbackInfo<v8::Value> &info) {
		info.GetReturnValue().Set(info.This());
	}

	template <class T> void Factory<T>::cb_construct_internal(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto self = (Factory *) v8::External::Cast(*info.Data())->Value();

		try {
			self->new_internal_precheck();
			auto duple = self->new_internal(isolate, info.This());
			self->construct(duple.second(), info);
		}
		catch (E e) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, std::string("Could not create object: ") + (std::string) e)));
			return;
		}

		info.GetReturnValue().Set(info.This());
	}

	template <class T> void Factory<T>::cb_construct_external(const v8::FunctionCallbackInfo<v8::Value> &info) {
		info.GetReturnValue().Set(info.This());
	}

	template <class T> Factory<T>::Factory(std::string name, CTX &ctx, PersistentStorage &persistent_storage) :
		name(name),
		persistent_storage(persistent_storage),
		function_tmpl_base(v8::FunctionTemplate::New(ctx, cb_construct_base, v8::External::New(ctx, this))),
		function_tmpl_internal(v8::FunctionTemplate::New(ctx, cb_construct_internal, v8::External::New(ctx, this))),
		function_tmpl_external(v8::FunctionTemplate::New(ctx, cb_construct_external, v8::External::New(ctx, this)))
	{
		function_tmpl_base->InstanceTemplate()->SetInternalFieldCount(1);
		function_tmpl_internal->InstanceTemplate()->SetInternalFieldCount(1);
		function_tmpl_external->InstanceTemplate()->SetInternalFieldCount(1);
	}

	template <class T> void Factory<T>::register_as_global(CTX &ctx) {
		ctx.set_global(name, function_tmpl_internal->GetFunction(ctx).ToLocalChecked());
	}

	template <class N> class Native : public Persistable {
		public:
		virtual ~Native() = default;

		protected:
		template <class T> static N *self(const T &info) {
			auto self = info.Holder();
			auto wrap = v8::Local<v8::External>::Cast(self->GetInternalField(Factory<N>::INTERNAL_INDEX_THIS));
			return (N *) wrap->Value();
		}
	};
} // namespace RRR::JS
