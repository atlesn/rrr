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
#include "Factory.hxx"

extern "C" {
};

#include "EventQueue.hxx"

#include <v8.h>

namespace RRR::JS {
	class Timeout : public Native<Timeout> {
		friend class TimeoutFactory;

		v8::Local<v8::Context> ctx;
		v8::Local<v8::Function> function;
		std::vector<v8::Local<v8::Value>> args;
		uint32_t timeout_ms = 0;
		int64_t timeout_us = 0;

		private:
		bool cleared = false;

		protected:
		Timeout(v8::Local<v8::Context> ctx) :
			ctx(ctx)
		{
		}
		int64_t get_total_memory() final {
			return sizeof(*this);
		}
		void acknowledge(void *arg);
		void set_timeout(uint32_t timeout_ms) {
			this->timeout_ms = timeout_ms;
		}
		void set_function(v8::Local<v8::Function> function) {
			this->function = function;
		}
		void push_arg(v8::Local<v8::Value> arg) {
			args.emplace_back(arg);
		}
		void finalize() {
			timeout_us = timeout_ms * 1000;
			pass(EventQueue::MSG_SET_TIMEOUT, &timeout_us);
		}
		static void cb_clear(const v8::FunctionCallbackInfo<v8::Value> &info);
	};

	class TimeoutFactory : public Factory<Timeout> {
		private:
		v8::Local<v8::FunctionTemplate> tmpl_clear;
		v8::Local<v8::FunctionTemplate> tmpl_reset;

		protected:
		Timeout *new_native(v8::Isolate *isolate) final;
		void construct (Timeout *timeout, const v8::FunctionCallbackInfo<v8::Value> &info) final;

		public:
		TimeoutFactory(CTX &ctx, PersistentStorage &persistent_storage);
		Duple<v8::Local<v8::Object>, Timeout *> new_external (
				v8::Isolate *isolate
		);
	};
} // namespace RRR::JS
