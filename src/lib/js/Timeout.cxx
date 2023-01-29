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

#include "Timeout.hxx"
#include "BackingStore.hxx"
#include "Js.hxx"

extern "C" {
#include "../allocator.h"
};

#include <v8.h>

namespace RRR::JS {
	void gc(const v8::WeakCallbackInfo<void> &info) {
		printf("GC from timeout\n");
	}

	Timeout::Timeout(v8::Isolate *isolate) :
		isolate(isolate)
	{
	}

	Timeout::~Timeout() {
		printf("Timeout destructor\n");
	}

	void Timeout::acknowledge(void *arg) {
		if (cleared) {
			return;
		}
		cleared = true;

		std::vector<v8::Local<v8::Value>> argv;
		std::for_each(args_pos.begin(), args_pos.end(), [this, &argv](auto i){
			argv.emplace_back(pull_persistent(i));
		});
		v8::Local<v8::Value> function = pull_persistent(func_pos);

		int argc = (int) argv.size();
		assert(argc >= 0);
		auto value = function.As<v8::Function>()->Call(isolate->GetCurrentContext(), isolate->GetCurrentContext()->Global(), argc, argc > 0 ? argv.data() : nullptr);
		if (value.IsEmpty()) {
			throw E(std::string("Empty return value from function in ") + __func__);
		}
	}

	bool Timeout::is_complete() const {
		return cleared;
	}

	void Timeout::cb_clear(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto timeout = self(info);
		timeout->cleared = true;
	}

	void TimeoutFactory::construct (Timeout *timeout, const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();

		if (info.Length() == 0) {
			throw E(std::string("Callback argument missing to Timeout constructor"));
		}

		if (!info[0]->IsFunction()) {
			throw E(std::string("First argument to Timeout constructor was not a function"));
		}

		timeout->set_function(info[0].As<v8::Function>());

		if (info.Length() >= 2) {
			auto value = info[1]->ToUint32(ctx);
			if (value.IsEmpty()) {
				throw E(std::string("Second argument to Timeout constructor was not a number"));
			}
			auto value_uint = value.ToLocalChecked()->Uint32Value(ctx);
			if (value_uint.IsNothing()) {
				throw E(std::string("Failed to get the number value of the second argument to Timeout constructor"));
			}
			timeout->set_timeout(value_uint.ToChecked());
		}

		for (int i = 2; i < info.Length(); i++) {
			timeout->push_arg(info[i]);
		}

		timeout->finalize();
	}

	Timeout *TimeoutFactory::new_native(v8::Isolate *isolate) {
		return new Timeout(isolate);
	}

	TimeoutFactory::TimeoutFactory(CTX &ctx, PersistentStorage &persistent_storage) :
		Factory("Timeout", ctx, persistent_storage),
		tmpl_clear(v8::FunctionTemplate::New(ctx, Timeout::cb_clear))
	{
		auto tmpl = get_object_template();
		tmpl->Set(ctx, "clear", tmpl_clear);
	}

	Duple<v8::Local<v8::Object>, Timeout *> TimeoutFactory::new_external (
			v8::Isolate *isolate
	) {
		auto duple = new_internal(isolate, new_external_function(isolate));
		return duple;
	}
} // namespace RRR::JS
