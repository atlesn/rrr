
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

#include "OS.hxx"
#include "Js.hxx"

extern "C" {
#include <unistd.h>
#include <errno.h>

#include "../allocator.h"
#include "../rrr_strerror.h"
#include "../rrr_limits.h"
};

#include <v8.h>

namespace RRR::JS {
	void OS::cb_hostname(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		char hostname[RRR_HOST_NAME_MAX + 1];

		if (info.Length() != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "hostname() takes no arguments")));
			return;
		}

		if (gethostname(hostname, sizeof(hostname)) != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, std::string("gethostname() failed: ") + rrr_strerror(errno))));
			return;
		}

		// Terminating zero is not always guaranteed
		hostname[sizeof(hostname) - 1] = '\0';

		info.GetReturnValue().Set((v8::Local<v8::String>) String(isolate, hostname));
	}

	OS *OSFactory::new_native(v8::Isolate *isolate) {
		return new OS();
	}

	OSFactory::OSFactory(CTX &ctx, PersistentStorage &persistent_storage) :
		Factory("OS", ctx, persistent_storage),
		tmpl_hostname(v8::FunctionTemplate::New(ctx, OS::cb_hostname))
	{
		auto tmpl = get_object_template();
		tmpl->Set(ctx, "hostname", tmpl_hostname);
	}

	Duple<v8::Local<v8::Object>, OS *> OSFactory::new_external (
			v8::Isolate *isolate
	) {
		auto duple = new_internal(isolate, new_external_function(isolate));
		return duple;
	}
} // namespace RRR::JS
