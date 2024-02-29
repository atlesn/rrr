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

#include "Config.hxx"
#include "../InstanceConfig.hxx"
#include "BackingStore.hxx"
#include "Js.hxx"

extern "C" {
#include "../allocator.h"
};

#include <v8.h>

namespace RRR::JS {
	void Config::cb_has(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto config = self(info);

		if (info.Length() == 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "missing configuration parameter name")));
			return;
		}
		if (!info[0]->IsString()) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "configuration parameter name was not a string")));
			return;
		}

		std::string name_str = String(isolate, info[0]->ToString(ctx).ToLocalChecked());

		info.GetReturnValue().Set(v8::Boolean::New(
			isolate,
			rrr_settings_exists(config->settings_used, config->settings, name_str.c_str());
		));
	}

	void Config::cb_get(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto config = self(info);

		if (info.Length() == 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "missing configuration parameter name")));
			return;
		}
		if (!info[0]->IsString()) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "configuration parameter name was not a string")));
			return;
		}

		auto parameter = String(isolate, info[0]->ToString(ctx).ToLocalChecked());
		auto instance_config = InstanceConfig(config->config);
		if (!instance_config.has(parameter)) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, std::string("configuration parameter '") + (std::string) parameter + "' not found")));
			return;
		}

		info.GetReturnValue().Set((v8::Local<v8::String>) String(isolate, instance_config.get(parameter)));
	}

	void ConfigFactory::new_internal_precheck () {
		throw E("Creation of Config object using new is not possible");
	}

	Config *ConfigFactory::new_native(v8::Isolate *isolate) {
		return new Config();
	}

	ConfigFactory::ConfigFactory(CTX &ctx, PersistentStorage &persistent_storage) :
		Factory("Config", ctx, persistent_storage),
		tmpl_has(v8::FunctionTemplate::New(ctx, Config::cb_has)),
		tmpl_get(v8::FunctionTemplate::New(ctx, Config::cb_get))
	{
		auto tmpl = get_object_template();
		tmpl->Set(ctx, "has", tmpl_has);
		tmpl->Set(ctx, "get", tmpl_get);
	}

	Duple<v8::Local<v8::Object>, Config *> ConfigFactory::new_external (
			v8::Isolate *isolate,
			struct rrr_settings *settings,
			struct rrr_settings_used *settings_used
	) {
		auto duple = new_internal(isolate, new_external_function(isolate));

		duple.second()->set_config(settings, settings_used);

		return duple;
	}
} // namespace RRR::JS
