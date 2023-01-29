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

#include "Factory.hxx"
#include "Js.hxx"

extern "C" {
};

#include <v8.h>

struct rrr_instance_config_data;

namespace RRR::JS {
	class Config : public Native<Config> {
		friend class ConfigFactory;

		private:
		struct rrr_instance_config_data *config = nullptr;

		protected:
		int64_t get_total_memory() final {
			return sizeof(*this);
		}

		static void cb_has(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_get(const v8::FunctionCallbackInfo<v8::Value> &info);

		void set_config(struct rrr_instance_config_data *config) {
			this->config = config;
		}
	};

	class ConfigFactory : public Factory<Config> {
		private:
		v8::Local<v8::FunctionTemplate> tmpl_has;
		v8::Local<v8::FunctionTemplate> tmpl_get;

		protected:
		void new_internal_precheck () final;
		Config *new_native(v8::Isolate *isolate) final;

		public:
		ConfigFactory(CTX &ctx, PersistentStorage<Persistable> &persistent_storage);
		Duple<v8::Local<v8::Object>, Config *> new_external (
				v8::Isolate *isolate,
				struct rrr_instance_config_data *config
		);
	};
} // namespace RRR::JS
