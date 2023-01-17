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
#include <sys/socket.h>
//#include "../rrr_types.h"
};

#include <v8.h>

#include "Js.hxx"

namespace RRR::JS {
	class Message : public Object {
		private:
		struct sockaddr_storage ip_addr;
		socklen_t ip_addr_len;
		std::string ip_so_type;

		template <class T> static Message *self(const T &info) {
			auto self = info.Holder();
			auto wrap = v8::Local<v8::External>::Cast(self->GetInternalField(0));
			return (Message *) wrap->Value();
		}
		static void cb_ip_addr_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_ip_addr_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_ip_so_type_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_ip_so_type_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_ip_get(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_ip_set(const v8::FunctionCallbackInfo<v8::Value> &info);

		protected:
		Message(CTX &ctx, v8::Local<v8::Object> obj);

		public:
		class Template {
			friend class Message;

			private:
			v8::Local<v8::ObjectTemplate> tmpl;
			v8::Local<v8::FunctionTemplate> tmpl_ip_get;
			v8::Local<v8::FunctionTemplate> tmpl_ip_set;

			protected:
			Template(CTX &ctx);

			public:
			Message new_instance(CTX &ctx);
		};

		static Template make_template(CTX &ctx);
	};
}; // namespace RRR::JS

/*
  ip_addr: new ArrayBuffer(),  // Operating system raw IP address information (struct sockaddr)
  ip_so_type: "",              // Protocol, set to udp or tcp. May also be empty.
  topic: "",                   // MQTT topic of the message
  timestamp: 0,                // The timestamp of the message in microseconds
  data: new ArrayBuffer(),     // The raw data of the message (ignored when arrays are used)
  type: 1,                     // Message type
  class: 1                     // Message class
*/
