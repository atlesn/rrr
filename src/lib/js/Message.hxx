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
//#include "../rrr_types.h"
};

#include <v8.h>

#include "Js.hxx"

namespace RRR::JS {
	class Message : public Value {
		private:
		v8::Local<v8::ArrayBuffer> ip_addr;
		v8::Local<v8::String> ip_so_type;
		v8::Local<v8::Function> ip_set;
		v8::Local<v8::Function> ip_get;

		static void cb_ip_set(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_ip_get(const v8::FunctionCallbackInfo<v8::Value> &info);

		public:
		Message(CTX &ctx);
	};
}; // namespace RRR::JS

/*
{
  ip_addr: new ArrayBuffer(),  // Operating system raw IP address information (struct sockaddr)
  ip_so_type: "",              // Protocol, set to udp or tcp. May also be empty.

  ip_set: function(ip, port){}              // Helper function to set adddress of ip_addr field
  ip_get: function(){ return [ip, port]; }  // Helper function to retrieve adddress of ip_addr field
}
*/
