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

#include "Message.hxx"

extern "C" {
#include <sys/socket.h>
};

namespace RRR::JS {
	void Message::cb_ip_set(const v8::FunctionCallbackInfo<v8::Value> &info) {
		printf("Set ip\n");
	}

	void Message::cb_ip_get(const v8::FunctionCallbackInfo<v8::Value> &info) {
		printf("Get ip");
	}

	Message::Message(CTX &ctx) :
		Value((v8::Local<v8::Value>) v8::Object::New(ctx)),
		ip_addr(v8::ArrayBuffer::New(ctx, sizeof(struct sockaddr_storage))),
		ip_so_type(v8::String::NewFromUtf8(ctx, "udp")),
		ip_set(v8::Function::New(ctx, cb_ip_set).ToLocalChecked()),
		ip_get(v8::Function::New(ctx, cb_ip_get).ToLocalChecked())
	{
		v8::Local<v8::Value> value = *this;
		v8::Local<v8::Object> parent = value->ToObject((v8::Isolate *) ctx);
		parent->Set(ctx, String(ctx, "ip_addr"), ip_addr).Check();
		parent->Set(ctx, String(ctx, "ip_so_type"), ip_so_type).Check();
		parent->Set(ctx, String(ctx, "ip_set"), ip_set).Check();
		parent->Set(ctx, String(ctx, "ip_get"), ip_get).Check();
	}
}; // namespace RRR::JS

/*
{
  ip_addr: new ArrayBuffer(),  // Operating system raw IP address information (struct sockaddr)
  ip_so_type: "",              // Protocol, set to udp or tcp. May also be empty.

  ip_set: function(ip, port){}              // Helper function to set adddress of ip_addr field
  ip_get: function(){ return [ip, port]; }  // Helper function to retrieve adddress of ip_addr field
}
*/
