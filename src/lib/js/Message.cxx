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
#include "../ip/ip_util.h"
};

namespace RRR::JS {
	void Message::cb_ip_addr_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto self = info.Holder();
		auto wrap = v8::Local<v8::External>::Cast(self->GetInternalField(0));
		auto message = (Message *) wrap->Value();
		auto buffer = v8::ArrayBuffer::New(info.GetIsolate(), message->ip_addr_len);
		info.GetReturnValue().Set(buffer);
	}

	void Message::cb_ip_addr_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<v8::Value> &info) {
		printf("Set ip %i\n", info.kArgsLength);
	}

	void Message::cb_ip_get(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto self = info.Holder();
		auto wrap = v8::Local<v8::External>::Cast(self->GetInternalField(0));
		auto message = (Message *) wrap->Value();
		char ip_str[128];
		rrr_ip_to_str(ip_str, sizeof(ip_str), (const sockaddr *) &message->ip_addr, message->ip_addr_len);

		info.GetReturnValue().Set((v8::Local<v8::Value>) String(isolate, ip_str));
	}

	Message::Template::Template(CTX &ctx) :
		tmpl(v8::ObjectTemplate::New(ctx)),
		tmpl_ip_get(v8::FunctionTemplate::New(ctx, cb_ip_get))
	{
		tmpl->SetInternalFieldCount(1);
		tmpl->SetAccessor(String(ctx, "ip_addr"), cb_ip_addr_get);
	}

	Message::Message(CTX &ctx, v8::Local<v8::Object> obj) :
		Object(obj),
		ip_so_type("udp")
	{
		memset(&ip_addr, 0, sizeof(ip_addr));
		ip_addr_len = 0;
		/*parent->Set(ctx, String(ctx, "ip_addr"), ip_addr).Check();
		parent->Set(ctx, String(ctx, "ip_so_type"), ip_so_type).Check();
		parent->Set(ctx, String(ctx, "ip_set"), ip_set).Check();
		parent->Set(ctx, String(ctx, "ip_get"), ip_get).Check();*/
	}

	Message::Template Message::make_template(CTX &ctx) {
		return Template(ctx);
	}

	Message Message::Template::new_instance(CTX &ctx) {
		Message message(ctx, tmpl->NewInstance(ctx).ToLocalChecked());

		message->SetInternalField(0, v8::External::New(ctx, &message));
		message->Set(ctx, String(ctx, "ip_get"), tmpl_ip_get->GetFunction(ctx).ToLocalChecked()).Check();

		return message;
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
