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
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../ip/ip_util.h"
};

namespace RRR::JS {
	void Message::cb_ip_addr_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto message = self(info);
		auto buffer = v8::ArrayBuffer::New(info.GetIsolate(), message->ip_addr_len);
		info.GetReturnValue().Set(buffer);
	}

	void Message::cb_ip_so_type_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto result = String(isolate, message->ip_so_type.c_str());
		info.GetReturnValue().Set((v8::Local<v8::String>) result);
	}

	void Message::cb_ip_so_type_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);

		auto string = v8::Local<v8::String>();
		if (!value->ToString(ctx).ToLocal(&string)) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value was not a string")));
			return;
		}

		auto string_ = String(isolate, string);
		if (string_.length() > 0 && strcmp(*string_, "udp") != 0 && strcmp(*string_, "tcp") != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value was not 'udp', 'tcp' nor empty")));
			return;
		}

		message->ip_so_type = *string_;
	}

	void Message::cb_ip_addr_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Cannot change value of ip_addr field")));
	}

	void Message::cb_ip_get(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		char ip_str[128];
		uint16_t port;
		rrr_ip_to_str(ip_str, sizeof(ip_str), (const sockaddr *) &message->ip_addr, message->ip_addr_len);

		if (rrr_ip_check((const struct sockaddr *) &message->ip_addr, message->ip_addr_len) != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "No valid IP address in address field")));
			return;
		}
		if (rrr_ip_to_str_and_port(&port, ip_str, sizeof(ip_str), (const struct sockaddr *) &message->ip_addr, message->ip_addr_len) != 0) {
			isolate->ThrowException(v8::Exception::Error(String(isolate, "Conversion of IP address failed")));
			return;
		}

		auto array = v8::Array::New(info.GetIsolate(), 2);
		array->Set(ctx, 0, String(isolate, ip_str)).Check();
		array->Set(ctx, 1, U32(isolate, port)).Check();
		info.GetReturnValue().Set(array);
	}

	void Message::cb_ip_set(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);

		auto ip = v8::Local<v8::String>();
		auto port = v8::Local<v8::Uint32>();

		if ((info.kArgsLength >= 1 ? info[0] : String(isolate, "0.0.0.0"))->ToString(ctx).ToLocal(&ip) != true) {
			auto ip_str = String(isolate, ip);
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "IP not a valid string")));
		}
		if ((info.kArgsLength >= 2 ? info[1] : U32(isolate, 0))->ToUint32(ctx).ToLocal(&port) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Port not a valid number")));
			return;
		}
		if (port->Uint32Value(ctx).ToChecked() > 65535) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Port out of range")));
			return;
		}

		auto ip_str = String(isolate, ip);
		int af_protocol;
		union {
			struct sockaddr_storage tmp_addr;
			struct sockaddr_in tmp_in;
			struct sockaddr_in6 tmp_in6;
		};
		socklen_t tmp_addr_len;

		memset(&tmp_addr, 0, sizeof(tmp_addr));

		// IPv6 must be checked first as this address may also contain dots .
		if (ip_str.contains(":")) {
			af_protocol = AF_INET6;
			tmp_addr_len = sizeof(struct sockaddr_in6);
			if (inet_pton(af_protocol, *ip_str, (void *) &tmp_in6.sin6_addr) != 1) {
				isolate->ThrowException(v8::Exception::Error(String(isolate, "IPv6 address conversion failed")));
				return;
			}
			tmp_in6.sin6_family = AF_INET6;
			tmp_in6.sin6_port = htons(port->Uint32Value(ctx).ToChecked());
		}
		else if (ip_str.contains(".")) {
			af_protocol = AF_INET;
			tmp_addr_len = sizeof(struct sockaddr_in);
			if (inet_pton(af_protocol, *ip_str, (void *) &tmp_in.sin_addr) != 1) {
				isolate->ThrowException(v8::Exception::Error(String(isolate, "IPv4 address conversion failed")));
				return;
			}
			tmp_in.sin_family = AF_INET;
			tmp_in.sin_port = htons(port->Uint32Value(ctx).ToChecked());
		}
		else {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "IP address not valid (no : or . found)")));
			return;
		}

		assert(sizeof(message->ip_addr) == sizeof(tmp_addr));
		memcpy(&message->ip_addr, &tmp_addr, sizeof(tmp_addr));
		message->ip_addr_len = tmp_addr_len;
	}

	Message::Template::Template(CTX &ctx) :
		tmpl(v8::ObjectTemplate::New(ctx)),
		tmpl_ip_get(v8::FunctionTemplate::New(ctx, cb_ip_get)),
		tmpl_ip_set(v8::FunctionTemplate::New(ctx, cb_ip_set))
	{
		tmpl->SetInternalFieldCount(1);
		tmpl->SetAccessor(String(ctx, "ip_addr"), cb_ip_addr_get, cb_ip_addr_set, v8::Local<v8::Value>());
		tmpl->SetAccessor(String(ctx, "ip_so_type"), cb_ip_so_type_get, cb_ip_so_type_set, v8::Local<v8::Value>());
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
		message->Set(ctx, String(ctx, "ip_set"), tmpl_ip_set->GetFunction(ctx).ToLocalChecked()).Check();

		return message;
	}
}; // namespace RRR::JS
