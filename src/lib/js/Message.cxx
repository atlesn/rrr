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
#include <arpa/inet.h>
#include "../ip/ip_util.h"
#include "../ip/ip_defines.h"
#include "../mqtt/mqtt_topic.h"
#include "../util/rrr_time.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../array.h"
};

#include <cassert>
#include <type_traits>
#include <stdexcept>

namespace RRR::JS {
	int64_t Message::get_total_memory() {
		int64_t acc = sizeof(*this);

		acc += ip_so_type.length();
		acc += topic.length();
		acc += data.size();
		acc += array.allocated_size();

		return acc;
	}

	void Message::clear_array() {
		array.clear();
	}

	void Message::clear_tag(std::string tag) {
		array.clear_by_tag(tag);
	}

	rrr_msg_msg_class Message::get_class() {
		return array.count() > 0
			? MSG_CLASS_ARRAY
			: MSG_CLASS_DATA
		;
	}

	void Message::set_from_msg_msg(const struct rrr_msg_msg *msg) {
		array.clear();
		data.clear();
		topic = "";
		timestamp = rrr_time_get_64();
		type = MSG_TYPE_MSG;

		if (msg == nullptr)
			return;

		if (MSG_IS_ARRAY(msg)) {
			uint16_t array_version_dummy;
			array.add_from_message(&array_version_dummy, msg);
		}
		else if (MSG_DATA_LENGTH(msg) > 0) {
			data.clear();
			data.reserve((size_t) MSG_DATA_LENGTH(msg));
			memcpy(data.data(), MSG_DATA_PTR(msg), (size_t) MSG_DATA_LENGTH(msg));
		}

		topic = MSG_TOPIC_LENGTH(msg) > 0
			? std::string(MSG_TOPIC_PTR(msg), MSG_TOPIC_LENGTH(msg))
			: std::string()
		;
		timestamp = msg->timestamp;
		type = (rrr_msg_msg_type) MSG_TYPE(msg);
	}

	void Message::set_from_msg_addr(const struct rrr_msg_addr *msg_addr) {
		ip_so_type = "";
		ip_addr_len = 0;

		if (msg_addr == nullptr || RRR_MSG_ADDR_GET_ADDR_LEN(msg_addr) == 0)
			return;

		memcpy(&ip_addr, &msg_addr->addr, RRR_MSG_ADDR_GET_ADDR_LEN(msg_addr));
		ip_addr_len = (socklen_t) RRR_MSG_ADDR_GET_ADDR_LEN(msg_addr);
		switch (msg_addr->protocol) {
			case RRR_IP_UDP:
				ip_so_type = "UDP";
				break;
			case RRR_IP_TCP:
				ip_so_type = "TCP";
				break;
			default:
				break;
		}
	}

	void Message::send() {
		struct rrr_msg_addr msg_addr;
		struct rrr_msg_msg *msg_ptr = nullptr;
		std::unique_ptr<struct rrr_msg_msg> msg(nullptr);

		// Lengths must be verified in the setters
		assert(data.size() <= RRR_MSG_DATA_MAX);
		assert(topic.length() <= RRR_MSG_TOPIC_MAX);

		if (get_class() == MSG_CLASS_ARRAY) {
			array.to_message(&msg_ptr, timestamp, topic.c_str(), (rrr_u16) topic.length());
		}
		else if (data.size() > 0) {
			if (rrr_msg_msg_new_empty(&msg_ptr, MSG_TYPE_MSG, MSG_CLASS_DATA, timestamp, (rrr_u16) topic.length(), (rrr_u32) data.size()) != 0) {
				throw E(std::string("Could not allocate new message in ") + __func__);
			}
			memcpy(MSG_TOPIC_PTR(msg), topic.c_str(), topic.length());
			memcpy(MSG_DATA_PTR(msg), data.data(), data.size());
		}
		msg.reset(msg_ptr);

		MSG_SET_TYPE(msg, type);

		if (ip_addr_len > 0) {
			rrr_msg_addr_init(&msg_addr);
			msg_addr.protocol = ip_so_type.compare("UDP")
				? RRR_IP_UDP
				: ip_so_type.compare("TCP")
					? RRR_IP_TCP
					: RRR_IP_AUTO
			;
			assert(ip_addr_len <= sizeof(msg_addr.addr));
			RRR_MSG_ADDR_SET_ADDR_LEN(&msg_addr, ip_addr_len);
			memcpy(&msg_addr.addr, &ip_addr, ip_addr_len);
		}
	}

	void Message::push_tag_vain(std::string key) {
		array.push_value_vain_with_tag(key);
	}

	void Message::push_tag_str(std::string key, std::string value) {
		array.push_value_str_with_tag(key, value);
	}

	void Message::push_tag_blob(std::string key, const char *value, rrr_length size) {
		array.push_value_blob_with_tag_with_size(key, value, size);
	}

	void Message::push_tag_blob(v8::Isolate *isolate, std::string key, v8::ArrayBuffer *blob) {
		if (blob->ByteLength() == 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Cannot push blob of data length 0 to array")));
			return;
		}
		auto contents = blob->GetContents();
		rrr_length length;
		if (rrr_length_from_size_t_err(&length, contents.ByteLength()) != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(
				isolate, std::string("Blob data length overflow, cannot push to array")
			)));
			return;
		}
		push_tag_blob(key, (const char *) contents.Data(), length);
	}

	void Message::push_tag_h(v8::Isolate *isolate, std::string key, int64_t i64) {
		array.push_value_64_with_tag(key, i64);
	}

	void Message::push_tag_h(v8::Isolate *isolate, std::string key, uint64_t u64) {
		array.push_value_64_with_tag(key, u64);
	}

	void Message::push_tag_h(v8::Isolate *isolate, std::string key, v8::BigInt *bigint) {
		bool lossless = false;
		uint64_t u64 = bigint->Uint64Value(&lossless);
		if (lossless) {
			push_tag_h(isolate, String(isolate, key), u64);
			return;
		}
		int64_t i64 = bigint->Int64Value(&lossless);
		if (lossless) {
			push_tag_h(isolate, String(isolate, key), i64);
			return;
		}
		isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Could not convert BigInt without precision loss")));
		return;
	}

	void Message::push_tag_h(v8::Isolate *isolate, std::string key, std::string string) {
		try {
			static_assert(sizeof(std::stoll(string)) == sizeof(int64_t));
			push_tag_h(isolate, String(isolate, key), (int64_t) std::stoll(string));
		}
		catch (std::out_of_range e) {
			try {
				static_assert(sizeof(std::stoull(string)) == sizeof(uint64_t));
				push_tag_h(isolate, String(isolate, key), (uint64_t) std::stoull(string));
			}
			catch (std::out_of_range e) {
				isolate->ThrowException(v8::Exception::TypeError(String(isolate, std::string("Could not convert number: ") + e.what())));
			}
		}
	}

	void Message::push_tag_fixp(v8::Isolate *isolate, std::string key, rrr_fixp fixp) {
		array.push_value_fixp_with_tag(key, fixp);
	}

	void Message::push_tag_fixp(v8::Isolate *isolate, std::string key, v8::BigInt *bigint) {
		bool lossless = false;
		int64_t i64 = bigint->Int64Value(&lossless);
		if (lossless) {
			push_tag_fixp(isolate, String(isolate, key), i64);
			return;
		}
		isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Could not convert BigInt without precision loss")));
		return;
	}

	void Message::push_tag_fixp(v8::Isolate *isolate, std::string key, std::string string) {
		array.push_value_fixp_with_tag(key, string);
	}

	Message::Message(v8::Isolate *isolate, MessageDrop &message_drop) :
		ip_so_type(""),
		topic(),
		timestamp(rrr_time_get_64()),
		type(MSG_TYPE_MSG),
		data(),
		array(),
		message_drop(message_drop)
	{
		memset(&ip_addr, 0, sizeof(ip_addr));
		ip_addr_len = 0;
	}

	void Message::cb_throw(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Cannot change the value of this field")));
	}

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
		if (string_.length() > 0 && strcmp(*string_, "UDP") != 0 && strcmp(*string_, "TCP") != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value was not 'UDP', 'TCP' nor empty")));
			return;
		}

		message->ip_so_type = *string_;
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

		if ((info.Length() >= 1 ? info[0] : String(isolate, "0.0.0.0"))->ToString(ctx).ToLocal(&ip) != true) {
			auto ip_str = String(isolate, ip);
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "IP not a valid string")));
		}
		if ((info.Length() >= 2 ? info[1] : U32(isolate, 0))->ToUint32(ctx).ToLocal(&port) != true) {
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
			tmp_in6.sin6_port = htons((uint16_t) port->Uint32Value(ctx).ToChecked());
		}
		else if (ip_str.contains(".")) {
			af_protocol = AF_INET;
			tmp_addr_len = sizeof(struct sockaddr_in);
			if (inet_pton(af_protocol, *ip_str, (void *) &tmp_in.sin_addr) != 1) {
				isolate->ThrowException(v8::Exception::Error(String(isolate, "IPv4 address conversion failed")));
				return;
			}
			tmp_in.sin_family = AF_INET;
			tmp_in.sin_port = htons((uint16_t) port->Uint32Value(ctx).ToChecked());
		}
		else {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "IP address not valid (no : or . found)")));
			return;
		}

		static_assert(sizeof(message->ip_addr) == sizeof(tmp_addr));
		memcpy(&message->ip_addr, &tmp_addr, sizeof(tmp_addr));
		message->ip_addr_len = tmp_addr_len;
	}

	void Message::cb_clear_array(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto message = self(info);
		message->clear_array();
	}

#define TRY_CATCH_ARRAY(c)                                                 \
  try { c; }                                                               \
  catch (RRR::Array::E e) {                                                \
    isolate->ThrowException(v8::Exception::TypeError(String(isolate, e))); \
    return;                                                                \
  }

	void Message::cb_push_tag_blob(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto tag = v8::Local<v8::String>();

		if ((info.Length() >= 1 ? info[0] : String(isolate, ""))->ToString(ctx).ToLocal(&tag) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Invalid tag argument")));
			return;
		}

		if (info.Length() < 2 || !info[1]->IsArrayBuffer()) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for blob was not given or was not an ArrayBuffer")));
			return;
		}

		TRY_CATCH_ARRAY(message->push_tag_blob(isolate, String(isolate, tag), v8::ArrayBuffer::Cast(*info[1])));
	}

	void Message::cb_push_tag_str(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto tag = v8::Local<v8::String>();
		auto value = v8::Local<v8::String>();

		if ((info.Length() >= 1 ? info[0] : String(isolate, ""))->ToString(ctx).ToLocal(&tag) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Invalid tag argument")));
			return;
		}

		if ((info.Length() >= 2 ? info[1] : String(isolate, ""))->ToString(ctx).ToLocal(&value) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Invalid value argument")));
			return;
		}

		TRY_CATCH_ARRAY(message->push_tag_str(String(isolate, tag), String(isolate, value)));
	}

	template <typename BIGINT, typename STRING> void Message::cb_push_tag_number(const v8::FunctionCallbackInfo<v8::Value> &info, BIGINT b, STRING s) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto tag = v8::Local<v8::String>();
		auto value = v8::Local<v8::Value>();
		auto string = v8::Local<v8::String>();

		if ((info.Length() >= 1 ? info[0] : String(isolate, ""))->ToString(ctx).ToLocal(&tag) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Invalid tag argument")));
			return;
		}

		if (info.Length() >= 2) {
			value = info[1];
		}
		else {
			value = v8::Uint32::New(isolate, 0);
		}

		if (value->IsBigInt()) {
			TRY_CATCH_ARRAY(b(message, isolate, String(isolate, tag), v8::BigInt::Cast(*value)));
			return;
		}

		if (value->ToString(ctx).ToLocal(&string)) {
			try {
				TRY_CATCH_ARRAY(s(message, isolate, String(isolate, tag), String(isolate, string)));
			}
			catch (std::invalid_argument e) {
				isolate->ThrowException(v8::Exception::TypeError(String(isolate, std::string("Could not convert number: ") + e.what())));
			}
			return;
		}

		isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Could not convert argument to a number")));
		return;
	}

	void Message::cb_push_tag_h(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto l = [](auto message, auto a, auto b, auto c){
			message->push_tag_h(a, b, c);
		};
		Message::cb_push_tag_number(info, l, l);
	}

	void Message::cb_push_tag_fixp(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto l = [](auto message, auto a, auto b, auto c){
			message->push_tag_fixp(a, b, c);
		};
		Message::cb_push_tag_number(info, l, l);
	}

	void Message::cb_push_tag(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto key = info.Length() >= 1 ? info[0] : v8::Local<v8::Value>();
		auto value = info.Length() >= 2 ? info[1] : v8::Local<v8::Value>();
		auto key_string = v8::Local<v8::String>();

		// Process key argument
		if (key.IsEmpty() || key->IsNullOrUndefined()) {
			key_string.Clear();
		}
		else if (!key->ToString(ctx).ToLocal(&key_string)) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "key was not a string")));
			return;
		}
		else if (key_string->Length() == 0) {
			// OK, no key
			key_string.Clear();
		}

		// Process value argument
		TRY_CATCH_ARRAY (
			auto key = String(isolate, key_string);
			auto value_string = v8::Local<v8::String>();
			if (value.IsEmpty() || value->IsNullOrUndefined()) {
				message->push_tag_vain(*key);
				return;
			}
			else if (value->IsArrayBuffer()) {
				message->push_tag_blob(isolate, key, v8::ArrayBuffer::Cast(*value));
				return;
			}
			else if (value->IsBigInt()) {
				TRY_CATCH_ARRAY(message->push_tag_h(isolate, key, v8::BigInt::Cast(*value)));
				return;
			}
			else if (value->ToString(ctx).ToLocal(&value_string)) {
				try {
					TRY_CATCH_ARRAY(message->push_tag_h(isolate, key, String(isolate, value_string)));
					return;
				}
				catch (std::invalid_argument e) {
					if (value->IsNumber()) {
						isolate->ThrowException(v8::Exception::TypeError(String(isolate, std::string("Could not convert number: ") + e.what())));
						return;
					}
				}
				message->push_tag_str(key, String(isolate, value_string));
				return;
			}

			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Unsupported value type, cannot push to array")));
			return;
		);
	}

	void Message::cb_clear_tag(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto tag = v8::Local<v8::String>();

		if ((info.Length() >= 1 ? info[0] : String(isolate, ""))->ToString(ctx).ToLocal(&tag) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Invalid tag argument")));
			return;
		}
	
		message->clear_tag(String(isolate, tag));
	}

	void Message::cb_get_tag_all(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto tag = v8::Local<v8::String>();

		if ((info.Length() >= 1 ? info[0] : String(isolate, ""))->ToString(ctx).ToLocal(&tag) != true) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Invalid tag argument")));
			return;
		}

		std::vector<v8::Local<v8::Value>> result;

		auto tag_string = (std::string) String(isolate, tag);
		message->array.iterate (
			[&result, &isolate](rrr_type_be data, bool sign) {
				static_assert(sizeof(data) == sizeof(int64_t));
				if (sign) {
					const int64_t i64 = *((int64_t *)((void *) &data));
					result.emplace_back(i64 > INT32_MAX || i64 < INT32_MIN
						? (v8::Local<v8::Value>) v8::BigInt::New(isolate, i64)
						: (v8::Local<v8::Value>) v8::Integer::New(isolate, (int32_t) i64)
					);
				}
				else {
					const uint64_t u64 = *((uint64_t *)((void *) &data));
					result.emplace_back(u64 > UINT32_MAX
						? (v8::Local<v8::Value>) v8::BigInt::NewFromUnsigned(isolate, u64)
						: (v8::Local<v8::Value>) v8::Integer::NewFromUnsigned(isolate, (uint32_t) u64)
					);
				}
			},
			[&result, &isolate](const uint8_t *data, rrr_length size) {
				result.emplace_back(v8::ArrayBuffer::New(isolate, (void *) data, size));
			},
			[&result, &isolate](const struct rrr_msg *data, rrr_length size) {
				result.emplace_back(v8::ArrayBuffer::New(isolate, (void *) data, size));
			},
			[&result, &isolate](rrr_fixp data) {
				static_assert(sizeof(data) == sizeof(int64_t));
				result.emplace_back(v8::BigInt::New(isolate, data));
			},
			[&result, &isolate, &tag_string](const char *data, rrr_length size) {
				int size_int;
				if (rrr_int_from_length_err(&size_int, size) != 0) {
					RRR_MSG_0("Warning: String in array message too long for JavaScript(%" PRIrrrl ">%i) in value with key '%s'. Dropping value.\n",
						size, INT_MAX, tag_string.c_str());
					return;
				}
				result.emplace_back(String(isolate, data, size_int));
			},
			[&result, &isolate](void) {
				result.emplace_back(v8::Null(isolate));
			},
			[tag_string](std::string tag){
				return tag_string == tag;
			}
		);

		if (result.size() > INT_MAX) {
			isolate->ThrowException(v8::Exception::TypeError(String(
				isolate, std::string("Message to JavaScript had too many values (") + std::to_string(result.size()) + ">" + std::to_string(INT_MAX) + "). Cannot access elements.\n"
			)));
			return;
		}

		info.GetReturnValue().Set(result.size() > 0
			? v8::Array::New(isolate, result.data(), result.size())
			: v8::Array::New(isolate, 0)
		);
	}

	void Message::cb_send(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto message = self(info);
		message->send();
	}

	void Message::cb_topic_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto message = self(info);
		info.GetReturnValue().Set((v8::Local<v8::Value>) String(isolate, message->topic));
	}

	void Message::cb_topic_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto topic = v8::Local<v8::Value>();
		if (!value->ToString(ctx).ToLocal(&topic)) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value was not a string")));
			return;
		}
		auto topic_ = String(isolate, topic->ToString(ctx).ToLocalChecked());
		if (topic_.length() == 0) {
			// OK, no topic
		}
		else if (rrr_mqtt_topic_validate_name(*topic_) != 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value was not a valid MQTT topic")));
			return;
		}
		if (topic_.length() > RRR_MSG_TOPIC_MAX) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for topic exceeds maximum length")));
			return;
		}
		message->topic = topic_;
	}

	void Message::cb_timestamp_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto message = self(info);
		info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, message->timestamp));
	}

	void Message::cb_timestamp_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto timestamp = v8::Local<v8::BigInt>();
		if (!value->ToBigInt(ctx).ToLocal(&timestamp)) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value was not a valid timestamp")));
			return;
		}

		// Only 63 bit timestamp is supported here, which is OK. RRR
		// otherwise support positive timestamps but then with 64 bits.
		bool lossless = false;
		int64_t timestamp_ = timestamp->Int64Value(&lossless);
		if (timestamp_ < 0) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for timestamp was negative")));
			return;
		}
		if (!lossless) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for timestamp was truncated")));
			return;
		}
		message->timestamp = (uint64_t) timestamp_;
	}

	void Message::cb_data_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		info.GetReturnValue().Set(v8::ArrayBuffer::New(isolate, (void *) message->data.data(), message->data.size()));
	}

	void Message::cb_data_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);

		if (value->IsNullOrUndefined()) {
			message->data.clear();
			return;
		}
		if (value->IsArrayBuffer()) {
			auto contents = v8::ArrayBuffer::Cast(*value)->GetContents();
			if (contents.ByteLength() > RRR_MSG_DATA_MAX) {
				isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for data was too long")));
				return;
			}
			message->data.clear();
			message->data.reserve(contents.ByteLength());
			memcpy(message->data.data(), contents.Data(), contents.ByteLength());
			return;
		}
		if (value->IsString()) {
			String data(isolate, value->ToString(ctx).ToLocalChecked());
			if ((unsigned int) data.length() > RRR_MSG_DATA_MAX) {
				isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for data was too long")));
				return;
			}
			message->data.clear();
			message->data.reserve((size_t) data.length());
			memcpy(message->data.data(), *data, (size_t) data.length());
			return;
		}

		isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for data was not null, undefined, ArrayBuffer or a string")));
		return;
	}

	void Message::cb_type_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		info.GetReturnValue().Set(v8::Uint32::New(isolate, message->type));
	}

	void Message::cb_type_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		auto type = v8::Int32::New(isolate, 0);
		if (!value->ToUint32(ctx).ToLocal(&type)) {
			isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for type was not a number")));
			return;
		}
		uint32_t type_ = type->Uint32Value(ctx).ToChecked();
		switch (type_) {
			case MSG_TYPE_MSG:
			case MSG_TYPE_TAG:
			case MSG_TYPE_GET:
			case MSG_TYPE_PUT:
			case MSG_TYPE_DEL:
				break;
			default:
				isolate->ThrowException(v8::Exception::TypeError(String(isolate, "Value for type was not a valid type")));
				return;
		};
		message->type = (rrr_msg_msg_type) type_;
	}

	void Message::cb_class_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto message = self(info);
		info.GetReturnValue().Set(v8::Uint32::New(isolate, message->get_class()));
	}

	void Message::cb_constant_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info) {
		info.GetReturnValue().Set(info.Data());
	}

	void MessageFactory::cb_construct_base(const v8::FunctionCallbackInfo<v8::Value> &info) {
		info.GetReturnValue().Set(info.This());
	}

	void MessageFactory::cb_construct_internal(const v8::FunctionCallbackInfo<v8::Value> &info) {
		auto isolate = info.GetIsolate();
		auto ctx = info.GetIsolate()->GetCurrentContext();
		auto self = (MessageFactory *) v8::External::Cast(*info.Data())->Value();
		auto message = self->new_internal(isolate, info.This());
		info.GetReturnValue().Set(info.This());
	}

	void MessageFactory::cb_construct_external(const v8::FunctionCallbackInfo<v8::Value> &info) {
		info.GetReturnValue().Set(info.This());
	}

	MessageFactory::MessageFactory(CTX &ctx, PersistentStorage<Persistable> &persistent_storage, MessageDrop &message_drop) :
		persistent_storage(persistent_storage),
		function_tmpl_base(v8::FunctionTemplate::New(ctx, MessageFactory::cb_construct_base, v8::External::New(ctx, this))),
		function_tmpl_internal(v8::FunctionTemplate::New(ctx, MessageFactory::cb_construct_internal, v8::External::New(ctx, this))),
		function_tmpl_external(v8::FunctionTemplate::New(ctx, MessageFactory::cb_construct_external, v8::External::New(ctx, this))),
		message_drop(message_drop),
		tmpl_ip_get(v8::FunctionTemplate::New(ctx, Message::cb_ip_get)),
		tmpl_ip_set(v8::FunctionTemplate::New(ctx, Message::cb_ip_set)),
		tmpl_clear_array(v8::FunctionTemplate::New(ctx, Message::cb_clear_array)),
		tmpl_push_tag_blob(v8::FunctionTemplate::New(ctx, Message::cb_push_tag_blob)),
		tmpl_push_tag_str(v8::FunctionTemplate::New(ctx, Message::cb_push_tag_str)),
		tmpl_push_tag_h(v8::FunctionTemplate::New(ctx, Message::cb_push_tag_h)),
		tmpl_push_tag_fixp(v8::FunctionTemplate::New(ctx, Message::cb_push_tag_fixp)),
		tmpl_push_tag(v8::FunctionTemplate::New(ctx, Message::cb_push_tag)),
		tmpl_clear_tag(v8::FunctionTemplate::New(ctx, Message::cb_clear_tag)),
		tmpl_get_tag_all(v8::FunctionTemplate::New(ctx, Message::cb_get_tag_all)),
		tmpl_send(v8::FunctionTemplate::New(ctx, Message::cb_send))
	{
		auto instance = function_tmpl_base->InstanceTemplate();
		instance->Set(ctx, "ip_get", tmpl_ip_get);
		instance->Set(ctx, "ip_set", tmpl_ip_set);
		instance->Set(ctx, "clear_array", tmpl_clear_array);
		instance->Set(ctx, "clear_tag", tmpl_clear_tag);
		instance->Set(ctx, "push_tag_blob", tmpl_push_tag_blob);
		instance->Set(ctx, "push_tag_str", tmpl_push_tag_str);
		instance->Set(ctx, "push_tag_h", tmpl_push_tag_h);
		instance->Set(ctx, "push_tag_fixp", tmpl_push_tag_fixp);
		instance->Set(ctx, "push_tag", tmpl_push_tag);
		instance->Set(ctx, "get_tag_all", tmpl_get_tag_all);
		instance->SetAccessor(String(ctx, "ip_addr"), Message::cb_ip_addr_get, Message::cb_throw);
		instance->SetAccessor(String(ctx, "ip_so_type"), Message::cb_ip_so_type_get, Message::cb_ip_so_type_set);
		instance->SetAccessor(String(ctx, "topic"), Message::cb_topic_get, Message::cb_topic_set);
		instance->SetAccessor(String(ctx, "timestamp"), Message::cb_timestamp_get, Message::cb_timestamp_set);
		instance->SetAccessor(String(ctx, "data"), Message::cb_data_get, Message::cb_data_set);
		instance->SetAccessor(String(ctx, "type"), Message::cb_type_get, Message::cb_type_set);
		instance->SetAccessor(String(ctx, "class"), Message::cb_class_get, Message::cb_throw);
		instance->SetAccessor(String(ctx, "MSG_TYPE_MSG"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_TYPE_MSG));
		instance->SetAccessor(String(ctx, "MSG_TYPE_TAG"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_TYPE_TAG));
		instance->SetAccessor(String(ctx, "MSG_TYPE_GET"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_TYPE_GET));
		instance->SetAccessor(String(ctx, "MSG_TYPE_PUT"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_TYPE_PUT));
		instance->SetAccessor(String(ctx, "MSG_TYPE_DEL"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_TYPE_DEL));
		instance->SetAccessor(String(ctx, "MSG_CLASS_DATA"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_CLASS_DATA));
		instance->SetAccessor(String(ctx, "MSG_CLASS_ARRAY"), Message::cb_constant_get, Message::cb_throw, v8::Uint32::New(ctx, MSG_CLASS_ARRAY));
		function_tmpl_base->InstanceTemplate()->SetInternalFieldCount(1);
		function_tmpl_internal->InstanceTemplate()->SetInternalFieldCount(1);
		function_tmpl_external->InstanceTemplate()->SetInternalFieldCount(1);
	}

	Duple<v8::Local<v8::Object>, Message *> MessageFactory::new_internal (
			v8::Isolate *isolate,
			v8::Local<v8::Object> obj
	) {
		auto ctx = isolate->GetCurrentContext();
		auto message = std::unique_ptr<Message>(new Message(isolate, message_drop));
		auto duple = Duple(obj, message.get());
		auto base = function_tmpl_base->InstanceTemplate()->NewInstance(ctx).ToLocalChecked();

		// The accessor functions seem to receive the base object as This();
		base->SetInternalField(Message::INTERNAL_INDEX_THIS, v8::External::New(isolate, message.get()));

		// The otheer functions seem to receive the derived object as This();
		obj->SetInternalField(Message::INTERNAL_INDEX_THIS, v8::External::New(isolate, message.get()));

		obj->SetPrototype(ctx, base).Check();

		persistent_storage.push(isolate, obj, message.release());

		return duple;
	}

	Duple<v8::Local<v8::Object>, Message *> MessageFactory::new_external (
			v8::Isolate *isolate,
			const struct rrr_msg_msg *msg,
			const struct rrr_msg_addr *msg_addr
	) {
		auto obj = function_tmpl_external->GetFunction(isolate->GetCurrentContext()).ToLocalChecked()->NewInstance(isolate->GetCurrentContext()).ToLocalChecked();
		auto duple = new_internal(isolate, obj);

		duple.second()->set_from_msg_msg(msg);
		duple.second()->set_from_msg_addr(msg_addr);

		return duple;
	}

	v8::Local<v8::Function> MessageFactory::get_internal_function(CTX &ctx) {
		return function_tmpl_internal->GetFunction(ctx).ToLocalChecked();
	}
}; // namespace RRR::JS
