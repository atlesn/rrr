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
#include "../Array.hxx"

#include <v8.h>

extern "C" {
#include "../messages/msg_msg_struct.h"
#include <sys/socket.h>
};

namespace RRR::JS {
	class MessageDrop {
		private:
		void (* const callback) (const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr, void *callback_arg);
		void * const callback_arg;

		public:
		MessageDrop(
			void (* const callback) (const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr, void *callback_arg),
			void * const callback_arg
		) :
			callback(callback),
			callback_arg(callback_arg)
		{
		}

		void drop(const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr);
	};

	class Message : public Native<Message> {
		friend class MessageFactory;

		private:
		struct sockaddr_storage ip_addr;
		socklen_t ip_addr_len;
		std::string ip_so_type;
		std::string topic;
		uint64_t timestamp;
		rrr_msg_msg_type type;
		std::vector<char> data;
		RRR::Array array;

		MessageDrop &message_drop;

		int64_t get_total_memory() final;
		void clear_array();
		void clear_tag(std::string tag);
		rrr_msg_msg_class get_class();
		void set_data(const char *new_data, size_t new_data_size);
		void set_from_msg_msg(const struct rrr_msg_msg *msg);
		void set_from_msg_addr(const struct rrr_msg_addr *msg_addr);
		void send(v8::Isolate *isolate);

		void push_tag_vain(std::string key);
		void push_tag_str(std::string key, std::string value);
		void push_tag_str_json(std::string key, std::string value);
		void push_tag_blob(std::string key, const char *value, rrr_length size);
		void push_tag_blob(v8::Isolate *isolate, std::string key, v8::Local<v8::ArrayBuffer> blob);
		void push_tag_h(v8::Isolate *isolate, std::string key, int64_t i64);
		void push_tag_h(v8::Isolate *isolate, std::string key, uint64_t u64);
		void push_tag_h(v8::Isolate *isolate, std::string key, v8::BigInt *bigint);
		void push_tag_h(v8::Isolate *isolate, std::string key, std::string string);
		void push_tag_fixp(v8::Isolate *isolate, std::string key, int64_t i64);
		void push_tag_fixp(v8::Isolate *isolate, std::string key, v8::BigInt *bigint);
		void push_tag_fixp(v8::Isolate *isolate, std::string key, std::string string);
		void push_tag_object(v8::Isolate *isolate, std::string key, v8::Local<v8::Value> object);
		void push_tag(v8::Isolate *isolate, std::string key_string, v8::Local<v8::Value> value);

		protected:

		Message(v8::Isolate *isolate, MessageDrop &MessageDrop);

		static void cb_throw(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_ip_addr_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_ip_so_type_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_ip_so_type_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_topic_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_topic_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_timestamp_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_timestamp_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_data_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_data_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_type_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_type_set(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<void> &info);
		static void cb_class_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_constant_get(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value> &info);
		static void cb_ip_get(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_ip_set(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_clear_array(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_push_tag_blob(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_push_tag_str(const v8::FunctionCallbackInfo<v8::Value> &info);
		template <typename BIGINT, typename STRING> static void cb_push_tag_number(const v8::FunctionCallbackInfo<v8::Value> &info, BIGINT b, STRING s);
		static void cb_push_tag_h(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_push_tag_fixp(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_push_tag_object(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_push_tag(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_set_tag(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_clear_tag(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_get_tag_all(const v8::FunctionCallbackInfo<v8::Value> &info);
		static void cb_send(const v8::FunctionCallbackInfo<v8::Value> &info);

		public:
		Message(const Message &) = delete;

		operator v8::Local<v8::Object>(); 
	};

	class MessageFactory : public Factory<Message> {
		private:
		v8::Local<v8::FunctionTemplate> tmpl_ip_get;
		v8::Local<v8::FunctionTemplate> tmpl_ip_set;
		v8::Local<v8::FunctionTemplate> tmpl_clear_array;
		v8::Local<v8::FunctionTemplate> tmpl_push_tag_blob;
		v8::Local<v8::FunctionTemplate> tmpl_push_tag_str;
		v8::Local<v8::FunctionTemplate> tmpl_push_tag_h;
		v8::Local<v8::FunctionTemplate> tmpl_push_tag_fixp;
		v8::Local<v8::FunctionTemplate> tmpl_push_tag_object;
		v8::Local<v8::FunctionTemplate> tmpl_push_tag;
		v8::Local<v8::FunctionTemplate> tmpl_set_tag;
		v8::Local<v8::FunctionTemplate> tmpl_clear_tag;
		v8::Local<v8::FunctionTemplate> tmpl_get_tag_all;
		v8::Local<v8::FunctionTemplate> tmpl_send;

		MessageDrop &message_drop;

		Message *new_native(v8::Isolate *isolate) final;

		public:
		MessageFactory(CTX &ctx, PersistentStorage &persistent_storage, MessageDrop &message_drop);
		Duple<v8::Local<v8::Object>, Message *> new_external (
				v8::Isolate *isolate,
				const struct rrr_msg_msg *msg_msg = nullptr,
				const struct rrr_msg_addr *msg_addr = nullptr
		);
	};
}; // namespace RRR::JS
