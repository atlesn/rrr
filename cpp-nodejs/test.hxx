#pragma once

#include "v8-isolate.h"
#include <memory>
#include <v8.h>

namespace RRR::JS {
	class ENV {
		friend class SCOPE;

		private:
		std::unique_ptr<v8::Platform> platform;
		v8::Isolate::CreateParams isolate_create_params;
		v8::Isolate *isolate;

		public:
		ENV(const char *program_name);
		~ENV();
		operator v8::Isolate *();
	};

	class SCOPE {
		private:
		v8::Isolate *isolate;
		v8::Isolate::Scope isolate_scope;
		v8::HandleScope handle_scope;

		public:
		SCOPE(ENV &env);
	};

	class CTX {
		private:
		v8::Local<v8::Context> ctx;
		v8::Context::Scope ctx_scope;

		public:
		CTX(ENV &env);
		operator v8::Local<v8::Context>();
	};

	class String {
		private:
		v8::Local<v8::String> str;

		public:
		String(ENV &env, const char *str);
		operator v8::Local<v8::String>();
	};

	class Value : public v8::Local<v8::Value> {
		public:
		Value(v8::Local<v8::Value> &&value);
	};

	class UTF8 {
		private:
		v8::String::Utf8Value utf8;

		public:
		UTF8(ENV &env, Value &&value);
		const char * operator *();
	};

	class Script {
		private:
		v8::Local<v8::Script> script;

		public:
		Script(CTX &ctx, String &&str);
		Value run(CTX &ctx);
	};
}
