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
		static void fatal_error(const char *where, const char *what);

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

	class Value : public v8::Local<v8::Value> {
		public:
		Value(v8::Local<v8::Value> &&value);
	};

	class UTF8 {
		private:
		v8::String::Utf8Value utf8;

		public:
		UTF8(ENV &env, Value &&value);
		UTF8(ENV &env, v8::Local<v8::String> &str);
		const char * operator *();
	};

	class String {
		private:
		v8::Local<v8::String> str;
		UTF8 utf8;

		public:
		String(ENV &env, const char *str);
		String(ENV &env, v8::Local<v8::String> &&str);
		operator v8::Local<v8::String>();
		const char * operator *();
	};

	class Script {
		private:
		v8::Local<v8::Script> script;

		public:
		Script(CTX &ctx, String &&str);
		Value run(CTX &ctx);
	};

	class TryCatch {
		private:
		v8::TryCatch trycatch;

		public:
		TryCatch(ENV &env) :
			trycatch(v8::TryCatch(env))
		{
		}

		template <class C> bool ok(ENV &env, C c) {
			if (trycatch.HasCaught()) {
				auto msg = String(env, trycatch.Message()->Get());
				c(*msg);
				return false;
			}
			else if (trycatch.HasTerminated()) {
				c("Program terminated");
				return false;
			}
			else if (trycatch.CanContinue()) {
				return true;
			}
			c("Unknown error");
			return false;
		}
	};
}
