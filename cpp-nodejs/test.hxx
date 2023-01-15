#pragma once

#include "v8-function-callback.h"
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
		static void fatal_error(const char *where, const char *what);
	};

	class SCOPE {
		private:
		v8::Isolate *isolate;
		v8::Isolate::Scope isolate_scope;
		v8::HandleScope handle_scope;

		public:
		SCOPE(ENV &env);
	};

	class Value : public v8::Local<v8::Value> {
		public:
		Value(v8::Local<v8::Value> &&value);
		Value(v8::Local<v8::String> &&value);
	};

	class UTF8 {
		private:
		v8::String::Utf8Value utf8;

		public:
		UTF8(ENV &env, Value &value);
		UTF8(ENV &env, Value &&value);
		UTF8(ENV &env, v8::Local<v8::String> &str);
		UTF8(v8::Isolate *isolate, v8::Local<v8::String> &str);
		const char * operator *();
	};

	class String {
		private:
		v8::Local<v8::String> str;
		UTF8 utf8;

		public:
		String(ENV &env, const char *str);
		String(ENV &env, v8::Local<v8::String> &&str);
		String(v8::Isolate *isolate, v8::Local<v8::String> &&str);
		operator v8::Local<v8::String>();
		operator v8::Local<v8::Value>();
		const char * operator *();
	};

	class E {
		private:
		String str;

		public:
		E(ENV &env, const char *);
		const char * operator *();
	};

	class CTX {
		private:
		v8::Local<v8::Context> ctx;
		v8::Context::Scope ctx_scope;

		public:
		CTX(ENV &env);
		operator v8::Local<v8::Context>();
	};

	class TryCatch {
		private:
		v8::TryCatch trycatch;

		public:
		TryCatch(ENV &env) :
			trycatch(v8::TryCatch(env))
		{
		}

		template <class A> bool ok(ENV &env, A err) {
			if (trycatch.HasCaught()) {
				auto msg = String(env, trycatch.Message()->Get());
				err(*msg);
				return false;
			}
			else if (trycatch.HasTerminated()) {
				err("Program terminated");
				return false;
			}
			else if (trycatch.CanContinue()) {
				return true;
			}
			err("Unknown error");
			return false;
		}
	};

	class Script {
		private:
		v8::Local<v8::Script> script;

		public:
		Script(ENV &env, CTX &ctx, String &&str);
		Value run(ENV &env, CTX &ctx);
	};
}
