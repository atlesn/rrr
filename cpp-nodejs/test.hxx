#pragma once

#include "v8-callbacks.h"
#include "v8-function-callback.h"
#include "v8-isolate.h"
#include <memory>
#include <v8.h>

namespace RRR::JS {
	class CTX;
	class Scope;
	class TryCatch;

	class ENV {
		friend class Isolate;

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

	class Isolate {
		private:
		v8::Isolate *isolate;
		v8::Isolate::Scope isolate_scope;
		v8::HandleScope handle_scope;

		public:
		Isolate(ENV &env);
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
		UTF8(CTX &ctx, Value &value);
		UTF8(CTX &ctx, Value &&value);
		UTF8(CTX &ctx, v8::Local<v8::String> &str);
		UTF8(v8::Isolate *isolate, v8::Local<v8::String> &str);
		const char * operator *();
	};

	class String {
		private:
		v8::Local<v8::String> str;
		UTF8 utf8;

		public:
		String(CTX &ctx, const char *str);
		String(CTX &ctx, v8::Local<v8::String> &&str);
		String(v8::Isolate *isolate, v8::Local<v8::String> &&str);
		operator v8::Local<v8::String>();
		operator v8::Local<v8::Value>();
		const char * operator *();
		operator Value();
	};

	class E {
		private:
		String str;

		public:
		E(CTX &ctx, std::string &&str);
		const char * operator *();
	};

	class Function {
		friend class CTX;

		private:
		v8::Local<v8::Function> function;

		protected:
		Function(v8::Local<v8::Function> &&function);

		public:
		void run(CTX &ctx, int argc, Value argv[]);
	};

	class CTX {
		friend class Scope;

		private:
		v8::Local<v8::Context> ctx;

		public:
		CTX(ENV &env);
		operator v8::Local<v8::Context>();
		operator v8::Local<v8::Value>();
		operator v8::Isolate *();
		Function get_function(const char *name);
		void run_function(TryCatch &trycatch, Function &function, const char *name, int argc, Value argv[]);
		void run_function(TryCatch &trycatch, const char *name, int argc, Value argv[]);
	};

	class Scope {
		friend class CTX;

		private:
		CTX ctx;
		public:
		Scope(CTX &ctx);
		~Scope();
	};

	class TryCatch {
		private:
		v8::TryCatch trycatch;

		public:
		TryCatch(CTX &ctx) :
			trycatch(v8::TryCatch(ctx))
		{
		}

		template <class A> bool ok(CTX &ctx, A err) {
			if (trycatch.HasCaught()) {
				auto msg = String(ctx, trycatch.Message()->Get());
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
		Script(CTX &ctx, TryCatch &trycatch, String &&str);
		void run(CTX &ctx, TryCatch &trycatch);
	};
}
