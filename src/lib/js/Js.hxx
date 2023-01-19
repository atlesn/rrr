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
#include "../rrr_types.h"
};

#include <v8.h>
#include "../util/E.hxx"

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
		Value(v8::Local<v8::Value> value);
	//	Value(v8::Local<v8::String> &&value);
	};

	class Object : public v8::Local<v8::Object> {
		public:
		Object(v8::Local<v8::Object> object);
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
		int length();
	};

	class String {
		private:
		v8::Local<v8::String> str;
		UTF8 utf8;

		public:
		String(v8::Isolate *isolate, const char *str);
		String(v8::Isolate *isolate, const char *data, int size);
		String(v8::Isolate *isolate, v8::Local<v8::String> str);
		String(v8::Isolate *isolate, std::string str);
		operator v8::Local<v8::String>();
		operator v8::Local<v8::Value>();
		operator std::string();
		const char * operator *();
		operator Value();
		bool contains(const char *needle);
		int length();
	};

	class U32 : public v8::Local<v8::Integer> {
		public:
		U32(v8::Isolate *isolate, uint32_t u);
	};

	class E : public RRR::util::E {
		public:
		E( std::string &&str);
	};

	class Function {
		friend class CTX;

		private:
		v8::Local<v8::Function> function;

		protected:
		Function(v8::Local<v8::Function> &&function);

		public:
		Function();
		bool empty() const {
			return function.IsEmpty();
		}
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
		void compile(CTX &ctx, TryCatch &trycatch);

		public:
		Script(CTX &ctx, TryCatch &trycatch, String &&str);
		Script(CTX &ctx, TryCatch &trycatch, std::string &&str);
		void run(CTX &ctx, TryCatch &trycatch);
	};
} // namespace RRR::JS
