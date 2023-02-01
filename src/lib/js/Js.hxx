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

#include "../util/E.hxx"

#include <v8.h>
#include <forward_list>

extern "C" {
#include "../rrr_types.h"
};

namespace RRR::JS {
	class CTX;
	class Scope;
	class Isolate;

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
		~Isolate();
		v8::Isolate *operator-> () {
			return isolate;
		}
	};

	class Value : public v8::Local<v8::Value> {
		public:
		Value(v8::Local<v8::Value> value);
	//	Value(v8::Local<v8::String> &&value);
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
		private:
		v8::Local<v8::Function> function;

		public:
		Function();
		Function(v8::Local<v8::Function> function);
		bool empty() const {
			return function.IsEmpty();
		}
		void run(CTX &ctx, int argc, Value argv[]);
	};

	class CTX {
		private:
		v8::Local<v8::Context> ctx;
		v8::TryCatch trycatch;
		std::string script_name;

		std::string make_location_message(v8::Local<v8::Message> msg);

		public:
		template <class A> bool trycatch_ok(A err) {
			auto msg = trycatch.Message();
			auto str = std::string("");

			if (trycatch.HasTerminated()) {
				str += "Program terminated";
			}
			else if (trycatch.HasCaught()) {
				str += "Uncaught exception";
			}
			else {
				return true;
			}

			if (!msg.IsEmpty()) {
				str += std::string(":\n") + make_location_message(msg);
			}
			else {
				str += "\n";
			}

			err(str.c_str());

			return trycatch.CanContinue();
		}
		CTX(v8::Local<v8::Context> ctx, std::string script_name);
		CTX(ENV &env, std::string script_name);
		~CTX();
		CTX(const CTX &) = delete;
		operator v8::Local<v8::Context>();
		operator v8::Local<v8::Value>();
		operator v8::Isolate *();
		template <typename T> void set_global(std::string name, T object) {
			auto result = ctx->Global()->Set(ctx, String(*this, name), object);
			if (!result.FromMaybe(false)) {
				throw E("Failed to set global '" + name + "'\n");
			}
		}
		void run_function(Function &function, const char *name, int argc, Value argv[]);
	};

	class Scope {
		v8::HandleScope handle_scope;

		public:
		Scope(CTX &ctx) :
			handle_scope(ctx)
		{
		}
	};

	class Program {
		protected:
		std::string name;
		std::string program_source;
		bool compiled = false;

		protected:
		void set_compiled();
		template <typename L> void compile_str_wrap(CTX &ctx, L l);
		Function get_function(CTX &ctx, v8::Local<v8::Object> object, std::string name);

		public:
		Program(std::string name, std::string program_source);
		bool is_compiled();
		std::string get_name();
		virtual ~Program() = default;
		virtual void compile(CTX &ctx) = 0;
		virtual void run(CTX &ctx) = 0;
		virtual Function get_function(CTX &ctx, std::string name) = 0;
	};

	class Script : public Program {
		private:
		v8::Local<v8::Script> script;

		public:
		Script(std::string name, std::string script_source);
		void compile(CTX &ctx) final;
		void run(CTX &ctx) final;
		Function get_function(CTX &ctx, std::string name) final;
	};

	class Module : public Program {
		private:
		v8::Local<v8::Module> mod;
		std::forward_list<std::shared_ptr<v8::Local<v8::Module>>> submodules;
		static v8::MaybeLocal<v8::Module> resolve_callback(v8::Local<v8::Context> context, v8::Local<v8::String> specifier, v8::Local<v8::Module> referrer);
		operator v8::MaybeLocal<v8::Module>();

		public:
		Module(std::string name, std::string module_source);
		void compile(CTX &ctx) final;
		void run(CTX &ctx) final;
		Function get_function(CTX &ctx, std::string name) final;
	};

	template <class A, class B> class Duple {
		private:
		A a;
		B b;

		public:
		Duple(A a, B b) : a(a), b(b) {}
		A first() { return a; }
		B second() { return b; }
		A* operator->() { return &a; };
	};

} // namespace RRR::JS
