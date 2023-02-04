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
#include "v8-value.h"

#include <v8.h>
#include <forward_list>
#include <map>

extern "C" {
#include "../rrr_types.h"
};

namespace RRR::JS {
	class CTX;
	class Scope;
	class Isolate;

	class ENV {
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
		public:
		template <class T> class DataHandle {
			private:
			uint32_t pos;
			Isolate *isolate;

			public:
			DataHandle(Isolate *isolate, T *ptr) :
				isolate(isolate),
				pos(isolate->set_data(ptr))
			{
			}
			T *operator *() {
				return (T *) isolate->get_data(pos);
			}
		};

		private:
		uint32_t data_pos = 0;
		v8::Isolate *isolate;
		v8::Isolate::Scope isolate_scope;
		v8::HandleScope handle_scope;
		std::map<int,void *> module_map;
		DataHandle<Isolate> isolate_handle;
		DataHandle<std::map<int,void *>> module_map_handle;

		protected:
		void *get_data(uint32_t pos);
		uint32_t set_data(void *ptr);

		public:
		Isolate(ENV &env);
		~Isolate();
		void *get_module(int identity);
		void set_module(int identity, void *mod);
		v8::Isolate *operator-> () {
			return isolate;
		}
		template <class T> DataHandle<T> make_handle(T *ptr) {
			return DataHandle<T>(this, ptr);
		}
		static Isolate *get_from_context(CTX &ctx);
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

	class Source {
		private:
		bool compiled = false;
		std::string name;
		std::string program_source;

		void set_compiled();

		protected:
		template <typename L> void compile_str_wrap(CTX &ctx, L l);

		public:
		Source(std::string name, std::string program_source);
		bool is_compiled();
		std::string get_name();
		virtual ~Source() = default;
		virtual void compile(CTX &ctx) = 0;
	};

	class Program : public Source {
		protected:
		Function get_function(CTX &ctx, v8::Local<v8::Object> object, std::string name);

		public:
		Program(std::string name, std::string program_source);
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
		enum ImportType {
			tModule,
			tJSON
		};
		v8::Local<v8::Module> mod;
		std::forward_list<std::shared_ptr<v8::Local<v8::Module>>> submodules;
		static v8::MaybeLocal<v8::Module> load_module(CTX &ctx, std::string name);
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
		static v8::MaybeLocal<v8::Module> load_json(CTX &ctx, std::string name);
		template <class T, class U> static void import_assertions_diverge(CTX &ctx, v8::Local<v8::FixedArray> import_assertions, T t, U u);
#endif
		static v8::MaybeLocal<v8::Module> static_resolve_callback(
				v8::Local<v8::Context> context,
				v8::Local<v8::String> specifier,
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
				v8::Local<v8::FixedArray> import_assertions,
#endif
				v8::Local<v8::Module> referrer
		);

		public:
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
		static v8::MaybeLocal<v8::Promise> dynamic_resolve_callback(
				v8::Local<v8::Context> context,
				v8::Local<v8::Data> host_defined_options,
				v8::Local<v8::Value> resource_name,
				v8::Local<v8::String> specifier,
				v8::Local<v8::FixedArray> import_assertions
		);
#else
		static v8::MaybeLocal<v8::Promise> dynamic_resolve_callback(
				v8::Local<v8::Context> context,
				v8::Local<v8::ScriptOrModule> referrer,
				v8::Local<v8::String> specifier
		);
#endif
		Module(std::string name, std::string module_source);
		void compile(CTX &ctx) final;
		void run(CTX &ctx) final;
		Function get_function(CTX &ctx, std::string name) final;
	};

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
	class JSONModule : public Source {
		private:
		v8::Local<v8::Module> mod;
		v8::Local<v8::Value> json;
		static v8::MaybeLocal<v8::Value> evaluation_steps_callback(v8::Local<v8::Context> context, v8::Local<v8::Module> mod);
		static v8::MaybeLocal<v8::Module> static_resolve_callback_unexpected (
				v8::Local<v8::Context> context,
				v8::Local<v8::String> specifier,
				v8::Local<v8::FixedArray> import_assertions,
				v8::Local<v8::Module> referrer
		);

		public:
		JSONModule(std::string name, std::string program_source);
		operator v8::MaybeLocal<v8::Module>();
		void compile(CTX &ctx) final;
	};
#endif

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
