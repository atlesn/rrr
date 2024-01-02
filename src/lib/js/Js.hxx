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

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
#  include <v8-value.h>
#endif
#include <v8.h>
#include <forward_list>
#include <map>
#include <cassert>

extern "C" {
#include "../rrr_types.h"
};

namespace RRR::JS {
	class CTX;
	class Scope;
	class Isolate;
	class Source;

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
		private:
		uint32_t data_pos = 0;
		v8::Isolate *isolate;
		v8::Isolate::Scope isolate_scope;
		v8::HandleScope handle_scope;
		std::map<int,std::shared_ptr<Source>> module_map;
		template <typename T> void register_module(int identity, std::shared_ptr<T> mod);
		template <typename T> std::shared_ptr<T> compile_module(CTX &ctx, std::shared_ptr<T> mod);

		public:
		Isolate(ENV &env);
		~Isolate();
		template <typename T, typename = std::enable_if_t<std::is_base_of_v<Source, T>>> std::shared_ptr<T> get_module(int identity);
		template <typename T> std::shared_ptr<T> make_module(CTX &ctx, const std::string &cwd, const std::string &path, const std::string &program_source);
		template <typename T> std::shared_ptr<T> make_module(CTX &ctx, const std::string &absolute_path);
		v8::Isolate *operator-> ();
		static Isolate *get_from_context(CTX &ctx);
	};

	class Value : public v8::Local<v8::Value> {
		public:
		Value(v8::Local<v8::Value> value);
	};

	class Undefined : public Value {
		public:
		Undefined(CTX &ctx);
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
		bool begins_with(char c);
		int length();
	};

	class U32 : public v8::Local<v8::Integer> {
		public:
		U32(v8::Isolate *isolate, uint32_t u);
	};

	class E : public RRR::util::E {
		public:
		E(std::string str);
	};

	template <class A, class B> class Duple {
		private:
		A a;
		B b;

		public:
		Duple(A a, B b) : a(a), b(b) {}
		A first() { return a; }
		B second() { return b; }
		A first() const { return a; }
		B second() const { return b; }
		A* operator->() { return &a; };
		const A* operator->() const { return &a; };
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
		operator v8::Local<v8::Function>() {
			return function;
		}
	};

	class CTX {
		private:
		v8::Local<v8::Context> ctx;
		v8::TryCatch trycatch;
		std::string script_name;

		public:
		std::string make_location_message(v8::Local<v8::Message> msg);
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
		const std::string cwd;
		const std::string name;
		const std::string program_source;

		void set_compiled();
		static const std::string &verify_cwd(const std::string &cwd);
		static const std::string &verify_name(const std::string &name);
		static Duple<std::string, std::string> split_path(const std::string &path);

		protected:
		template <typename L> void compile_str_wrap(CTX &ctx, L l);
		virtual bool is_type(const std::type_info &type) const = 0;
		const std::string &get_cwd() const {
			return cwd;
		}
		const std::string &get_name() const {
			return name;
		}
		std::string get_path_() const {
			return cwd + "/" + name;
		}

		public:
		Source(const std::string &cwd, const std::string &name, const std::string &program_source);
		Source(const Duple<std::string,std::string> &cwd_and_name, const std::string &program_source);
		Source(const std::string &absolute_path);
		template <typename T, typename = std::enable_if_t<std::is_base_of_v<Source, T>>> static std::shared_ptr<T> cast(std::shared_ptr<Source> ptr);
		template <typename T, typename = std::enable_if_t<std::is_base_of_v<Source, T>>> static T *cast(Source *ptr);
		bool is_compiled() const;
		virtual ~Source() = default;
	};

	class Program : public Source {
		protected:
		Program(const std::string &cwd, const std::string &name, const std::string &program_source);
		Program(const std::string &absolute_path);
		Function get_function(CTX &ctx, v8::Local<v8::Object> object, std::string name);

		public:
		virtual ~Program() = default;
		void run(CTX &ctx);
		virtual void _run(CTX &ctx) = 0;
		virtual Function get_function(CTX &ctx, std::string name) = 0;
	};

	class Script : public Program {
		friend class Isolate;

		private:
		v8::Local<v8::Script> script;
		void _run(CTX &ctx) final;

		protected:
		bool is_type(const std::type_info &type) const override {
			return typeid(Script) == type;
		};
		Script(const std::string &cwd, const std::string &name, const std::string &script_source);
		Script(const std::string &absolute_path);

		public:
		void compile(CTX &ctx);
		static std::shared_ptr<Script> make_shared (const std::string &cwd, const std::string &name, const std::string &module_source);
		static std::shared_ptr<Script> make_shared (const std::string &absolute_path);
		Function get_function(CTX &ctx, std::string name) final;
	};

	class ImportCallbackData {
		private:
		Source *mod;

		public:
		ImportCallbackData(Source *mod) : mod(mod) {}
		template <typename T, typename = std::enable_if_t<std::is_base_of_v<Source, T>>> T *get_module() const;
	};

	class Module : public Program {
		friend class Isolate;

		private:
		Module(const std::string &cwd, const std::string &name, const std::string &module_source);
		Module(const std::string &absolute_path);
		static std::shared_ptr<Module> make_shared (const std::string &cwd, const std::string &name, const std::string &module_source);
		static std::shared_ptr<Module> make_shared (const std::string &absolute_path);
		enum ImportType {
			tModule,
			tJSON
		};
		v8::Local<v8::Module> mod;
		std::forward_list<std::shared_ptr<v8::Local<v8::Module>>> submodules;
		ImportCallbackData import_callback_data;
		static std::string load_resolve_path(const std::string &specifier, const std::string &referrer);
		template<typename L> static v8::MaybeLocal<v8::Module> load_wrap(const std::string &referrer_cwd, const std::string &relative_path, L l);
		static v8::MaybeLocal<v8::Module> load_module(CTX &ctx, const std::string &referrer_cwd, const std::string &relative_path);
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
		static v8::MaybeLocal<v8::Module> load_json(CTX &ctx, const std::string &referrer_cwd, const std::string &relative_path);
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
		void _run(CTX &ctx) final;
		void compile_prepare(CTX &ctx);
		void compile(CTX &ctx);
		bool is_created() const;
		int get_identity_hash() const;
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

		protected:
		bool is_type(const std::type_info &type) const override {
			return typeid(Module) == type;
		};

		public:
		operator v8::MaybeLocal<v8::Module>();
		Function get_function(CTX &ctx, std::string name) final;
	};

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
	class JSONModule : public Source {
		friend class Isolate;

		private:
		JSONModule(const std::string &cwd, const std::string &name, const std::string &program_source);
		JSONModule(const std::string &absolute_path);
		static std::shared_ptr<JSONModule> make_shared (const std::string &cwd, const std::string &name, const std::string &module_source);
		static std::shared_ptr<JSONModule> make_shared (const std::string &absolute_path);
		v8::Local<v8::Module> mod;
		v8::Local<v8::Value> json;
		static v8::MaybeLocal<v8::Value> evaluation_steps_callback (
				v8::Local<v8::Context> context,
				v8::Local<v8::Module> mod
		);
		static v8::MaybeLocal<v8::Module> static_resolve_callback_unexpected (
				v8::Local<v8::Context> context,
				v8::Local<v8::String> specifier,
				v8::Local<v8::FixedArray> import_assertions,
				v8::Local<v8::Module> referrer
		);
		void compile_prepare(CTX &ctx);
		void compile(CTX &ctx);
		bool is_created() const;
		int get_identity_hash() const;

		protected:
		bool is_type(const std::type_info &type) const override {
			return typeid(JSONModule) == type;
		};

		public:
		operator v8::MaybeLocal<v8::Module>();
	};
#endif

	template <typename T> void Isolate::register_module(int identity, std::shared_ptr<T> mod) {
		module_map[mod->get_identity_hash()] = mod;
	}

	template <typename T> std::shared_ptr<T> Isolate::compile_module(CTX &ctx, std::shared_ptr<T> mod) {
		// Prepare phase may or may not create the module, difference
		// being availibility of the identity hash after the call.
		mod->compile_prepare(ctx);

		if (mod->is_created()) {
			const int hash = mod->get_identity_hash();
			module_map[hash] = mod;
			mod->compile(ctx);
			if (!mod->is_compiled()) {
				module_map.erase(hash);
			}
		}
		else {
			mod->compile(ctx);
			if (mod->is_compiled()) {
				const int hash = mod->get_identity_hash();
				module_map[hash] = mod;
			}
		}

		return mod;
	}

	template <typename T> std::shared_ptr<T> Isolate::make_module(CTX &ctx, const std::string &cwd, const std::string &path, const std::string &program_source) {
		return compile_module(ctx, T::make_shared(cwd, path, program_source));
	}

	template <typename T> std::shared_ptr<T> Isolate::make_module(CTX &ctx, const std::string &absolute_path) {
		return compile_module(ctx, T::make_shared(absolute_path));
	}

	template <typename T, typename> T *ImportCallbackData::get_module() const {
		return Source::cast<T>(mod);
	}

	template <typename T, typename> std::shared_ptr<T> Source::cast(std::shared_ptr<Source> ptr) {
		assert(ptr->is_type(typeid(T)));
		return std::static_pointer_cast<T>(ptr);
	}

	template <typename T, typename> T *Source::cast(Source *ptr) {
		assert(ptr->is_type(typeid(T)));
		return static_cast<T*>(ptr);
	}
} // namespace RRR::JS
