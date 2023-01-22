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
#include <algorithm>
#include <forward_list>
#include <cassert>
#include "../util/E.hxx"

namespace RRR::JS {
	class CTX;
	class Scope;
	class TryCatch;
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

	class Persistable {
		private:
		int64_t total_memory = 0;

		protected:
		// Derived classes must implement this and report the current
		// estimated size of the object so that we can report changes
		// to V8.
		virtual int64_t get_total_memory() = 0;

		public:
		// Called reguralerly by storage
		int64_t get_unreported_memory() {
			int64_t total_memory_new = get_total_memory();
			int64_t diff = total_memory_new - total_memory;
			total_memory = total_memory_new;
			return diff;
		}
		// Called by storage before object is destroyed
		int64_t get_total_memory_finalize() {
			assert(total_memory >= 0);
			int64_t ret = total_memory;
			total_memory = 0;
			return ret;
		}
		virtual ~Persistable() = default;
	};

	template <class T> class PersistentStorage {
		private:
		template <class U> class Persistent {
			private:
			v8::Persistent<v8::Object> persistent;
			bool done;
			std::unique_ptr<U> t;

			public:
			int64_t get_unreported_memory() {
				return t->get_unreported_memory();
			}
			int64_t get_total_memory_finalize() {
				return t->get_total_memory_finalize();
			}
			static void gc(const v8::WeakCallbackInfo<void> &info) {
				auto self = (Persistent<U> *) info.GetParameter();
				printf("GC called for %p, done\n", self);
				self->persistent.Reset();
				self->done = true;
			}
			Persistent(v8::Isolate *isolate, v8::Local<v8::Object> obj, U *t) :
				t(t),
				persistent(isolate, obj),
				done(false)
			{
				printf("Persistent %p for %p created\n", this, this->t.get());
				persistent.SetWeak<void>(this, gc, v8::WeakCallbackType::kParameter);
			}
			Persistent(const Persistent &p) = delete;
			~Persistent() {
				printf("Persistent %p for %p destroy done %i\n", this, t.get(), done);
			}
			bool is_done() const {
				return done;
			}
		};

		v8::Isolate *isolate;
		std::forward_list<std::unique_ptr<Persistent<T>>> persistents;
		int entries;

		public:
		PersistentStorage(v8::Isolate *isolate) :
			isolate(isolate),
			persistents(),
			entries(0)
		{
		}
		PersistentStorage(const PersistentStorage &p) = delete;
		void report_memory(int64_t memory) {
			printf("Report memory %li\n", memory);
			isolate->AdjustAmountOfExternalAllocatedMemory(memory);
		}
		void push(v8::Isolate *isolate, v8::Local<v8::Object> obj, T *t) {
			persistents.emplace_front(new Persistent(isolate, obj, t));
			entries++;
			printf("Push %i entries\n", entries);
		}
		void gc() {
			printf("GC %i entries\n", entries);
			std::for_each(persistents.begin(), persistents.end(), [this](auto &p){
				int64_t memory = p->get_unreported_memory();
				if (memory != 0) {
					report_memory(memory);
				}
			});
			persistents.remove_if([this](auto &p){
				if (p->is_done()) {
					entries--;
					// Report negative value as memory is now being freed up
					report_memory(-p->get_total_memory_finalize());
				}
				return p->is_done();
			});
		}
	};

	class Isolate {
		private:
		v8::Isolate *isolate;
		v8::Isolate::Scope isolate_scope;
		v8::HandleScope handle_scope;

		public:
		Isolate(ENV &env);
		~Isolate();
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
		template <typename T> void set_global(std::string name, T object) {
			auto result = ctx->Global()->Set(ctx, String(*this, name), object);
			if (!result.FromMaybe(false)) {
				throw E("Failed to set global '" + name + "'\n");
			}
		}
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

	template <class A, class B> class Duple {
		private:
		A a;
		B b;

		public:
		Duple(A a, B b) : a(a), b(b) {}
		A first() { return a; }
		B second() { return b; }
	};
} // namespace RRR::JS
