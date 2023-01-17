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

#include "Js.hxx"

#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <v8.h>
#include <libplatform/libplatform.h>

namespace RRR::JS {
	ENV::ENV(const char *program_name) :
		platform(v8::platform::NewDefaultPlatform())
	{
		v8::V8::InitializeICUDefaultLocation(program_name);
		v8::V8::InitializeExternalStartupData(program_name);
		v8::V8::InitializePlatform(platform.get());
		v8::V8::Initialize();

		isolate_create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
		isolate = v8::Isolate::New(isolate_create_params);
		isolate->SetFatalErrorHandler(fatal_error);
	}

	ENV::~ENV() {
		isolate->Dispose();
		delete isolate_create_params.array_buffer_allocator;

		v8::V8::Dispose();
	}

	ENV::operator v8::Isolate *() {
		return isolate;
	}

	void ENV::fatal_error(const char *where, const char *what) {
		printf("Fatal error from V8. This is a bug. : %s %s\n", where, what);
		abort();
	}

	Isolate::Isolate(ENV &env) :
		isolate(env.isolate),
		isolate_scope(isolate),
		handle_scope(isolate)
	{
	}

	Value::Value(v8::Local<v8::Value> value) :
		v8::Local<v8::Value>(value)
	{
	}

	Object::Object(v8::Local<v8::Object> object) :
		v8::Local<v8::Object>(object)
	{
	}

	UTF8::UTF8(CTX &ctx, Value &value) :
		utf8(ctx, value)
	{
	}

	UTF8::UTF8(CTX &ctx, Value &&value) :
		utf8(ctx, value)
	{
	}

	UTF8::UTF8(CTX &ctx, v8::Local<v8::String> &str) :
		utf8(ctx, str)
	{
	}

	UTF8::UTF8(v8::Isolate *isolate, v8::Local<v8::String> &str) :
		utf8(isolate, str)
	{
	}

	const char * UTF8::operator * () {
		return *utf8;
	}

	String::String(v8::Isolate *isolate, const char *str) :
		str(v8::String::NewFromUtf8(isolate, str, v8::NewStringType::kNormal).ToLocalChecked()),
		utf8(isolate, this->str)
	{
	}

	String::String(v8::Isolate *isolate, v8::Local<v8::String> str) :
		str(str),
		utf8(isolate, str)
	{
	}

	String::operator v8::Local<v8::String>() {
		return str;
	}

	String::operator v8::Local<v8::Value>() {
		return str;
	}

	const char * String::operator * () {
		static const char *empty = "";
		return str.IsEmpty() ? empty : *utf8;
	}

	String::operator Value () {
		return Value(str);
	}

	bool String::contains(const char *needle) {
		return strstr(*utf8, needle) != NULL;
	}

	U32::U32(v8::Isolate *isolate, uint32_t u) :
		v8::Local<v8::Integer>(v8::Integer::NewFromUnsigned(isolate, u))
	{
	}

	E::E(std::string &&str) :
		RRR::util::E(str)
	{
	}

	Function::Function(v8::Local<v8::Function> &&function) :
		function(function)
	{
	}

	Function::Function() :
		function() {
	}

	void Function::run(CTX &ctx, int argc = 0, Value argv[] = nullptr) {
		if (empty()) {
			throw E("Function object was empty");
		}
		auto scope = Scope(ctx);
		if (argc > 0) {
			v8::Local<v8::Value> values[argc];
			for (int i = 0; i < argc; i++) {
				values[i] = argv[i];
			}
			auto result = function->Call(ctx, ctx, argc, values);
		}
		else {
			auto result = function->Call(ctx, ctx, 0, nullptr);
		}
		// Ignore result
	}

	namespace Console {
		void flog(FILE *target, const v8::FunctionCallbackInfo<v8::Value> &args) {
			auto isolate = args.GetIsolate();
			auto ctx = args.GetIsolate()->GetCurrentContext();
			for (int i = 0; i < args.Length(); i++) {
				auto value = String(isolate, args[i]->ToString(ctx).ToLocalChecked());
				fprintf(target, "%s", *value);
			}
			args.GetReturnValue().Set(true);
		}

		void log(const v8::FunctionCallbackInfo<v8::Value> &args) {
			flog(stdout, args);
		}

		void error(const v8::FunctionCallbackInfo<v8::Value> &args) {
			flog(stderr, args);
		}
	} // namespace Console

	CTX::CTX(ENV &env) :
		ctx(v8::Context::New(env, nullptr))
	{	
		v8::Local<v8::Object> console = (v8::ObjectTemplate::New(env))->NewInstance(ctx).ToLocalChecked();
		{
			auto result = console->Set(ctx, String(*this, "log"), v8::Function::New(ctx, Console::log).ToLocalChecked());
			if (!result.FromMaybe(false)) {
				throw E("Failed to intitialize globals\n");
			}
		}
		{
			auto result = console->Set(ctx, String(*this, "error"), v8::Function::New(ctx, Console::error).ToLocalChecked());
			if (!result.FromMaybe(false)) {
				throw E("Failed to intitialize globals\n");
			}
		}
		{
			auto result = ctx->Global()->Set(ctx, String(*this, "console"), console);
			if (!result.FromMaybe(false)) {
				throw E("Failed to intitialize globals\n");
			}
		}
	}

	CTX::operator v8::Local<v8::Context> () {
		return ctx;
	}

	CTX::operator v8::Local<v8::Value> () {
		return ctx->Global();
	}

	CTX::operator v8::Isolate *() {
		return ctx->GetIsolate();
	}

	Function CTX::get_function(const char *name) {
		v8::MaybeLocal<v8::Value> value = ctx->Global()->Get(ctx, String(*this, name));
		if (value.IsEmpty()) {
			std::string msg("Error while finding function '" + std::string(name) + "'");
			throw E(msg.c_str());
		}
		if (value.ToLocalChecked()->IsUndefined()) {
			std::string msg("Function '" + std::string(name) + "' not found");
			throw E(msg.c_str());
		}
		if (!value.ToLocalChecked()->IsFunction()) {
			std::string msg("Name '" + std::string(name) + "' was not a function");
			throw E(msg.c_str());
		}
		return Function(value.ToLocalChecked().As<v8::Function>());
	}

	void CTX::run_function(TryCatch &trycatch, Function &function, const char *name, int argc = 0, Value argv[] = nullptr) {
		auto &ctx = *this;
		function.run(ctx, argc, argv);
		if (trycatch.ok(ctx, [ctx, name](const char *msg) mutable {
			throw E(std::string("Exception while running function '") + name + "': " + msg + "\n");
		})) {
			// OK
		}
	}

	void CTX::run_function(TryCatch &trycatch, const char *name, int argc = 0, Value argv[] = nullptr) {
		auto function = get_function(name);
		run_function(trycatch, function, name, argc, argv);
	}

	Scope::Scope(CTX &ctx) :
		ctx(ctx)
	{
		ctx.ctx->Enter();
	}

	Scope::~Scope() {
		ctx.ctx->Exit();
	}

	void Script::compile(CTX &ctx, TryCatch &trycatch) {
		if (trycatch.ok(ctx, [ctx](const char *msg) mutable {
			throw E(std::string("Failed to compile script: ") + msg);
		})) {
			// OK
		}
	}

	Script::Script(CTX &ctx, TryCatch &trycatch, String &&str) :
		script(v8::Script::Compile(ctx, str).ToLocalChecked())
	{
		compile(ctx, trycatch);
	}

	Script::Script(CTX &ctx, TryCatch &trycatch, std::string &&str) :
		script()
	{
		v8::MaybeLocal<v8::Script> script_(v8::Script::Compile(ctx, v8::String::NewFromUtf8(ctx, str.c_str(), v8::String::kNormalString, str.length())));
		if (script_.IsEmpty()) {
			throw E("Failed to compile script");
		}
		script = script_.ToLocalChecked();
		compile(ctx, trycatch);
	}

	void Script::run(CTX &ctx, TryCatch &trycatch) {
		auto result = script->Run(ctx).FromMaybe((v8::Local<v8::Value>) String(ctx, ""));
		if (trycatch.ok(ctx, [ctx](const char *msg) mutable {
			throw E(std::string("Exception while running script: ") + std::string(msg));
		})) {
			// OK
		}
		// Ignore result
	}
} // namespace RRR::JS

