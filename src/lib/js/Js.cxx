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
#include "../util/Readfile.hxx"

#include <stdio.h>
#include <stdlib.h>

#include <libplatform/libplatform.h>
#include <v8.h>

#include <cassert>
#include <iostream>
#include <algorithm>

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
		RRR_BUG("Fatal error from V8. This is a bug. : %s %s\n", where, what);
	}

	Isolate::Isolate(ENV &env) :
		isolate(env.isolate),
		isolate_scope(isolate),
		handle_scope(isolate)
	{
	}

	Isolate::~Isolate() {
	}

	Value::Value(v8::Local<v8::Value> value) :
		v8::Local<v8::Value>(value)
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

	int UTF8::length() {
		return utf8.length();
	}

	String::String(v8::Isolate *isolate, const char *str) :
		str(v8::String::NewFromUtf8(isolate, str, v8::NewStringType::kNormal).ToLocalChecked()),
		utf8(isolate, this->str)
	{
	}

	String::String(v8::Isolate *isolate, const char *data, int size) :
		str(v8::String::NewFromUtf8(isolate, data, v8::NewStringType::kNormal, size).ToLocalChecked()),
		utf8(isolate, this->str)
	{
	}

	String::String(v8::Isolate *isolate, v8::Local<v8::String> str) :
		str(str.IsEmpty() ? ((v8::MaybeLocal<v8::String>) v8::String::NewFromUtf8(isolate, "")).ToLocalChecked() : str),
		utf8(isolate, this->str)
	{
	}

	String::String(v8::Isolate *isolate, std::string str) :
		str(v8::String::NewFromUtf8(isolate, str.c_str(), v8::NewStringType::kNormal).ToLocalChecked()),
		utf8(isolate, this->str)
	{
	}

	String::operator v8::Local<v8::String>() {
		return str;
	}

	String::operator v8::Local<v8::Value>() {
		return str;
	}

	String::operator std::string() {
		static const char *empty = "";
		return std::string(str.IsEmpty() ? empty : *utf8);
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

	int String::length() {
		return utf8.length();
	}

	U32::U32(v8::Isolate *isolate, uint32_t u) :
		v8::Local<v8::Integer>(v8::Integer::NewFromUnsigned(isolate, u))
	{
	}

	E::E(std::string &&str) :
		RRR::util::E(str)
	{
	}

	Function::Function() :
		function()
	{
	}

	Function::Function(v8::Local<v8::Function> function) :
		function(function)
	{
	}

	void Function::run(CTX &ctx, int argc = 0, Value argv[] = nullptr) {
		if (empty()) {
			throw E("Function object was empty");
		}
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
		void flog(uint8_t loglevel, const v8::FunctionCallbackInfo<v8::Value> &args) {
			auto isolate = args.GetIsolate();
			auto ctx = args.GetIsolate()->GetCurrentContext();
			for (int i = 0; i < args.Length(); i++) {
				auto value = String(isolate, args[i]->ToString(ctx).ToLocalChecked());
				RRR_MSG_X(loglevel, "%s", *value);
			}
			args.GetReturnValue().Set(true);
		}

		void log(const v8::FunctionCallbackInfo<v8::Value> &args) {
			flog(7, args);
		}

		void error(const v8::FunctionCallbackInfo<v8::Value> &args) {
			flog(0, args);
		}
	} // namespace Console

	CTX::CTX(v8::Local<v8::Context> ctx, std::string script_name) :
		ctx(ctx),
		script_name(script_name),
		trycatch(*this)
	{
		ctx->Enter();
		trycatch.SetCaptureMessage(true);
	}
	CTX::CTX(ENV &env, std::string script_name) :
		ctx(v8::Context::New(env, nullptr)),
		script_name(script_name),
		trycatch(*this)
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
		ctx->Enter();
		trycatch.SetCaptureMessage(true);
	}

	CTX::~CTX() {
		ctx->Exit();
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

	void CTX::run_function(Function &function, const char *name, int argc = 0, Value argv[] = nullptr) {
		auto &ctx = *this;
		function.run(ctx, argc, argv);
		if (trycatch_ok([&ctx, name](const char *msg) mutable {
			throw E(std::string("Exception while running function '") + name + "': " + msg + "\n");
		})) {
			// OK
		}
	}

	std::string CTX::make_location_message(v8::Local<v8::Message> msg) {
		auto &ctx = *this;
		std::string str("");
		int line = 0;
		int col = 0;

		auto source_line = msg->GetSourceLine(ctx);
		auto line_number = msg->GetLineNumber(ctx);
		auto column = msg->GetStartColumn(ctx);
		auto resource = msg->GetScriptResourceName();
		auto msg_string = String(ctx, msg->Get());

		if (!line_number.IsNothing()) {
			line = line_number.ToChecked();
		}
		if (!column.IsNothing()) {
			col = column.ToChecked();
		}

		str += "In " + script_name + "\n";

		if (!resource->IsNullOrUndefined()) {
			auto resource_str = String(ctx, resource->ToString((v8::Local<v8::Context>) ctx).ToLocalChecked());
			str += std::string(" resource ") + *resource_str + "\n";
		}

		str += " line " + std::to_string(line) +
		       " col " + std::to_string(col) + ": " + std::string(msg_string) + "\n";

		if (!source_line.IsEmpty()) {
			auto line_str = (std::string) String(ctx, source_line.ToLocalChecked());
			std::replace(line_str.begin(), line_str.end(), '\t', ' ');
			auto srcline = std::string(std::to_string(line));
			str += "\n";
			str.append(6 - (srcline.length() < 6 ? srcline.length() : 6), ' ');
			str += srcline + " | " + line_str + "\n";
			str.append(rrr_length_from_slength_bug_const(col), ' ');
			str += "        ~^~ Here\n";
		}

		return str;
	}

	void Program::set_compiled() {
		assert(!compiled);
		compiled = true;
	}

	template <typename L> void Program::compile_str_wrap(CTX &ctx, L l) {
		if (program_source.length() > v8::String::kMaxLength) {
			throw E("Script or module data too long");
		}
		l(v8::String::NewFromUtf8 (
				ctx,
				program_source.c_str(),
				v8::NewStringType::kNormal,
				(int) program_source.length()
		).ToLocalChecked());

		set_compiled();
	}

	Function Program::get_function(CTX &ctx, v8::Local<v8::Object> object, std::string name) {
		// Enforce usage of MaybeLocal overload as Local overload is deprecated
		v8::MaybeLocal<v8::Value> value = object->Get(ctx, (v8::Local<v8::String>) String(ctx, name));
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

	Program::Program(std::string name, std::string program_source) :
		name(name),
		program_source(program_source)
	{
	}

	bool Program::is_compiled() {
		return compiled;
	}

	std::string Program::get_name() {
		return name;
	}

	Script::Script(std::string name, std::string script_source) :
		Program(name, script_source),
		script()
	{
		RRR_DBG_1("V8 new Script %s\n", name.c_str());
	}

	void Script::compile(CTX &ctx) {
		compile_str_wrap(ctx, [&ctx,this](auto str){
			auto script_maybe = v8::Script::Compile (ctx, str);
			if (ctx.trycatch_ok([](auto msg){
				throw E(std::string("Failed to compile script: ") + msg);
			})) {
				// OK
			}
			script = script_maybe.ToLocalChecked();
		});
	}

	void Script::run(CTX &ctx) {
		assert(compiled);
		auto result = script->Run(ctx).FromMaybe((v8::Local<v8::Value>) String(ctx, ""));
		// Ignore result
	}

	Function Script::get_function(CTX &ctx, std::string name) {
		return Program::get_function(ctx, ((v8::Local<v8::Context>) ctx)->Global(), name);
	}

	v8::MaybeLocal<v8::Module> Module::resolve_callback (
			v8::Local<v8::Context> context,
			v8::Local<v8::String> specifier,
			v8::Local<v8::Module> referrer
	) {
		RRR_DBG_1("V8 import %s\n", ((std::string) String(context->GetIsolate(), specifier)).c_str());

		auto name = std::string(String(context->GetIsolate(), specifier));
		auto ctx = CTX(context, name);
		try {
			auto submodule = Module(name, std::string(RRR::util::Readfile(name, 0, 0)));
			submodule.compile(ctx);
			submodule.run(ctx);
			return submodule;
		}
		catch (RRR::util::Readfile::E e) {
			throw E(std::string("Failed to read from module file '") + name + "': " + ((std::string) e));
		}
		catch (RRR::util::E e) {
			throw E(std::string("Failed to load module '") + name + "': " + ((std::string) e));
		}
		return v8::MaybeLocal<v8::Module>();
	}

	Module::operator v8::MaybeLocal<v8::Module>() {
		return mod;
	}

	Module::Module(std::string name, std::string module_source) :
		Program(name, module_source),
		mod(),
		submodules()
	{
		RRR_DBG_1("V8 new Module %s\n", name.c_str());
	}

	void Module::compile(CTX &ctx) {
		compile_str_wrap(ctx, [&ctx,this](auto str){
			auto origin = v8::ScriptOrigin(
					(v8::Local<v8::String>) String(ctx, name),
					v8::Local<v8::Integer>(),
					v8::Local<v8::Integer>(),
					v8::Local<v8::Boolean>(),
					v8::Local<v8::Integer>(),
					v8::Local<v8::Value>(),
					v8::Local<v8::Boolean>(),
					v8::Local<v8::Boolean>(),
					v8::Boolean::New(ctx, true) // is_module
			);
			auto source = v8::ScriptCompiler::Source(str, origin);
			auto module_maybe = v8::ScriptCompiler::CompileModule(ctx, &source);
			if (ctx.trycatch_ok([](auto msg){
				throw E(std::string("Failed to compile module: ") + msg);
			})) {
				// OK
			}
			mod = module_maybe.ToLocalChecked();
		});

		if (ctx.trycatch_ok([](auto msg){
			throw E(std::string("Failed to instantiate  module: ") + msg);
		})) {
			// OK
		}
	}

	void Module::run(CTX &ctx) {
		if (mod->InstantiateModule(ctx, resolve_callback).IsNothing()) {
			throw E(std::string("Instantiation of module ") + name + (" failed"));
		}
		assert (mod->GetStatus() == v8::Module::Status::kInstantiated);

		// Ignore result
		auto result = mod->Evaluate(ctx);
		if (mod->GetStatus() != v8::Module::Status::kEvaluated) {
			if (ctx.trycatch_ok([](auto msg){
				throw E(std::string("Failed to evaluate module: ") + msg);
			})) {
				// OK
			}
			throw E(std::string("Failed to evaluate module, unknown reason."));
		}
	}

	Function Module::get_function(CTX &ctx, std::string name) {
		// Force use of MaybeLocal overloads as Local overloads are deprecated
		v8::Local<v8::Object> object = mod->GetModuleNamespace()->ToObject((v8::Local<v8::Context>) ctx).ToLocalChecked();
		return Program::get_function(ctx, object, name);
	}
} // namespace RRR::JS

