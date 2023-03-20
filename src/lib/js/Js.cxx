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
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
#  include <v8-primitive.h>
#endif
#include <v8.h>

#include <cassert>
#include <iostream>
#include <algorithm>
#include <set>
#include <filesystem>

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
		isolate(env),
		isolate_scope(isolate),
		handle_scope(isolate),
		module_map()
	{
		isolate->SetHostImportModuleDynamicallyCallback(Module::dynamic_resolve_callback);
		isolate->SetData(0, this);
	}

	Isolate::~Isolate() {
	}

	template <typename T, typename> std::shared_ptr<T> Isolate::get_module(int identity) {
		RRR_DBG_1("V8 isolate %p get module with id %i type %s\n", this, identity, typeid(T).name());
		return Source::cast<T>(module_map.at(identity));
	}

	v8::Isolate *Isolate::operator-> () {
		return isolate;
	}

	Isolate *Isolate::get_from_context(CTX &ctx) {
		return (Isolate *) ((v8::Isolate *) ctx)->GetData(0);
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
			RRR_UNUSED(result);
		}
		else {
			auto result = function->Call(ctx, ctx, 0, nullptr);
			RRR_UNUSED(result);
		}
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

		void critical(const v8::FunctionCallbackInfo<v8::Value> &args) {
			flog(0, args);
			abort();
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
			auto result = console->Set(ctx, String(*this, "critical"), v8::Function::New(ctx, Console::critical).ToLocalChecked());
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

	void Source::set_compiled() {
		assert(!compiled);
		compiled = true;
	}

	const std::string &Source::verify_cwd (const std::string &cwd) {
		assert (cwd.length() > 0 && cwd.front() == '/');
		return cwd;
	}

	const std::string &Source::verify_name (const std::string &name) {
		assert (!name.empty() && name != "." && name != "..");
		for (const auto &c : name) {
			assert (c != '/');
		}
		return name;
	}

	Duple<std::string, std::string> Source::split_path(const std::string &path) {
		assert(path.length() > 0 && path.front() == '/');

		auto fs_path = std::filesystem::path(path);
		auto dir = fs_path.parent_path().string();
		auto name = fs_path.filename().string();

		return Duple<std::string, std::string>(dir, name);
	}

	template <typename L> void Source::compile_str_wrap(CTX &ctx, L l) {
		if (program_source.length() > v8::String::kMaxLength) {
			throw E("Script or module data too long");
		}
		l(String(ctx, program_source));
		set_compiled();
	}

	Source::Source(const std::string &cwd, const std::string &name, const std::string &program_source) :
		cwd(verify_cwd(cwd)),
		name(verify_name(name)),
		program_source(program_source)
	{
	}

	Source::Source(const Duple<std::string,std::string> &cwd_and_name, const std::string &program_source) :
		cwd(cwd_and_name.first()),
		name(cwd_and_name.second()),
		program_source(program_source)
	{
	}

	Source::Source(const std::string &absolute_path) :
		Source (split_path(absolute_path), (std::string) RRR::util::Readfile(absolute_path, 0, 0))
	{
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

	Program::Program(const std::string &cwd, const std::string &name, const std::string &program_source) :
		Source(cwd, name, program_source)
	{
	}

	Program::Program(const std::string &absolute_path) :
		Source(absolute_path)
	{
	}

	void Program::run(CTX &ctx) {
		assert(is_compiled());
		_run(ctx);
	}

	Script::Script(const std::string &cwd, const std::string &name, const std::string &script_source) :
		Program(cwd, name, script_source),
		script()
	{
		RRR_DBG_1("V8 new Script cwd %s name %s (source provided)\n", cwd.c_str(), name.c_str());
	}

	Script::Script(const std::string &absolute_path) :
		Program(absolute_path),
		script()
	{
		RRR_DBG_1("V8 new Script absolute_path %s\n", absolute_path.c_str());
	}

	std::shared_ptr<Script> Script::make_shared (const std::string &cwd, const std::string &name, const std::string &module_source) {
		return std::shared_ptr<Script>(new Script(cwd, name, module_source));
	}

	std::shared_ptr<Script> Script::make_shared (const std::string &absolute_path) {
		return std::shared_ptr<Script>(new Script(absolute_path));
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

	void Script::_run(CTX &ctx) {
		auto result = script->Run(ctx).FromMaybe((v8::Local<v8::Value>) String(ctx, ""));
		RRR_UNUSED(result);
	}

	Function Script::get_function(CTX &ctx, std::string name) {
		return Program::get_function(ctx, ((v8::Local<v8::Context>) ctx)->Global(), name);
	}

	std::string Module::load_resolve_path(const std::string &referrer_cwd, const std::string &name) {
		if (name.find("/") != 0 && name.find("./") != 0 && name.find("../") != 0) {
			throw E(std::string("Bare import statements are not supported. Specifier must be a path beginning with / or ./ ('" + name + "' was provided and referrer cwd was '" + referrer_cwd + "')"));
		}
		return (std::filesystem::path(referrer_cwd) / name).lexically_normal().string();
	}

	template<typename L> v8::MaybeLocal<v8::Module> Module::load_wrap(const std::string &referrer_cwd, const std::string &relative_path, L l) {
		try {
			return *l(load_resolve_path(referrer_cwd, relative_path));
		}
		catch (RRR::util::Readfile::E e) {
			throw E(std::string("Failed to read from module file '") + relative_path + "' cwd '" + referrer_cwd + "': " + ((std::string) e));
		}
		catch (RRR::util::E e) {
			throw E(std::string("Failed to load module file '") + relative_path + "' cwd '" + referrer_cwd + "': " + ((std::string) e));
		}
		catch (...) {
			throw E(std::string("Failed to load module. Unknown reason."));
		}
	}

	v8::MaybeLocal<v8::Module> Module::load_module(CTX &ctx, const std::string &referrer_cwd, const std::string &relative_path) {
		return load_wrap(referrer_cwd, relative_path, [&ctx](const std::string &absolute_path){
			auto mod = std::shared_ptr<Module>(Isolate::get_from_context(ctx)->make_module<Module>(ctx, absolute_path));
			mod->run(ctx);
			return mod;
		});
	}

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
	v8::MaybeLocal<v8::Module> Module::load_json(CTX &ctx, const std::string &referrer_cwd, const std::string &relative_path) {
		return load_wrap(referrer_cwd, relative_path, [&ctx](const std::string &absolute_path){
			auto mod = std::shared_ptr<JSONModule>(Isolate::get_from_context(ctx)->make_module<JSONModule>(ctx, absolute_path));
			mod->run(ctx);
			return mod;
		});
	}

	template <class T, class U> void Module::import_assertions_diverge(CTX &ctx, v8::Local<v8::FixedArray> import_assertions, T t, U u) {
		assert(import_assertions->Length() % 2 == 0);

		std::set<std::string> encountered_keys;
		ImportType type = tModule;

		for (int i = 0; i < import_assertions->Length(); i += 2) {
			auto key_data = import_assertions->Get(ctx, i);
			auto value_data = import_assertions->Get(ctx, i);
			if (key_data.IsEmpty()) {
				throw E("Undefined key in import assertions");
			}

			auto key = (std::string) String(ctx, import_assertions->Get(ctx, i).As<v8::String>());
			if (encountered_keys.find(key) != encountered_keys.end()) {
				throw E(std::string("Import assertion key '") + key + "' specified more than once");
			}

			if (key.compare("type") == 0) {
				if (value_data.IsEmpty()) {
					// OK, assume script
					type = tModule;
					continue;
				}

				// TODO : Uncertainty about what types are actually legal.
				auto value = (std::string) String(ctx, import_assertions->Get(ctx, i + 1).As<v8::String>());
				if (value.compare("module") == 0) {
					type = tModule;
				}
				else if (value.compare("json") == 0) {
					type = tJSON;
				}
				else {
					throw E(std::string("Unsupported import assertion type '") + value + "'. Only no type set, meaning script, is supported.");
				}
			}
			else {
				throw E(std::string("Unknown import assertion key '") + key + "'. Only no type set, meaning script, is supported.");
			}
		}

		switch (type) {
			case tModule:
				t();
				break;
			case tJSON:
				u();
				break;
			default:
				assert(0);
		};
	}
#endif

	v8::MaybeLocal<v8::Module> Module::static_resolve_callback (
			v8::Local<v8::Context> context,
			v8::Local<v8::String> specifier,
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
v8::Local<v8::FixedArray> import_assertions,
#endif
			v8::Local<v8::Module> referrer
	) {
		auto name = std::string(String(context->GetIsolate(), specifier));
		auto ctx = CTX(context, name);
		auto referrer_cwd = Isolate::get_from_context(ctx)
			->get_module<Module>(referrer->GetIdentityHash())
			->get_cwd();

		RRR_DBG_1("V8 static import %s referrer cwd %s\n", name.c_str(), referrer_cwd.c_str());

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
		auto mod = v8::MaybeLocal<v8::Module>();
		import_assertions_diverge<>(ctx, import_assertions, [&ctx,referrer_cwd,name,&mod](){
			mod = load_module(ctx, referrer_cwd, name);
		}, [&ctx,referrer_cwd,name,&mod](){
			mod = load_json(ctx, referrer_cwd, name);
		});
		return mod;
#else
		return load_module(ctx, referrer_cwd, name);
#endif
	}

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
	v8::MaybeLocal<v8::Promise> Module::dynamic_resolve_callback(
			v8::Local<v8::Context> context,
			v8::Local<v8::Data> host_defined_options,
			v8::Local<v8::Value> resource_name,
			v8::Local<v8::String> specifier,
			v8::Local<v8::FixedArray> import_assertions
	) {
		auto name = std::string(String(context->GetIsolate(), specifier));
		auto ctx = CTX(context, name);
		auto resolver = v8::Promise::Resolver::New(ctx).ToLocalChecked();
		auto import_callback_data = static_cast<ImportCallbackData*>(v8::External::Cast(host_defined_options)->Value());

		try {
#else
	v8::MaybeLocal<v8::Promise> Module::dynamic_resolve_callback (
			v8::Local<v8::Context> context,
			v8::Local<v8::ScriptOrModule> referrer,
			v8::Local<v8::String> specifier
	) {
		auto name = std::string(String(context->GetIsolate(), specifier));
		auto ctx = CTX(context, name);
		auto resolver = v8::Promise::Resolver::New(ctx).ToLocalChecked();
		auto host_defined_options = referrer->GetHostDefinedOptions();

		try {
			if (host_defined_options->Length() == 0) {
				throw E("Cannot import dynamically from this context");
			}
			auto import_callback_data = &(
				Isolate::get_from_context(ctx)
					->get_module<Module> (
							v8::Local<v8::Int32>::Cast(host_defined_options->Get(ctx, 0))->Value()
					)
				->import_callback_data
			);
#endif
			auto referrer_cwd = import_callback_data
				->get_module<Module>()
				->get_cwd();

			RRR_DBG_1("V8 dynamic import %s referrer cwd %s\n", name.c_str(), referrer_cwd.c_str());

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
			import_assertions_diverge(ctx, import_assertions, [&ctx,name,resolver](){
#endif
				auto mod = load_module(ctx, referrer_cwd, name);
				resolver->Resolve(ctx, mod.ToLocalChecked()->GetModuleNamespace()->ToObject((v8::Local<v8::Context>) ctx).ToLocalChecked()).Check();
#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
			}, [&ctx,name,resolver](){
				auto mod = load_json(ctx, referrer_cwd, name);
				resolver->Resolve(ctx, mod.ToLocalChecked()->GetModuleNamespace()->ToObject((v8::Local<v8::Context>) ctx).ToLocalChecked()).Check();
			});
#endif
		}
		catch(RRR::util::E e) {
			// Reject
			auto msg = String(ctx, std::string("Error while loading module ") + name + ": " + std::string(e));
			resolver->Reject(ctx, msg).Check();
			// ((v8::Isolate *) ctx)->ThrowException(String(ctx, std::string("Error while loading module ") + name + ": " + std::string(e)));
		}
		return resolver->GetPromise();
	}

	Module::Module(const std::string &cwd, const std::string &name, const std::string &module_source) :
		Program(cwd, name, module_source),
		mod(),
		import_callback_data(this),
		submodules()
	{
		RRR_DBG_1("V8 new Module cwd %s name %s (source provided)\n", cwd.c_str(), name.c_str());
	}

	Module::Module(const std::string &absolute_path) :
		Program(absolute_path),
		mod(),
		import_callback_data(this),
		submodules()
	{
		RRR_DBG_1("V8 new Module absolute_path %s\n", absolute_path.c_str());
	}

	std::shared_ptr<Module> Module::make_shared (const std::string &cwd, const std::string &name, const std::string &module_source) {
		return std::shared_ptr<Module>(new Module(cwd, name, module_source));
	}

	std::shared_ptr<Module> Module::make_shared (const std::string &absolute_path) {
		return std::shared_ptr<Module>(new Module(absolute_path));
	}

	Module::operator v8::MaybeLocal<v8::Module>() {
		assert(is_compiled());
		return mod;
	}

	void Module::compile(CTX &ctx) {
		compile_str_wrap(ctx, [&ctx,this](auto str){
#ifdef RRR_HAVE_V8_PRIMITIVE_ARGS_TO_SCRIPTORIGIN
			auto host_defined_options = v8::Local<v8::External>::New(ctx, &import_callback_data);
			auto origin = v8::ScriptOrigin (
					ctx,
					(v8::Local<v8::String>) String(ctx, get_path()),
					0,
					0,
					false,
					-1,
					v8::Local<v8::Value>(),
					false,
					false,
					true, // is_module
					v8::Local<v8::External>::New(ctx, &import_callback_data)
			);
#else
			// Element 0 is set after mod is created below
			auto host_defined_options = v8::PrimitiveArray::New(ctx, 1);
			auto origin = v8::ScriptOrigin (
					(v8::Local<v8::String>) String(ctx, get_path_()),
					v8::Local<v8::Integer>(),
					v8::Local<v8::Integer>(),
					v8::Local<v8::Boolean>(),
					v8::Local<v8::Integer>(),
					v8::Local<v8::Value>(),
					v8::Local<v8::Boolean>(),
					v8::Local<v8::Boolean>(),
					v8::Boolean::New(ctx, true), // is_module
					host_defined_options
			);
#endif
			auto source = v8::ScriptCompiler::Source(str, origin);
			auto module_maybe = v8::ScriptCompiler::CompileModule(ctx, &source);
			if (ctx.trycatch_ok([](auto msg){
				throw E(std::string("Failed to compile module: ") + msg);
			})) {
				// OK
			}
			mod = module_maybe.ToLocalChecked();
			host_defined_options->Set(ctx, 0, v8::Int32::New(ctx, mod->GetIdentityHash()));
		});

		if (ctx.trycatch_ok([](auto msg){
			throw E(std::string("Failed to instantiate  module: ") + msg);
		})) {
			// OK
		}
	}

	int Module::get_identity_hash() const {
		return mod->GetIdentityHash();
	}

	void Module::_run(CTX &ctx) {
		if (mod->InstantiateModule(ctx, static_resolve_callback).IsNothing()) {
			throw E(std::string("Instantiation of module ") + get_path_() + (" failed"));
		}
		assert (mod->GetStatus() == v8::Module::Status::kInstantiated);

		auto result = mod->Evaluate(ctx);
		RRR_UNUSED(result);
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

#ifdef RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK
	v8::MaybeLocal<v8::Value> JSONModule::evaluation_steps_callback(v8::Local<v8::Context> context, v8::Local<v8::Module> mod) {
		auto ctx = CTX(context, __func__);
		auto self = Isolate::get_from_context(ctx)->get_module<JSONModule>(mod->GetIdentityHash());
		auto result = mod->SetSyntheticModuleExport(ctx, String(ctx, "default"), self->json);
		if (ctx.trycatch_ok([](auto msg){
			throw E(std::string("Failed set default export for JSON module: ") + msg);
		})) {
			// OK
		}
		return v8::Boolean::New(ctx, true);

//		ns->Set(ctx, String(ctx, "default"), json.ToLocalChecked()).Check();
//		auto ns = mod->GetModuleNamespace().As<v8::Object>();
//.		assert(0);

/*

			assert(!result.IsNothing());*/
	}

	v8::MaybeLocal<v8::Module> JSONModule::static_resolve_callback_unexpected (
			v8::Local<v8::Context> context,
			v8::Local<v8::String> specifier,
			v8::Local<v8::FixedArray> import_assertions,
			v8::Local<v8::Module> referrer
	) {
		assert(0);
	}

	JSONModule::JSONModule(const std::string &cwd, const std::string &name, std::string program_source) :
		Source(cwd, name, program_source),
		mod(),
		json()
	{
		RRR_DBG_1("V8 new JSON cwd %s name %s (source provided)\n", cwd.c_str(), name.c_str());
	}

	JSONModule::JSONModule(const std::string &absolute_path) :
		Source(absolute_path),
		mod(),
		json()
	{
		RRR_DBG_1("V8 new JSON cwd %s name %s\n", cwd.c_str(), name.c_str());
	}

	std::shared_ptr<JSONModule> JSONModule::make_shared (const std::string &cwd, const std::string &name, const std::string &module_source) {
		return std::shared_ptr<JSONModule>(new JSONModule(cwd, name, module_source));
	}

	std::shared_ptr<JSONModule> JSONModule::make_shared (const std::string &absolute_path) {
		return std::shared_ptr<JSONModule>(new JSONModule(absolute_path));
	}

	JSONModule::operator v8::MaybeLocal<v8::Module>() {
		assert(is_compiled());
		return mod;
	}

	void JSONModule::compile(CTX &ctx) {
		auto export_names = std::vector<v8::Local<v8::String>>();
		export_names.emplace_back(String(ctx, "default"));

		mod = v8::Module::CreateSyntheticModule (
			ctx,
			String(ctx, get_path_()),
			export_names,
			evaluation_steps_callback
		);

		if (ctx.trycatch_ok([](auto msg){
			throw E(std::string("Failed to create JSON module: ") + msg);
		})) {
			// OK
		}

		assert(!mod.IsEmpty());

		Isolate::get_from_context(ctx)->set_module(mod->GetIdentityHash(), this);

		compile_str_wrap(ctx, [&ctx,this](auto str){
			auto json_maybe = v8::JSON::Parse(ctx, str);
			if (ctx.trycatch_ok([](auto msg){
				throw E(std::string("Failed to parse JSON module: ") + msg);
			})) {
				// OK
			}
			json = json_maybe.ToLocalChecked();

			if (mod->InstantiateModule(ctx, static_resolve_callback_unexpected).IsNothing()) {
				throw E(std::string("Instantiation of module ") + get_path_() + (" failed"));
			}
			assert (mod->GetStatus() == v8::Module::Status::kInstantiated);

			auto result = mod->Evaluate(ctx);
			if (ctx.trycatch_ok([](auto msg){
				throw E(std::string("Failed to evaluate JSON module: ") + msg);
			})) {
				// OK
			}
			assert(!result.IsEmpty());
		});
	}

	int JSONModule::get_identity_hash() const {
		return mod->GetIdentityHash();
	}
#endif
} // namespace RRR::JS

