#include "test.hxx"
#include "v8-callbacks.h"
#include "v8-exception.h"
#include "v8-primitive.h"
#include "v8-template.h"

#include <v8.h>
#include <libplatform/libplatform.h>
#include <stdio.h>
#include <stdlib.h>

const char script[] = "function(){ return true; }";

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

	Value::Value(v8::Local<v8::Value> &&value) :
		v8::Local<v8::Value>(value)
	{
	}

	Value::Value(v8::Local<v8::String> &&value) :
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

	String::String(CTX &ctx, const char *str) :
		str(v8::String::NewFromUtf8(ctx, str, v8::NewStringType::kNormal).ToLocalChecked()),
		utf8(ctx, this->str)
	{
	}

	String::String(CTX &ctx, v8::Local<v8::String> &&str) :
		str(str),
		utf8(ctx, str)
	{
	}

	String::String(v8::Isolate *isolate, v8::Local<v8::String> &&str) :
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

	E::E(CTX &ctx, std::string &&str) :
			str(ctx, str.c_str())
	{
	}

	const char * E::operator * () {
		return *str;
	}

	Function::Function(v8::Local<v8::Function> &&function) :
		function(function)
	{
	}

	void Function::run(CTX &ctx, int argc = 0, Value argv[] = nullptr) {
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
				throw E(*this, "Failed to intitialize globals\n");
			}
		}
		{
			auto result = console->Set(ctx, String(*this, "error"), v8::Function::New(ctx, Console::error).ToLocalChecked());
			if (!result.FromMaybe(false)) {
				throw E(*this, "Failed to intitialize globals\n");
			}
		}
		{
			auto result = ctx->Global()->Set(ctx, String(*this, "console"), console);
			if (!result.FromMaybe(false)) {
				throw E(*this, "Failed to intitialize globals\n");
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
			throw E(*this, msg.c_str());
		}
		if (value.ToLocalChecked()->IsUndefined()) {
			std::string msg("Function '" + std::string(name) + "' not found");
			throw E(*this, msg.c_str());
		}
		if (!value.ToLocalChecked()->IsFunction()) {
			std::string msg("Name '" + std::string(name) + "' was not a function");
			throw E(*this, msg.c_str());
		}
		return Function(value.ToLocalChecked().As<v8::Function>());
	}

	void CTX::run_function(TryCatch &trycatch, const char *name, int argc = 0, Value argv[] = nullptr) {
		auto &ctx = *this;
		get_function(name).run(ctx, argc, argv);
		if (trycatch.ok(ctx, [ctx, name](const char *msg) mutable {
			throw E(ctx, (std::string("Exception while running function '") + name + "': " + msg + "\n").c_str());
		})) {
			// OK
		}
	}

	Scope::Scope(CTX &ctx) :
		ctx(ctx)
	{
		ctx.ctx->Enter();
	}

	Scope::~Scope() {
		ctx.ctx->Exit();
	}

	Script::Script(CTX &ctx, TryCatch &trycatch, String &&str) :
		script(v8::Script::Compile(ctx, str).ToLocalChecked())
	{
		if (trycatch.ok(ctx, [ctx](const char *msg) mutable {
			throw E(ctx, std::string("Failed to compile script: ") + msg);
		})) {
			// OK
		}
	}

	void Script::run(CTX &ctx, TryCatch &trycatch) {
		auto result = script->Run(ctx).FromMaybe((v8::Local<v8::Value>) String(ctx, ""));
		if (trycatch.ok(ctx, [ctx](const char *msg) mutable {
			throw E(ctx, std::string("Exception while running script: ") + std::string(msg));
		})) {
			// OK
		}
		// Ignore result
	}
} // namespace RRR::JS

int main(int argc, const char **argv) {
	using namespace RRR::JS;

	int ret = EXIT_SUCCESS;

	ENV env(*argv);

	size_t size = 0;
	size_t size_total = 0;
	char tmp[4096];
	char *in = NULL;

	while ((size = fread (tmp, 1, 4096, stdin)) > 0) {
		in = reinterpret_cast<char *>(realloc(in, size_total + size + 1));
		if (in == NULL) {
			fprintf(stderr, "Failed to allocate memory in %s\n", __func__);
			ret = EXIT_FAILURE;
			goto out;
		}
		memcpy(in + size_total, tmp, size);
		size_total += size;
	}

	if (in == NULL) {
		fprintf(stderr, "No input read\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	in[size_total] = '\0';

	try {
		auto isolate = Isolate(env);
		auto ctx = CTX(env);
		auto scope = Scope(ctx);
		auto trycatch = TryCatch(ctx);
		auto script = Script(ctx, trycatch, String(ctx, in));
	
		Value arg = String(ctx, "arg");

		script.run(ctx, trycatch);
		ctx.run_function(trycatch, "process", 1, &arg);
	}
	catch (E &e) {
		fprintf(stderr, "%s\n", *e);
		ret = EXIT_FAILURE;
	}

	out:
	if (in != NULL) {
		free(in);
	}
	return ret;
}
