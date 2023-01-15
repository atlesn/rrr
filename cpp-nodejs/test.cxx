#include "test.hxx"
#include "v8-callbacks.h"
#include "v8-exception.h"
#include "v8-primitive.h"
#include "v8-template.h"

#include <v8.h>
#include <libplatform/libplatform.h>
#include <stdio.h>

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

	SCOPE::SCOPE(ENV &env) :
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

	UTF8::UTF8(ENV &env, Value &value) :
		utf8(env, value)
	{
	}

	UTF8::UTF8(ENV &env, Value &&value) :
		utf8(env, value)
	{
	}

	UTF8::UTF8(ENV &env, v8::Local<v8::String> &str) :
		utf8(env, str)
	{
	}

	UTF8::UTF8(v8::Isolate *isolate, v8::Local<v8::String> &str) :
		utf8(isolate, str)
	{
	}

	const char * UTF8::operator * () {
		return *utf8;
	}

	String::String(ENV &env, const char *str) :
		str(v8::String::NewFromUtf8(env, str, v8::NewStringType::kNormal).ToLocalChecked()),
		utf8(env, this->str)
	{
	}

	String::String(ENV &env, v8::Local<v8::String> &&str) :
		str(str),
		utf8(env, str)
	{
	}

	String::String(v8::Isolate *isolate, v8::Local<v8::String> &&str) :
		str(str),
		utf8(isolate, str)
	{
	}

	String::operator v8::Local<v8::String> () {
		return str;
	}

	String::operator v8::Local<v8::Value> () {
		return str;
	}

	const char * String::operator * () {
		static const char *empty = "";
		return str.IsEmpty() ? empty : *utf8;
	}

	E::E(ENV &env, const char *str) :
			str(env, str)
	{
	}

	const char * E::operator * () {
		return *str;
	}

	namespace Console {
		void flog(FILE *target, const v8::FunctionCallbackInfo<v8::Value> &args) {
			auto isolate = args.GetIsolate();
			auto ctx = args.GetIsolate()->GetCurrentContext();
			for (int i = 0; i < args.Length(); i++) {
				auto value = String(isolate, args[i]->ToString(ctx).ToLocalChecked());
				fprintf(target, "%s\n", *value);
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
		ctx(v8::Context::New(env, nullptr)),
		ctx_scope(ctx)
	{
		v8::Local<v8::Object> console = (v8::ObjectTemplate::New(env))->NewInstance(ctx).ToLocalChecked();

		{
			auto result = console->Set(ctx, String(env, "log"), v8::Function::New(ctx, Console::log).ToLocalChecked());
			if (!result.FromMaybe(false)) {
				throw E(env, "Failed to intitialize globals\n");
			}
		}
		{
			auto result = console->Set(ctx, String(env, "error"), v8::Function::New(ctx, Console::error).ToLocalChecked());
			if (!result.FromMaybe(false)) {
				throw E(env, "Failed to intitialize globals\n");
			}
		}
		{
			auto result = ctx->Global()->Set(ctx, String(env, "console"), console);
			if (!result.FromMaybe(false)) {
				throw E(env, "Failed to intitialize globals\n");
			}
		}
	}

	CTX::operator v8::Local<v8::Context> () {
		return ctx;
	}

	Script::Script(ENV &env, CTX &ctx, String &&str) :
		script(v8::Script::Compile(ctx, str).ToLocalChecked())
	{
	}

	Value Script::run(ENV &env, CTX &ctx) {
		return script->Run(ctx).FromMaybe((v8::Local<v8::Value>) String(env, ""));
	}
} // namespace RRR::JS

int main(int argc, const char **argv) {
	using namespace RRR::JS;

	ENV env(*argv);

	try {
		auto scope = SCOPE(env);
		auto ctx = CTX(env);
		auto trycatch = TryCatch(env);
		auto script = Script(env, ctx, String(env, "'Hello, World ' + (1+2);'abcd';console.log('gggg');"));
		if (trycatch.ok(env, [](const char *msg) -> void {
			printf("Failed to compile script: %s\n", msg);
		})) {
			auto result = script.run(env, ctx);
			if (trycatch.ok(env, [](const char *msg) -> void {
				printf("Failed run script: %s\n", msg);
			})) {
				auto result_utf8 = UTF8(env, result);
				// printf("Result: %s\n", *result_utf8);
			}
		}
	}
	catch (E &e) {
		printf("Initialization failed: %s\n", *e);
	}

	return 0;
}
