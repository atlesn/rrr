#include "test.hxx"
#include "v8-callbacks.h"
#include "v8-exception.h"
#include "v8-primitive.h"
#include <v8.h>
#include <libplatform/libplatform.h>
//#include <v8-platform.h>

const char script[] = "function(){ return true; }";

namespace RRR::JS {
	void ENV::fatal_error(const char *where, const char *what) {
		printf("Fatal error from V8: %s %s\n", where, what);
	}

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

	SCOPE::SCOPE(ENV &env) :
		isolate(env.isolate),
		isolate_scope(isolate),
		handle_scope(isolate)
	{
	}

	CTX::CTX(ENV &env) :
		ctx(v8::Context::New(env)),
		ctx_scope(ctx)
	{
	}

	CTX::operator v8::Local<v8::Context> () {
		return ctx;
	}

	Value::Value(v8::Local<v8::Value> &&value) :
		v8::Local<v8::Value>(value)
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

	String::operator v8::Local<v8::String> () {
		return str;
	}

	const char * String::operator * () {
		static const char *empty = "";
		return str.IsEmpty() ? empty : *utf8;
	}

	Script::Script(CTX &ctx, String &&str) :
		script(v8::Script::Compile(ctx, str).ToLocalChecked())
	{
	}

	Value Script::run(CTX &ctx) {
		return script->Run(ctx).ToLocalChecked();
	}
} // namespace RRR::JS

int main(int argc, const char **argv) {
	using namespace RRR::JS;

	ENV env(*argv);

	{
		auto scope = SCOPE(env);
		auto ctx = CTX(env);
		auto trycatch = TryCatch(env);
		auto script = Script(ctx, String(env, "'Hello, World ' + (1+2)"));
		if (trycatch.ok(env, [](const char *msg) -> void {
			printf("Failed to compile script: %s\n", msg);
		})) {
			auto result = UTF8(env, script.run(ctx));
			printf("Result: %s\n", *result);
		}
	}

	return 0;
}
