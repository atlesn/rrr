#include "test.hxx"
#include <v8.h>
#include <libplatform/libplatform.h>
//#include <v8-platform.h>

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

	String::String(ENV &env, const char *str) :
		str(v8::String::NewFromUtf8(env, str, v8::NewStringType::kNormal).ToLocalChecked())
	{
	}

	String::operator v8::Local<v8::String> () {
		return str;
	}

	Value::Value(v8::Local<v8::Value> value) :
		v8::Local<v8::Value>()
	{
	}

	UTF8::UTF8(ENV &env, Value &value) :
		utf8(env, value) {
	}

	UTF8::UTF8(ENV &env, Value &&value) :
		utf8(env, value) {
	}

	const char * UTF8::operator * () {
		return *utf8;
	}

	Script::Script(CTX &ctx, String &str) :
		ctx(ctx),
		script(v8::Script::Compile(ctx, str).ToLocalChecked())
	{
	}

	Script::Script(CTX &ctx, String &&str) :
		ctx(ctx),
		script(v8::Script::Compile(ctx, str).ToLocalChecked())
	{
	}

	Value Script::run() {
		return script->Run(ctx).ToLocalChecked();
	}
} // namespace RRR::JS

int main(int argc, const char **argv) {
	using namespace RRR::JS;

	ENV env(*argv);

	{
		auto scope = SCOPE(env);
		auto ctx = CTX(env);
		auto script = Script(ctx, String(env, "'Hello';"));
		auto result = UTF8(env, script.run());

		printf("Result: %s\n", *result);
	}

	return 0;
}
