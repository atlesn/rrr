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
} // namespace RRR::JS

int main(int argc, const char **argv) {
	RRR::JS::ENV js(*argv);
	{
	//	auto script_str = v8::String::NewFromUtf8(scope, script, v8::String::NewStringType::kNormalString, sizeof(script) - 1);
	}

	return 0;
}
