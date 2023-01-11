#include <libplatform/libplatform.h>
#include <v8.h>
#include <v8-platform.h>

const char script[] = "function(){ return true; }";

class RRRJS {
	private:
	v8::Isolate::CreateParams create_params;
	v8::Isolate *isolate = v8::Isolate::New(create_params);

	public:
	RRRJS(const char *program_name) {
		v8::V8::InitializeICUDefaultLocation(program_name);
		v8::V8::InitializeExternalStartupData(program_name);
		std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
		v8::V8::InitializePlatform(platform.get());
		v8::V8::Initialize();
		this->create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
		this->isolate = v8::Isolate::New(this->create_params);
	}
	~RRRJS() {
		this->isolate->Dispose();
		delete this->create_params.array_buffer_allocator;
		v8::V8::Dispose();
	}
};

int main(int argc, const char **argv) {
	RRRJS js(*argv);
	{
	//	auto script_str = v8::String::NewFromUtf8(scope, script, v8::String::NewStringType::kNormalString, sizeof(script) - 1);
	}

	return 0;
}
