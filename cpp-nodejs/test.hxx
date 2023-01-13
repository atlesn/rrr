#pragma once

#include <memory>
#include <v8.h>

namespace RRR::JS {
	class ENV {
		private:
		std::unique_ptr<v8::Platform> platform;
		v8::Isolate::CreateParams isolate_create_params;
		v8::Isolate *isolate;

		public:
		ENV(const char *program_name);
		~ENV();
	};
}
