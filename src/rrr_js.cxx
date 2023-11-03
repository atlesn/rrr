extern "C" {
	#include "lib/allocator.h"
	#include "lib/log.h"
	#include "lib/rrr_strerror.h"
	RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_js");
};

#include <filesystem>
#include <functional>

#include "lib/js/Js.hxx"

using namespace RRR::JS;

int main(int argc, const char **argv) {
	int ret = EXIT_SUCCESS;

	ENV env(*argv);

	size_t size = 0;
	size_t size_total = 0;
	char tmp[4096];
	char *in = NULL;
	int is_module = 0;

	switch (argc) {
		case 2:
			if (strcmp(argv[1], "module") == 0) {
				is_module = 1;
				break;
			}
			else if (strcmp(argv[1], "script") == 0) {
				break;
			}
			// Fallthrough
		default:
			ret = EXIT_FAILURE;
			goto usage;
	};

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_strerror_init();

	while ((size = fread (tmp, 1, 4096, stdin)) > 0) {
		{
			char *in_tmp = reinterpret_cast<char *>(rrr_reallocate(in, size_total + size + 1));
			if (in_tmp == NULL) {
				fprintf(stderr, "Failed to allocate memory in %s\n", __func__);
				ret = EXIT_FAILURE;
				goto out;
			}
			in = in_tmp;
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
		auto cwd = std::filesystem::current_path().string();
		printf("CWD: %s\n", cwd.c_str());
		auto isolate = Isolate(env);
		auto ctx = CTX(env, "-");
		auto scope = Scope(ctx);
		auto program = (is_module
			? std::function<std::shared_ptr<Program>()>([&](){
				return std::dynamic_pointer_cast<Program>(isolate.make_module<Module>(ctx, cwd, "-", std::string(in)));
			})
			: std::function<std::shared_ptr<Program>()>([&](){
				auto script = Script::make_shared(cwd, "-", std::string(in));
				script->compile(ctx);
				return std::dynamic_pointer_cast<Program>(script);
			}))();
		if (program->is_compiled()) {
			program->run(ctx);
		}
		if (ctx.trycatch_ok([](std::string &&msg){
			throw E(std::string(msg));
		})) {
			// OK
		}

	}
	catch (E &e) {
		fprintf(stderr, "%s\n", *e);
		ret = EXIT_FAILURE;
	}

	out:
		rrr_strerror_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	goto out_final;
	usage:
		printf("Usage: %s [module|script]\n", argv[0]);
	out_final:
		RRR_FREE_IF_NOT_NULL(in);
		return ret;
}
