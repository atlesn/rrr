extern "C" {
	#include "lib/allocator.h"
	#include "lib/log.h"
	#include "lib/rrr_strerror.h"
	RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_js");
};

#include "lib/js/Js.hxx"

int main(int argc, const char **argv) {
	using namespace RRR::JS;

	int ret = EXIT_SUCCESS;

	ENV env(*argv);

	size_t size = 0;
	size_t size_total = 0;
	char tmp[4096];
	char *in = NULL;

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
		in = reinterpret_cast<char *>(rrr_reallocate(in, in == NULL ? 0 : size_total + 1, size_total + size + 1));
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
		auto ctx = CTX(env, "-");
		auto scope = Scope(ctx);
		auto script = Script(ctx);
		auto script_source = std::string(in);
	
		Value arg = String(ctx, "arg");

		script.compile(ctx, script_source);
		if (script.is_compiled()) {
			script.run(ctx);
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
	out_final:
		RRR_FREE_IF_NOT_NULL(in);
		return ret;
}
