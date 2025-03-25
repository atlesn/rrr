extern "C" {
	#include "lib/allocator.h"
	#include "lib/log.h"
	#include "lib/rrr_strerror.h"
	#include "lib/rrr_config.h"
	#include "lib/cmdlineparser/cmdline.h"
	#include "lib/socket/rrr_socket.h"
	#include "main.h"
	RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_js");
};

#include <filesystem>
#include <functional>

#include "lib/js/Js.hxx"
#include "lib/js/OS.hxx"

using namespace RRR::JS;

static const struct cmd_arg_rule cmd_rules[] = {
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'L',    "log-socket",            "[-L|--log-socket[=]LOG SOCKET]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'l',    "loglevel-translation",  "[-l|--loglevel-translation]"},
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'h',    "help",                  "[-h|--help]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'v',    "version",               "[-v|--version]"},
	{CMD_ARG_FLAG_NO_FLAG,        '\0',   "type",                  "{script|module}"},
	{0,                           '\0',    NULL,                   NULL}
};

int main(int argc, const char **argv, const char **env) {
	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;

	ENV js_env(*argv);

	size_t size = 0;
	size_t size_total = 0;
	char tmp[4096];
	char *in = NULL;
	const char *type;
	int is_module = 0;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}

	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_strerror_init();

	cmd_init(&cmd, cmd_rules, argc, argv);

	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out_cleanup_cmd;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_cmd;
	}

	type = cmd_get_value(&cmd, "type", 0);
	if (strcmp(type, "script") == 0) {
		// OK
	}
	else if (strcmp(type, "module") == 0) {
		is_module = 1;
	}
	else {
		RRR_MSG_0("Unknown script type '%s'\n", type);
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	while ((size = fread (tmp, 1, 4096, stdin)) > 0) {
		{
			char *in_tmp = reinterpret_cast<char *>(rrr_reallocate(in, size_total + size + 1));
			if (in_tmp == NULL) {
				RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
				ret = EXIT_FAILURE;
				goto out_cleanup_cmd;
			}
			in = in_tmp;
		}
		memcpy(in + size_total, tmp, size);
		size_total += size;
	}

	if (in == NULL) {
		RRR_MSG_0("No input read\n");
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	in[size_total] = '\0';

	try {
		auto cwd = std::filesystem::current_path().string();
		RRR_DBG_1("CWD: %s\n", cwd.c_str());
		auto isolate = Isolate(js_env);
		auto ctx = CTX(js_env, "-");
		auto scope = Scope(ctx);
		auto persistent_storage = PersistentStorage(ctx);
		auto os_factory = RRR::JS::OSFactory(ctx, persistent_storage);

		os_factory.register_as_global(ctx);

		auto program = (is_module
			? std::function<std::shared_ptr<Program>()>([&](){
				return std::dynamic_pointer_cast<Program>(isolate.load_module(ctx, cwd, "-", std::string(in)));
			})
			: std::function<std::shared_ptr<Program>()>([&](){
				auto script = Script::make_shared(cwd, "-", std::string(in));
				script->compile(ctx);
				return std::dynamic_pointer_cast<Program>(script);
			}))();

		if (program->is_compiled() && !program->is_run()) {
			program->run(ctx);
		}

		if (ctx.trycatch_ok([](std::string &&msg){
			throw E(std::string(msg));
		})) {
			// OK
		}

	}
	catch (E &e) {
		RRR_MSG_0("%s\n", *e);
		ret = EXIT_FAILURE;
	}

	out_cleanup_cmd:
		rrr_socket_close_all_except(rrr_log_socket_fd_get());
		cmd_destroy(&cmd);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		RRR_FREE_IF_NOT_NULL(in);
		return ret;
}
