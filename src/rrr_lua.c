/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>

#include "main.h"
#include "lib/version.h"
#include "lib/allocator.h"
#include "lib/log.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/random.h"
#include "lib/common.h"
#include "lib/util/rrr_endian.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/lua/lua.h"

struct rrr_lua_data {
	uint8_t dummy;
};

static int main_running = 1;
static int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_lua");

int main(int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler;
	struct cmd_data cmd;
	struct rrr_lua_data lua_data = {0};
	struct rrr_lua *lua;

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

	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 0) != 0) {
		goto out_cleanup_signal;
	}

	RRR_DBG_1("Program started\n");

	rrr_signal_default_signal_actions_register();
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if (rrr_lua_new(&lua) != 0) {
		RRR_MSG_0("Failed to initialize Lua\n");
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	while (main_running) {
		goto out_cleanup_lua;
	}

	if (!main_running) {
		RRR_DBG_1("Exiting after received signal\n");
	}

	out_cleanup_lua:
		rrr_lua_destroy(lua);
	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
		cmd_destroy(&cmd);
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
