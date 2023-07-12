
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

#ifdef RRR_WITH_NODE
#	include "lib/testjs.hxx"
#endif

#include <stdio.h>
#include <unistd.h>

extern "C" {
#	include "test.h"
#	include "../lib/log.h"
#	include "../lib/allocator.h"
#	include "../lib/rrr_strerror.h"
#	include "../lib/cmdlineparser/cmdline.h"
#	include "../main.h"

	RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("test");
}


static const struct cmd_arg_rule cmd_rules[] = {
        {0,                           'W',    "no-watchdog-timers",    "[-W|--no-watchdog-timers]"},
        {0,                           'T',    "no-thread-restart",     "[-T|--no-thread-restart]"},
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'r',    "run-directory",         "[-r|--run-directory[=]RUN DIRECTORY]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel DEBUGLEVEL]"},
        {0,                           '\0',    NULL,                   ""}
};

int rrr_cxx_test_library_functions (void) {
	int ret = 0;
	int ret_tmp = 0;

#ifdef RRR_WITH_NODE
	TEST_BEGIN("js library functions") {
		ret_tmp = rrr_test_js();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

	return ret;
}

int main (int argc, const char **argv, const char **env) {
	int ret = 0;

	struct cmd_data cmd;
	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}
	rrr_strerror_init();

	TEST_MSG("Change to directory %s\n", RRR_TEST_PATH);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = 1;
		// Some data might have been stored also upon error
		goto out_cleanup_cmd;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 1) != 0) {
		goto out_cleanup_cmd;
	}

	if (chdir(RRR_TEST_PATH) != 0) {
		TEST_MSG("Error while changing directory\n");
		ret = 1;
		goto out_cleanup_cmd;
	}

	TEST_BEGIN("library fujnctions") {
		ret = rrr_cxx_test_library_functions();
	} TEST_RESULT(ret == 0);

	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
