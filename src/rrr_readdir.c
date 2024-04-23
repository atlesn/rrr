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

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "lib/rrr_umask.h"
#include "lib/rrr_strerror.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/log.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/allocator.h"
#include "lib/util/rrr_readdir.h"
#include "main.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_readdir");

#define RRR_GLOBAL_UMASK		S_IROTH | S_IWOTH | S_IXOTH

#ifndef RRR_BUILD_TIMESTAMP
#define RRR_BUILD_TIMESTAMP 1
#endif

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG,         '\0',   "directory",             "{DIRECTORY}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'p',    "prefix",                "[-p|--prefix[=]PREFIX]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
		{0,                            'h',    "help",                  "[-h|--help]"},
		{0,                            'v',    "version",               "[-v|--version]"},
		{0,                            '\0',    NULL,                   NULL}
};

static volatile int main_running = 1;
static volatile int sigusr2 = 0;

int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

/*
Events or persistent run not used
static int __rrr_readdir_periodic (void) {
	rrr_allocator_maintenance_nostats();
}
*/

static int __rrr_readdir_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	(void)(entry);
	(void)(type);
	(void)(private_data);

	printf("File '%s'=>'%s'\n", orig_path, resolved_path);

	if (sigusr2) {
		RRR_MSG_0("Received SIGUSR2, but this is not implemented in RRR readdir\n");
		sigusr2 = 0;
	}

	return main_running ? 0 : RRR_READ_EOF;
}

int main (int argc, const char *argv[], const char *env[]) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		goto out_cleanup_allocator;
	}
	rrr_strerror_init();

	struct rrr_signal_handler *signal_handler = NULL;
	struct cmd_data cmd;

	cmd_init(&cmd, cmd_rules, argc, argv);

	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);

	rrr_signal_default_signal_actions_register();

	// Everything which might print debug stuff must be called after this
	// as the global debuglevel is 0 up to now
	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_signal;
	}

	const char *directory = cmd_get_value(&cmd, "directory", 0);
	const char *prefix = cmd_get_value(&cmd, "prefix", 0);

	rrr_umask_onetime_set_global(RRR_GLOBAL_UMASK);

	RRR_DBG_1("RRR debuglevel is: %u\n", RRR_DEBUGLEVEL);
	RRR_DBG_1("Using directory '%s' and prefix '%s'\n", directory, prefix != NULL ? prefix : "");

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if (rrr_readdir_foreach_prefix (
			directory,
			prefix,
			__rrr_readdir_callback,
			NULL
	) != 0) {
		ret = (ret == RRR_READ_EOF ? EXIT_SUCCESS : EXIT_FAILURE);
	}


	rrr_config_set_debuglevel_on_exit();

	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_exit_cleanup_methods_run_and_free();
		if (ret == 0) {
			RRR_MSG_1("Exiting program without errors\n");
		}
		else {
			RRR_MSG_ERR("Exiting program following one or more errors\n");
		}
		cmd_destroy(&cmd);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
