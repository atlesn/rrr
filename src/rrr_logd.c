/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "lib/log.h"
#include "lib/allocator.h"

#include "lib/rrr_types.h"
#include "main.h"
#include "../build_timestamp.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/util/posix.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_logd");

static volatile int main_running = 1;
static volatile int sigusr2 = 0;

int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,   's',    "socket",                "[-s|--socket[=]SOCKET]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'f',    "file-descriptor",       "[-f|--file-descriptor[=]FILE DESCRIPTOR]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'l',    "loglevel-translation",  "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'h',    "help",                  "[-h|--help]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'v',    "version",               "[-v|--version]"},
        {0,                           '\0',    NULL,                   NULL}
};

struct rrr_logd_data {
	const char *receive_socket;
	int receive_fd;
};

static int rrr_logd_parse_config (struct rrr_logd_data *data, struct cmd_data *cmd) {
	const char *receive_socket;
	const char *receive_fd_str;

	receive_socket = cmd_get_value(cmd, "socket", 0);
	if (cmd_get_value(cmd, "socket", 1) != NULL) {
		RRR_MSG_0("Argument 'socket' may not be specified multiple times\n");
		return 1;
	}

	receive_fd_str = cmd_get_value(cmd, "file-descriptor", 0);
	if (cmd_get_value(cmd, "file-descriptor", 1) != NULL) {
		RRR_MSG_0("Argument 'file-descriptor' may not be specified multiple times\n");
		return 1;
	}

	if (receive_socket == NULL && receive_fd_str == NULL) {
		RRR_MSG_0("Neither 'file-descriptor' nor 'socket' argument was specified\n");
		return 1;
	}

	if (receive_socket != NULL) {
		data->receive_socket = receive_socket;
	}

	if (receive_fd_str != NULL) {
		long fd_tmp;
		if (cmd_convert_integer_10(receive_fd_str, &fd_tmp) != 0) {
			RRR_MSG_0("Failed to convert 'file-descriptor' argument to integer\n");
			return 1;
		}
#if LONG_MAX > INT_MAX
		if (fd_tmp > INT_MAX) {
			RRR_MSG_0("Value for 'file-descriptor' too high\n");
			return 1;
		}
#endif
		if (fd_tmp < 2) {
			RRR_MSG_0("Value for 'file-descriptor' must be greater than 2\n");
			return 1;
		}

		data->receive_fd = rrr_int_from_slength_bug_const(fd_tmp);
	}

	return 0;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler = NULL;
	struct cmd_data cmd = {0};
	struct rrr_logd_data data = {0};

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
	rrr_signal_default_signal_actions_register();

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 3)) {
		goto out_cleanup_signal;
	}

	if (rrr_logd_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	while (main_running) {
		rrr_posix_usleep(100 * 1000 /* 100 ms */);
	}

	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_log_cleanup();

	out_cleanup_allocator:
		rrr_allocator_cleanup();

	out_final:
		return ret;
}
