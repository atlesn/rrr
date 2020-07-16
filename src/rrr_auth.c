/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>

#include "main.h"
#include "../build_timestamp.h"
#include "lib/rrr_config.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/rrr_strerror.h"
#include "lib/version.h"
#include "lib/socket/rrr_socket.h"
#include "lib/linked_list.h"
#include "lib/log.h"
#include "lib/gnu.h"
#include "lib/parse.h"
#include "lib/passwd.h"
#include "lib/macro_utils.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_auth");

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"file",					"{PASSWORD_FILE}"},
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"username",				"{USERNAME}"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	's',	"stdin",				"[-s|--stdin]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'p',	"permission",			"[-p|--permission[=]PERMISSION]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'l',	"loglevel-translation",	"[-l|--loglevel-translation]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'h',	"help",					"[-h|--help]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_auth_data {
	int do_stdin;
	char *username;
	char *filename;
	char *permission;
};

static void __rrr_passwd_data_init (struct rrr_auth_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_passwd_destroy_data (struct rrr_auth_data *data) {
	RRR_FREE_IF_NOT_NULL(data->username);
	RRR_FREE_IF_NOT_NULL(data->filename);
	RRR_FREE_IF_NOT_NULL(data->permission);
}

static int __rrr_auth_parse_config (struct rrr_auth_data *data, struct cmd_data *cmd) {
	int ret = 0;

	const char *file = cmd_get_value(cmd, "file", 0);
	if (file != NULL && *file != '\0') {
		data->filename = strdup(file);
		if (data->filename == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_auth_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	const char *username = cmd_get_value(cmd, "username", 0);
	if (username != NULL && *username != '\0') {
		data->username = strdup(username);
		if (data->username == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_auth_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	if (data->filename == NULL || data->username == NULL || *(data->filename) == '\0' || *(data->username) == '\0') {
		RRR_MSG_0("Password filename and/or username not set\n");
		ret = 1;
		goto out;
	}

	const char *permission = cmd_get_value(cmd, "permission", 0);
	if (permission != NULL && *permission != '\0') {
		data->permission = strdup(permission);
		if (data->permission == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_auth_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	if (cmd_exists(cmd, "stdin", 0)) {
		data->do_stdin = 1;
	}
	else {
		data->do_stdin = 0;
	}

	out:
	return ret;
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	// By default return failure
	int ret = EXIT_FAILURE;

	if (rrr_log_init() != 0) {
		goto out_final;
	}
	rrr_strerror_init();

	char *input_password = NULL;

	struct cmd_data cmd;
	struct rrr_auth_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_passwd_data_init(&data);

	if ((ret = main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	// Don't require arguments here, separate check in parse_config
	if (rrr_print_help_and_version(&cmd, 0) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if ((ret = __rrr_auth_parse_config(&data, &cmd)) != 0) {
		cmd_print_usage(&cmd);
		ret = EXIT_FAILURE;
		goto out;
	}

	if (data.do_stdin) {
		if (rrr_passwd_read_password_from_stdin (&input_password) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	else {
		if (rrr_passwd_read_password_from_terminal(&input_password, 0) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (data.permission != NULL && *(data.permission) == '\0') {
		// Make sure empty permission is not \0 but NULL
		RRR_FREE_IF_NOT_NULL(data.permission);
	}

	if (rrr_passwd_authenticate(data.filename, data.username, input_password, data.permission) != 0) {
		RRR_MSG_0("Authentication failure\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	else {
		RRR_DBG_1("Authentication succeded\n");
		ret = EXIT_SUCCESS;
	}

	goto out;

	out:
		rrr_config_set_debuglevel_on_exit();
		RRR_FREE_IF_NOT_NULL(input_password);
		__rrr_passwd_destroy_data(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_final:
		return ret;
}
