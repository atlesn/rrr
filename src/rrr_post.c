/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>

#include "global.h"
#include "main.h"
#include "../build_timestamp.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_HAS_ARGUMENT,	's',	"socket",				"{-s|--socket[=]RRR SOCKET}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'i',	"input",				"[-i|--input[=]array|text]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'a',	"array_definition",		"[-a|--array_definition[=]ARRAY DEFINITION]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	't',	"topic",				"[-t|--topic[=]MQTT TOPIC]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;
	cmd_init(&cmd, cmd_rules, argc, argv);

	if ((ret = main_parse_cmd_arguments(&cmd)) != 0) {
		goto out;
	}

	if (rrr_print_help_and_version(&cmd) != 0) {
		goto out;
	}

	out:
	rrr_set_debuglevel_on_exit();
	cmd_destroy(&cmd);
	return ret;
}
