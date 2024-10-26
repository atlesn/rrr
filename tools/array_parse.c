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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "../build_timestamp.h"
#include "../src/main.h"
#include "../src/lib/version.h"
#include "../src/lib/allocator.h"
#include "../src/lib/rrr_strerror.h"
#include "../src/lib/array_tree.h"
#include "../src/lib/parse.h"
#include "../src/lib/cmdlineparser/cmdline.h"
#include "../src/lib/util/readfile.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("array_parse");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG_MULTI,   '\0',   "filename",             "{FILENAME}..."},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_array_parse_array_callback_data {
	const char *filename;
	int round;
};

static int array_parse_array_callback(struct rrr_array *array, void *arg) {
	struct rrr_array_parse_array_callback_data *callback_data = arg;

	if (RRR_DEBUGLEVEL_2) {
		RRR_DBG_2("%s:%i dumping array...\n",
			callback_data->filename, callback_data->round);
		rrr_array_dump(array);
	}

	return 0;
}

static int array_parse_process_file(const char *filename) {
	int ret = 0;

	char *buf = NULL;
	rrr_biglength size;
	struct rrr_array_tree *array_tree;
	struct rrr_parse_pos parse_pos = {0};
	rrr_length parsed_bytes;
	int ret_tmp;

	if ((ret = rrr_readfile_read(&buf, &size, filename, 0, 0)) != 0) {
		goto out;
	}

	rrr_parse_pos_init(&parse_pos, buf, rrr_length_from_biglength_bug_const(size));

	if ((ret = rrr_array_tree_interpret(&array_tree, &parse_pos, "tree")) != 0) {
		RRR_MSG_0("Failed to interpret array definition in file '%s'. Hint: The definition must be at the beginning of the file and ending with ;.\n", filename);
		goto out;
	}

	if (RRR_DEBUGLEVEL_1) {
		RRR_DBG_1("%s dumping array tree...\n", filename);
		rrr_array_tree_dump(array_tree);
	}

	rrr_parse_ignore_spaces_and_increment_line(&parse_pos);

	if (RRR_PARSE_CHECK_EOF(&parse_pos)) {
		RRR_MSG_0("No data after array definition in file '%s'\n", filename);
		ret = 1;
		goto out_destroy_array_tree;
	}

	struct rrr_array_parse_array_callback_data callback_data = {
		.filename = filename
	};

	do {
		callback_data.round++;

		if ((ret_tmp = rrr_array_tree_import_from_buffer(
				&parsed_bytes,
				buf + parse_pos.pos,
				size - parse_pos.pos,
				array_tree,
				array_parse_array_callback,
				&callback_data
		)) != 0) {
			break;
		}

		RRR_DBG_1("%s:%i parsed %" PRIrrrl " bytes...\n",
			filename,
			callback_data.round,
			parsed_bytes
		);

		rrr_length_add_bug(&parse_pos.pos, parsed_bytes);
	} while (!RRR_PARSE_CHECK_EOF(&parse_pos));

	if (!RRR_PARSE_CHECK_EOF(&parse_pos) || ret_tmp != 0) {
		RRR_DBG_1("%s:%i Round not complete, %" PRIrrrl " bytes remaining data after parsing, return was %i (%s)\n",
			filename,
			callback_data.round,
			parse_pos.size - parse_pos.pos,
			ret_tmp,
			ret_tmp == RRR_ARRAY_TREE_SOFT_ERROR
				? "soft error"
				: ret_tmp == RRR_ARRAY_TREE_PARSE_INCOMPLETE
					? "incomplete"
					:"hard error");
	}

	out_destroy_array_tree:
		rrr_array_tree_destroy(array_tree);
	out:
		RRR_FREE_IF_NOT_NULL(buf);
		return ret;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;

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

	for (int i = 0; 1; i++) {
		const char *filename = cmd_get_value(&cmd, "filename", i);
		if (filename == NULL)
			break;
		if (array_parse_process_file(filename) != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}
	}

	out_cleanup_cmd:
		cmd_destroy(&cmd);
	//out_cleanup_log:
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
