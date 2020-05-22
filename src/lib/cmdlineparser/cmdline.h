/*

Command Line Parser

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef CMD_CMDLINE_H
#define CMD_CMDLINE_H

#include <stdint.h>

#include "../../../config.h"
#include "../linked_list.h"

typedef unsigned long int cmd_arg_count;
typedef unsigned long int cmd_arg_size;
typedef unsigned long int cmd_conf;

#define CMD_CONFIG_DEFAULTS			0
#define CMD_CONFIG_COMMAND			(1<<0)

#define CMD_ARG_FLAG_NO_ARGUMENT	(0)
#define CMD_ARG_FLAG_HAS_ARGUMENT	(1<<0)
#define CMD_ARG_FLAG_SPLIT_COMMA	(1<<1)
#define CMD_ARG_FLAG_NO_FLAG		(1<<2)
#define CMD_ARG_FLAG_NO_FLAG_MULTI	(1<<4)

struct cmd_arg_value {
	RRR_LL_NODE(struct cmd_arg_value);
	char *value;
};

struct cmd_arg_pair {
	RRR_LL_NODE(struct cmd_arg_pair);
	RRR_LL_HEAD(struct cmd_arg_value);
	int was_used;
	const struct cmd_arg_rule *rule;
};

struct cmd_data {
	RRR_LL_HEAD(struct cmd_arg_pair);
	const char *program;
	const char *command;

	const struct cmd_arg_rule *rules;

	int argc;
	const char **argv;
};

struct cmd_argv_copy {
	int argc;
	char **argv;
};

struct cmd_arg_rule {
	int flags;
	const char shortname;
	const char *longname;
	const char *legend;
};

void cmd_destroy (
		struct cmd_data *data
);
void cmd_init (
		struct cmd_data *data,
		const struct cmd_arg_rule *rules,
		int argc,
		const char *argv[]
);
void cmd_get_argv_copy (
		struct cmd_argv_copy **target,
		struct cmd_data *data
);
void cmd_destroy_argv_copy (
		struct cmd_argv_copy *target
);
int cmd_parse (
		struct cmd_data *data,
		cmd_conf config
);
int cmd_match (
		struct cmd_data *data,
		const char *test
);
int cmd_convert_hex_byte (
		const char *value,
		char *result
);
int cmd_convert_hex_64 (
		const char *value,
		uint64_t *result
);
int cmd_convert_uint64_10 (
		const char *value,
		uint64_t *result
);
int cmd_convert_integer_10 (
		const char *value,
		int *result
);
int cmd_convert_float (
		const char *value,
		float *result
);
void cmd_print_usage (
		struct cmd_data *data
);
int cmd_exists (
		struct cmd_data *data,
		const char *key,
		cmd_arg_count index
);
int cmd_iterate_subvalues (
		struct cmd_data *data,
		const char *key,
		cmd_arg_count req_index,
		int (*callback)(const char *value, void *arg),
		void *callback_arg
);
const char *cmd_get_value (
		struct cmd_data *data,
		const char *key,
		cmd_arg_count index
);
const char *cmd_get_subvalue (
		struct cmd_data *data,
		const char *key,
		cmd_arg_count index,
		cmd_arg_count subindex
);
int cmdline_check_yesno	(
		const char *string,
		int *result
);
int cmd_check_all_args_used (
		struct cmd_data *data
);

#endif
