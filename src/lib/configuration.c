/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

#include "parse.h"
#include "log.h"
#include "configuration.h"
#include "rrr_strerror.h"
#include "array_tree.h"
#include "allocator.h"
#include "socket/rrr_socket.h"
#include "discern_stack.h"

int rrr_config_new (struct rrr_config **result) {
	struct rrr_config *config = NULL;

	*result = NULL;

	if ((config = rrr_allocate_zero(sizeof(*config))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_config_new\n");
		return 1;
	}

	*result = config;

	return 0;
}

static int __rrr_config_parse_setting (
		struct rrr_parse_pos *pos,
		int *did_parse,
		void *block,
		int (*new_setting_callback)(RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	char *name = NULL;
	char *value = NULL;

	*did_parse = 0;

	rrr_parse_ignore_spaces_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos)) {
		goto out;
	}

	while (pos->data[pos->pos] == '#') {
		rrr_parse_comment(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			goto out;
		}
	}

	if (pos->pos >= pos->size) {
		goto out;
	}

	if ((ret = rrr_parse_str_extract_name (&name, pos, '=')) != 0) {
		RRR_MSG_0("Failed to parse name of setting\n");
		goto out;
	}

	if (name == NULL) {
		goto out;
	}

	rrr_length line_orig = pos->line;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file after = at line %" PRIrrrl "\n", pos->line);
		ret = 1;
		goto out;
	}

	if (pos->line != line_orig) {
		RRR_MSG_0("Unexpected newline after = at line %" PRIrrrl ", parameter value missing\n", pos->line);
		ret = 1;
		goto out;
	}

	rrr_length value_begin;
	rrr_slength value_end;
	rrr_parse_non_newline(pos, &value_begin, &value_end);

	// Ignore trailing spaces
	while (value_end > value_begin && (pos->data[value_end] == ' ' || pos->data[value_end] == '\t')) {
		value_end--;
	}

	if (value_end < value_begin) {
		RRR_MSG_0("Expected value after = at line %" PRIrrrl "\n", pos->line);
		ret = 1;
		goto out;
	}

	rrr_length value_length = rrr_length_inc_bug_const(rrr_length_from_slength_sub_bug_const (value_end, value_begin));

	if (rrr_parse_str_extract(&value, pos, value_begin, value_length) != 0) {
		RRR_MSG_0("Could not extract value of setting\n");
		ret = 1;
		goto out;
	}

	if ((ret = new_setting_callback(block, name, value, callback_arg)) != 0) {
		goto out;
	}

	*did_parse = 1;

	out:
	RRR_FREE_IF_NOT_NULL(name);
	RRR_FREE_IF_NOT_NULL(value);

	return ret;
}

static int __rrr_config_parse_block (
		struct rrr_config *config,
		struct rrr_parse_pos *pos,
		int *did_parse,
		int (*new_block_callback)(RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS),
		int (*new_setting_callback)(RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	char *name = NULL;

	*did_parse = 0;

	if ((ret = rrr_parse_str_extract_name (&name, pos, ']')) != 0) {
		RRR_MSG_0("Failed to parse block name\n");
		goto out;
	}

	if (name == NULL) {
		RRR_MSG_0("Block name missing after [\n");
		goto out;
	}

	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of instance definition in line %" PRIrrrl "\n", pos->line);
		ret = 1;
		goto out;
	}

	void *block = NULL;
	if ((ret = new_block_callback (&block, config, name, callback_arg)) != 0) {
		goto out;
	}

	int did_parse_setting;
	while ((ret = __rrr_config_parse_setting (
			pos,
			&did_parse_setting,
			block,
			new_setting_callback,
			callback_arg
	)) == 0) {
		if (did_parse_setting != 1) {
			break;
		}
		else {
			rrr_parse_ignore_spaces_and_increment_line(pos);
		}
	}

	if (ret == 1) {
		RRR_MSG_0("Settings parsing failed at line %" PRIrrrl "\n", pos->line);
		*did_parse = 0;
	}

	if (ret == 0) {
		*did_parse = 1;
	}

	out:
	RRR_FREE_IF_NOT_NULL(name);
	return ret;
}

static int __rrr_config_parse_array_tree (
		struct rrr_config *config,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	struct rrr_array_tree *new_tree = NULL;
	char *name = NULL;

	if ((ret = rrr_parse_str_extract_name (&name, pos, '}')) != 0) {
		goto out;
	}

	if (name == NULL) {
		RRR_MSG_0("Array tree name missing after [\n");
		goto out;
	}

	if (rrr_array_tree_interpret (
			&new_tree,
			pos,
			name
	) != 0) {
		ret = 1;
		goto out;
	}

	if (pos->pos > pos->size) {
		RRR_BUG("BUG: Parsed beyond end in %s\n", __func__);
	}

	RRR_LL_APPEND(&config->array_trees, new_tree);
	new_tree = NULL;

	goto out;
	out:
		if (new_tree != NULL) {
			rrr_array_tree_destroy(new_tree);
		}
		RRR_FREE_IF_NOT_NULL(name);
		return ret;
}

static int __rrr_config_parse_discern_stack (
		struct rrr_discern_stack_collection *target,
		const char *type_name,
		const char delimeters[2],
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	char *name = NULL;

	if ((ret = rrr_parse_str_extract_name (&name, pos, delimeters[1])) != 0) {
		goto out;
	}

	if (name == NULL) {
		RRR_MSG_0("Definition name for %s missing after %s\n",
			type_name, delimeters[0]);
		goto out;
	}

	if (rrr_discern_stack_collection_get(target, name) != NULL) {
		RRR_MSG_0("Duplicate %s definition name %s\n",
				type_name, name);
		ret = 1;
		goto out;
	}

	enum rrr_discern_stack_fault fault;
	if (rrr_discern_stack_interpret (
			target,
			&fault,
			pos,
			name
	) != 0) {
		RRR_MSG_0("Failed to parse %s definition %s, error code was %u\n",
			type_name, name, fault);
		ret = 1;
		goto out;
	}

	if (pos->pos > pos->size) {
		RRR_BUG("BUG: Parsed beyond end in %s\n", __func__);
	}

	goto out;
	out:
		RRR_FREE_IF_NOT_NULL(name);
		return ret;
}

static int __rrr_config_parse_route_definition (
		struct rrr_config *config,
		struct rrr_parse_pos *pos
) {
	const char delimeters[2] = {'<', '>'};
	return __rrr_config_parse_discern_stack(&config->routes, "route", delimeters, pos);
}

static int __rrr_config_parse_method_definition (
		struct rrr_config *config,
		struct rrr_parse_pos *pos
) {
	const char delimeters[2] = {'(', ')'};
	return __rrr_config_parse_discern_stack(&config->routes, "method", delimeters, pos);
}

static int __rrr_config_parse_any (
		struct rrr_config *config,
		struct rrr_parse_pos *pos,
		int (*new_block_callback)(RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS),
		int (*new_setting_callback)(RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	rrr_parse_ignore_spaces_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos)) {
		return 0;
	}

	const char c = pos->data[pos->pos];

	if (rrr_length_inc_bug_new_value(&pos->pos) < pos->size) {
		if (c == '#') {
			rrr_parse_comment(pos);
		}
		else if (c == '{') {
			ret = __rrr_config_parse_array_tree(config, pos);
		}
		else if (c == '<') {
			ret = __rrr_config_parse_route_definition(config, pos);
		}
		else if (c == '(') {
			ret = __rrr_config_parse_method_definition(config, pos);
		}
		else if (c == '[') {
			int did_parse;
			ret = __rrr_config_parse_block (
					config,
					pos,
					&did_parse,
					new_block_callback,
					new_setting_callback,
					callback_arg
			);
			if (did_parse == 0 && ret == 0) {
				// XXX : Do we ever end up here?
				// No more instances, no errors
			}
			else if (ret == 1) {
				// Error occured
			}
		}
		else {
			RRR_MSG_0("Syntax error in config file at line %" PRIrrrl ", unexpected '%c'\n", pos->line, c);
			ret = 1;
		}
	}
	else {
		RRR_MSG_0("Syntax error at end of file (line %" PRIrrrl ")\n", pos->line);
		ret = 1;
	}

	return ret;
}

static int __rrr_config_parse_file (
		struct rrr_config *config,
		const void *data,
		const rrr_length size,
		int (*new_block_callback)(RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS),
		int (*new_setting_callback)(RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_parse_pos pos;

	rrr_parse_pos_init(&pos, data, size);

	while (!RRR_PARSE_CHECK_EOF(&pos)) {
		ret = __rrr_config_parse_any (
				config,
				&pos,
				new_block_callback,
				new_setting_callback,
				callback_arg
		);
		if (ret != 0) {
			break;
		}
	}

	if (ret != 0) {
		char *str_tmp = NULL;
		rrr_parse_make_location_message(&str_tmp, &pos);
		RRR_MSG_0("Parsing of configuration file failed\n%s\n", str_tmp);
		rrr_free(str_tmp);
	}

	return ret;
}

void rrr_config_destroy (
		struct rrr_config *target
) {
	rrr_array_tree_list_clear(&target->array_trees);
	rrr_discern_stack_collection_clear(&target->routes);
	rrr_free(target);
}

int rrr_config_parse_file (
		struct rrr_config *config,
		const char *filename,
		int (*new_block_callback)(RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS),
		int (*new_setting_callback)(RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	char *file_data = NULL;

	rrr_biglength file_size = 0;
	if ((ret = rrr_socket_open_and_read_file(&file_data, &file_size, filename, O_RDONLY, 0)) != 0) {
		RRR_MSG_0("Error while reading configuration file '%s'\n", filename);
		goto out;
	}

	if (file_data == NULL) {
		RRR_DBG_1("Configuration file '%s' was empty\n", filename);
	}
	else if (file_size > RRR_LENGTH_MAX) {
		RRR_DBG_1("Configuration file '%s' was too big (%llu>%llu)\n",
			filename, (long long unsigned) file_size, (long long unsigned) RRR_LENGTH_MAX);
		ret = 1;
		goto out;
	}
	else {
		RRR_DBG_1("Read %" PRIrrrbl " bytes from configuration file '%s'\n", file_size, filename);

		if ((ret = __rrr_config_parse_file (
				config,
				file_data,
				rrr_length_from_biglength_bug_const(file_size),
				new_block_callback,
				new_setting_callback,
				callback_arg
		)) != 0) {
			RRR_MSG_0("Error while parsing configuration file '%s'\n", filename);
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(file_data);
	return ret;
}

const struct rrr_array_tree_list *rrr_config_get_array_tree_list (
		struct rrr_config *config
) {
	return &config->array_trees;
}

const struct rrr_discern_stack_collection *rrr_config_get_routes (
		struct rrr_config *config
) {
	return &config->routes;
}
