/*

Command Line Parser

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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
#include <stddef.h>
#include <stdlib.h>
#include <inttypes.h>

#include "cmdline.h"
#include "../../global.h"

//#define CMD_DBG_CMDLINE

static const char *cmd_blank_argument = "";
static const char *cmd_help = "help";

static void __cmd_arg_value_destroy(struct cmd_arg_value *value) {
	RRR_FREE_IF_NOT_NULL(value->value);
	free(value);
}

static int __cmd_arg_value_new (struct cmd_arg_value **target, const char *value_str) {
	int ret = 0;

	*target = NULL;

	struct cmd_arg_value *value = malloc(sizeof(*value));
	if (value == NULL) {
		fprintf(stderr, "Error: Could not allocate memory in __cmd_arg_value_new\n");
		ret = 1;
		goto out;
	}
	memset(value, '\0', sizeof(*value));

	if ((value->value = strdup(value_str)) == NULL) {
		fprintf(stderr, "Error: Could not allocate memory in __cmd_arg_value_new\n");
		ret = 1;
		goto out;
	}

	*target = value;
	value = NULL;

	out:
	if (value != NULL) {
		__cmd_arg_value_destroy(value);
	}
	return ret;
}

static void __cmd_arg_pair_destroy(struct cmd_arg_pair *pair) {
	RRR_LINKED_LIST_DESTROY(pair, struct cmd_arg_value, __cmd_arg_value_destroy(node));
	free(pair);
}

static int __cmd_arg_pair_new (struct cmd_arg_pair **target, const struct cmd_arg_rule *rule) {
	int ret = 0;

	*target = NULL;

	struct cmd_arg_pair *pair = malloc(sizeof(*pair));
	if (pair == NULL) {
		fprintf(stderr, "Error: Could not allocate memory in __cmd_arg_pair_new\n");
		ret = 1;
		goto out;
	}
	memset(pair, '\0', sizeof(*pair));

	pair->rule = rule;

	*target = pair;
	pair = NULL;

	out:
	if (pair != NULL) {
		__cmd_arg_pair_destroy(pair);
	}
	return ret;
}

static int __cmd_arg_pair_append_value (struct cmd_arg_pair *target, const char *value_str) {
	struct cmd_arg_value *value = NULL;

	if (__cmd_arg_value_new(&value, value_str) != 0) {
		return 1;
	}

	RRR_LINKED_LIST_APPEND(target, value);

	return 0;
}

void cmd_destroy(struct cmd_data *data) {
	RRR_LINKED_LIST_DESTROY(data, struct cmd_arg_pair, __cmd_arg_pair_destroy(node));
}

void cmd_init(struct cmd_data *data, const struct cmd_arg_rule *rules, int argc, const char *argv[]) {
	memset (data, '\0', sizeof(*data));
	data->argc = argc;
	data->argv = argv;
	data->rules = rules;
}

int cmd_check_all_args_used(struct cmd_data *data) {
	int err = 0;
	unsigned long int i = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct cmd_arg_pair);
		if (node->was_used != 1) {
			fprintf (stderr, "Error: Argument %lu ('%s') was not used\n", i, node->rule->longname);
		}
		i++;
	RRR_LINKED_LIST_ITERATE_END(data);
	return err;
}

struct cmd_arg_pair *cmd_find_pair(struct cmd_data *data, const char *key, cmd_arg_count index) {
	cmd_arg_count index_counter = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct cmd_arg_pair);
		if (strcmp(node->rule->longname, key) == 0 && index_counter++ == index) {
			node->was_used = 1;
			return node;
		}
	RRR_LINKED_LIST_ITERATE_END(data);
	return NULL;
}

int cmd_convert_hex_byte(const char *value, char *result) {
	char *err;
	long int intermediate = strtol(value, &err, 16);

	if (err[0] != '\0' || intermediate < 0 || intermediate > 0xff) {
		return 1;
	}

	*result = intermediate;

	return 0;
}

int cmd_convert_hex_64(const char *value, uint64_t *result) {
	char *err;
	uint64_t intermediate = strtoull(value, &err, 16);

	if (err[0] != '\0') {
		return 1;
	}

	*result = intermediate;

	return 0;
}

int cmd_convert_uint64_10(const char *value, uint64_t *result) {
	char *err;
	*result = strtoull(value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int cmd_convert_integer_10(const char *value, int *result) {
	char *err;
	*result = strtol(value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int cmd_convert_float(const char *value, float *result) {
	char *err;
	*result = strtof(value, &err);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

void cmd_dump_usage(struct cmd_data *data) {
	const char *usage_format = "Usage: %s ";
	printf(usage_format, data->program);

	ssize_t spaces_length = strlen(usage_format) + strlen(data->program) - 1;
	char spaces[spaces_length];
	memset(spaces, ' ', sizeof(spaces) - 1);
	spaces[spaces_length - 1] = '\0';

	int i = 0;
	const struct cmd_arg_rule *rule = NULL;
	rule = &data->rules[i];
	while (rule->longname != NULL) {
		if (i > 0) {
			printf("%s", spaces);
		}
		printf("%s\n", rule->legend);
		i++;
		rule = &data->rules[i];
	}
}

int cmd_exists(struct cmd_data *data, const char *key, cmd_arg_count index) {
	cmd_arg_count i = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct cmd_arg_pair);
		if (strcmp (node->rule->longname, key) == 0) {
			if (i == index) {
				return 1;
			}
			i++;
		}
	RRR_LINKED_LIST_ITERATE_END(data);
	return 0;
}

const char *cmd_get_subvalue(struct cmd_data *data, const char *key, cmd_arg_count req_index, cmd_arg_count sub_index) {
	struct cmd_arg_pair *pair = cmd_find_pair(data, key, req_index);
	if (pair == NULL) {
		return NULL;
	}

	cmd_arg_count i = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(pair, struct cmd_arg_value);
		if (i == sub_index) {
			return node->value;
		}
	RRR_LINKED_LIST_ITERATE_END(pair);

	return NULL;
}

const char *cmd_get_value(struct cmd_data *data, const char *key, cmd_arg_count index) {
	return cmd_get_subvalue (data, key, index, 0);
}

void cmd_pair_split_comma(struct cmd_arg_pair *pair) {
	struct cmd_arg_value *value = NULL;
	char *buf = NULL;

	if (RRR_LINKED_LIST_COUNT(pair) != 1) {
		fprintf(stderr, "Bug: Length of argument values was not 1 in cmd_pair_split_comma\n");
		abort();
	}

	value = pair->ptr_first;
	RRR_LINKED_LIST_DANGEROUS_CLEAR_HEAD(pair);

	const char *pos = value->value;
	const char *end = pos + strlen(pos);

	buf = malloc(end - pos + 1);
	if (buf == NULL) {
		fprintf(stderr, "Error: Could not allocate memory in cmd_pair_split_comma\n");
		abort();
	}

	while (pos < end) {
		const char *comma_pos = strstr(pos, ",");
		if (comma_pos == NULL) {
			comma_pos = end;
		}
		cmd_arg_size length = comma_pos - pos;

		memcpy(buf, pos, length);
		buf[length] = '\0';

		__cmd_arg_pair_append_value(pair, buf);

		pos = comma_pos + 1;
	}

	RRR_FREE_IF_NOT_NULL(buf);
	RRR_FREE_IF_NOT_NULL(value);
}

void cmd_get_argv_copy (struct cmd_argv_copy **target, struct cmd_data *data) {
	struct cmd_argv_copy *ret = malloc(sizeof(*ret));

	*target = NULL;

	ret->argv = malloc(sizeof(char*) * (data->argc + 1));
	ret->argc = data->argc;

	int i;
	for (i = 0; i < data->argc; i++) {
		ret->argv[i] = malloc(strlen(data->argv[i]) + 1);
		strcpy(ret->argv[i], data->argv[i]);
	}
	ret->argv[i] = NULL;

	*target = ret;
}

void cmd_destroy_argv_copy (struct cmd_argv_copy *target) {
	if (target == NULL) {
		return;
	}
	// We always have an extra pointer to hold NULL, hence the <=
	for (int i = 0; i <= target->argc; i++) {
		free(target->argv[i]);
	}
	free(target->argv);
	free(target);
}

static const struct cmd_arg_rule *__cmd_get_rule_by_longname (const struct cmd_arg_rule *rules, const char *longname) {
	int i = 0;
	const struct cmd_arg_rule *rule = NULL;
	rule = &rules[i];
	while (rule->longname != NULL) {
		if (strcmp(rule->longname, longname) == 0) {
			return rule;
		}
		i++;
		rule = &rules[i];
	}
	return NULL;
}

static const struct cmd_arg_rule *__cmd_get_rule_by_shortname (const struct cmd_arg_rule *rules, const char shortname) {
	int i = 0;
	const struct cmd_arg_rule *rule = NULL;
	rule = &rules[i];
	while (rule->longname != NULL) {
		if (rule->shortname == shortname) {
			return rule;
		}
		i++;
		rule = &rules[i];
	}
	return NULL;
}

int cmd_parse (struct cmd_data *data, cmd_conf config) {
	data->program = data->argv[0];
	data->command = cmd_help;

	if (data->argc <= 1) {
		return 0;
	}

	cmd_arg_count argc_begin = 2;

	if ((config & CMD_CONFIG_NOCOMMAND) > 0) {
		data->command = cmd_blank_argument;
		argc_begin = 1;
	}
	else if (data->argc > 1) {
		data->command = data->argv[1];
	}

	for (int i = argc_begin; i < data->argc; i++) {
		const char *pos = data->argv[i];
		ssize_t key_length = 0;
		const char *pos_equal = NULL;
		const struct cmd_arg_rule *rule = NULL;
		int dash_count = 0;

		if (strncmp(pos, "--", 2) == 0) {
			dash_count = 2;
			pos += 2;
		}
		else if (strncmp(pos, "-", 1) == 0) {
			dash_count = 1;
			pos += 1;
		}

		if ((pos_equal = strstr(pos, "=")) != NULL) {
			key_length = pos_equal - pos;
		}
		else {
			key_length = strlen(pos);
		}

		if (key_length == 0) {
			fprintf (stderr, "Error: Argument index %i was empty\n", i);
			return 1;
		}
		if (key_length == 0) {
			fprintf (stderr, "Error: Syntax error with = syntax in argument %i ('%s'), use key=value\n",
					i, data->argv[i]);
			return 1;
		}

		if (dash_count == 1) {
			for (int j = 0; j < key_length; j++) {
				rule = __cmd_get_rule_by_shortname(data->rules, *(pos+j));
				if (rule == NULL) {
					fprintf (stderr, "Error: Argument '%c' is unknown\n", *(pos+j));
					return 1;
				}
				if (rule->has_argument != 0 && key_length != 1) {
					fprintf (stderr, "Error: Argument '%c' has arguments and must be declared by itself\n", *(pos+j));
					return 1;
				}
			}
		}
		else {
			char key[key_length + 1];
			strncpy(key, pos, key_length);
			key[key_length] = '\0';

			rule = __cmd_get_rule_by_longname(data->rules, key);
			if (rule == NULL) {
				fprintf (stderr, "Error: Argument '%s' is unknown\n", key);
				return 1;
			}
		}

		const char *value = NULL;
		if (rule->has_argument != 0) {
			if (pos_equal == NULL) {
				i++;
				if (i == data->argc) {
					fprintf (stderr, "Error: Required argument missing for '%s'\n", rule->longname);
					return 1;
				}
				value = data->argv[i];
			}
			else {
				value = pos_equal + 1;
			}
			if (strlen(value) < 1) {
				fprintf (stderr, "Error: Required argument missing or was empty for '%s'\n", rule->longname);
				return 1;
			}
		}
		else if (pos_equal != NULL)  {
			fprintf (stderr, "Error: Argument given to '%s' which takes no arguments\n", rule->longname);
			return 1;
		}

		struct cmd_arg_pair *pair = NULL;
		if (__cmd_arg_pair_new(&pair, rule) != 0) {
			return 1;
		}
		RRR_LINKED_LIST_APPEND(data,pair);
		if (value != NULL) {
			if (__cmd_arg_pair_append_value(pair, value) != 0) {
				return 1;
			}
			if ((config & CMD_CONFIG_SPLIT_COMMA) != 0) {
				cmd_pair_split_comma(pair);
			}
		}
	}

	#ifdef CMD_DBG_CMDLINE

	printf ("Program: %s\n", data->program);
	printf ("Command: %s\n", data->command);

	int i = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct cmd_arg_pair);
		struct cmd_arg_pair *pair = node;
		printf ("Argument %i key: %s\n", i, pair->rule->longname);
		RRR_LINKED_LIST_ITERATE_BEGIN(pair, struct cmd_arg_value);
			printf ("Argument %i value: %s\n", i, node->value);
		RRR_LINKED_LIST_ITERATE_END(node);
		i++;
	RRR_LINKED_LIST_ITERATE_END(data);

	#endif

	return 0;
}

int cmd_match(struct cmd_data *data, const char *test) {
	return strcmp(data->command, test) == 0;
}

int cmdline_check_yesno (const char *string, int *result) {
	*result = 0;

	if (*string == 'y' || *string == 'Y' || *string == '1') {
		*result = 1;
	}
	else if (*string == 'n' || *string == 'N' || *string == '0') {
		*result = 0;
	}
	else {
		return 1;
	}

	return 0;
}
