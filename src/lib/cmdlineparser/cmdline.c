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

void cmd_init(struct cmd_data *data) {
	data->command = NULL;
	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX; i++) {
		data->args[i] = NULL;
		data->args_used[i] = 0;
		memset(&data->arg_pairs[i], '\0', sizeof(data->arg_pairs[i]));
	}
}

int cmd_check_all_args_used(struct cmd_data *data) {
	int err = 0;
	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX && *(data->args[i]) != '\0'; i++) {
		if (data->args_used[i] != 1) {
			fprintf (stderr, "Error: Argument %lu ('%s') was not used, possible junk or typo\n", i, data->args[i]);
			err = 1;
		}
	}
	return err;
}
/*
int cmd_get_value_index(struct cmd_data *data, const char *key, unsigned long int index) {
	unsigned long int index_counter == 0;
	for (int i = 0; i < CMD_ARGUMENT_MAX && data->arg_pairs[i].key[0] != '\0'; i++) {
		if (strcmp(data->arg_pairs[i].key, key) == 0 && index_counter++ == index) {
			return i;
		}
	}

	return -1;
}*/

struct cmd_arg_pair *cmd_find_pair(struct cmd_data *data, const char *key, cmd_arg_count index) {
	cmd_arg_count index_counter = 0;
	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX && data->arg_pairs[i].key[0] != '\0'; i++) {
		if (strcmp(data->arg_pairs[i].key, key) == 0 && index_counter++ == index) {
			data->args_used[i] = 1;
			return &data->arg_pairs[i];
		}
	}
	return NULL;
}

int cmd_convert_hex_byte(struct cmd_data *data, const char *value, char *result) {

	char *err;
	long int intermediate = strtol(value, &err, 16);

	if (err[0] != '\0' || intermediate < 0 || intermediate > 0xff) {
		return 1;
	}

	*result = intermediate;

	return 0;
}

int cmd_convert_hex_64(struct cmd_data *data, const char *value, uint64_t *result) {
	char *err;
	uint64_t intermediate = strtoull(value, &err, 16);

	if (err[0] != '\0') {
		return 1;
	}

	*result = intermediate;

	return 0;
}

int cmd_convert_uint64_10(struct cmd_data *data, const char *value, uint64_t *result) {
	char *err;
	*result = strtoull(value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int cmd_convert_integer_10(struct cmd_data *data, const char *value, int *result) {
	char *err;
	*result = strtol(value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int cmd_convert_float(struct cmd_data *data, const char *value, float *result) {
	char *err;
	*result = strtof(value, &err);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

const char *cmd_get_subvalue(struct cmd_data *data, const char *key, cmd_arg_count req_index, cmd_arg_count sub_index) {
	if (req_index > CMD_ARGUMENT_MAX) {
		fprintf (stderr, "Requested cmd value index out of range\n");
		exit (EXIT_FAILURE);
	}

	if (sub_index > CMD_ARGUMENT_MAX) {
		fprintf (stderr, "Requested cmd sub value index out of range");
		exit (EXIT_FAILURE);
	}

	struct cmd_arg_pair *pair = cmd_find_pair(data, key, req_index);
	if (pair == NULL) {
		return NULL;
	}

	return pair->sub_values[sub_index];
}

const char *cmd_get_value(struct cmd_data *data, const char *key, cmd_arg_count index) {
	cmd_arg_count index_counter = 0;

	if (index > CMD_ARGUMENT_MAX) {
		fprintf (stderr, "Requested cmd value index out of range\n");
		exit (EXIT_FAILURE);
	}

	struct cmd_arg_pair *pair = cmd_find_pair(data, key, index);
	if (pair != NULL) {
		return pair->value;
	}

	return NULL;
}

const char *cmd_get_argument(struct cmd_data *data, cmd_arg_count index) {
	if (index >= CMD_ARGUMENT_MAX || *(data->args[index]) == '\0') {
		return NULL;
	}
	data->args_used[index] = 1;
	return data->args[index];
}

/* Get last argument after already read arg=val pairs */
const char *cmd_get_last_argument(struct cmd_data *data) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (data->args_used[i] == 0 && data->args[i] != NULL && *(data->args[i]) != '\0') {
			data->args_used[i] = 1;
			return data->args[i];
		}
	}
	return NULL;
}

void cmd_pair_split_comma(struct cmd_arg_pair *pair) {
	cmd_arg_count sub_value_counter = 0;
	const char *pos = pair->value;
	const char *end = pos + strlen(pos);
	while (pos < end) {
		const char *comma_pos = strstr(pos, ",");
		if (comma_pos == NULL) {
			comma_pos = end;
		}
		cmd_arg_size length = comma_pos - pos;

		memcpy(pair->sub_values[sub_value_counter], pos, length);
		pair->sub_values[sub_value_counter][length] = '\0';

		pos = comma_pos + 1;
		sub_value_counter++;
		if (sub_value_counter == CMD_ARGUMENT_MAX) {
			fprintf(stderr, "Too many comma separated values, maximum is %i\n", CMD_ARGUMENT_MAX);
			exit(EXIT_FAILURE);
		}
	}
}

int cmd_parse(struct cmd_data *data, int argc, const char *argv[], cmd_conf config) {
	cmd_init(data);

	data->program = argv[0];
	data->command = cmd_help;

	if (argc <= 1) {
		return 0;
	}

	int argc_begin = 2;

	if ((config & CMD_CONFIG_NOCOMMAND) > 0) {
		data->command = cmd_blank_argument;
		argc_begin = 1;
	}
	else if (argc > 1) {
		data->command = argv[1];
	}

	// Initialize all to empty strings
	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX; i++) {
		data->args[i] = cmd_blank_argument;
	}

	// Store pointers to all arguments
	int arg_pos = argc_begin;
	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX && arg_pos < argc; i++) {
		data->args[i] = argv[arg_pos];
		arg_pos++;
	}

	// Parse key-value pairs separated by =
	int pairs_pos = 0;
	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX && data->args[i] != NULL; i++) {
			const char *pos;
			if ((pos = strstr(data->args[i], "=")) != NULL) {
				const char *value = pos + 1;
				cmd_arg_size key_length = pos - data->args[i];
				cmd_arg_size value_length = strlen(value);

				if (key_length == 0 || value_length == 0) {
					fprintf (stderr, "Error: Syntax error with = syntax in argument %lu ('%s'), use key=value\n", i, data->args[i]);
					return 1;
				}
				if (key_length > CMD_ARGUMENT_SIZE - 1) {
					fprintf (stderr, "Error: Argument key %lu too long ('%s'), maximum size is %d\n", i, data->args[i], CMD_ARGUMENT_SIZE - 1);
					return 1;
				}
				if (value_length > CMD_ARGUMENT_SIZE - 1) {
					fprintf (stderr, "Error: Argument value %lu too long ('%s'), maximum size is %d\n", i, data->args[i], CMD_ARGUMENT_SIZE - 1);
					return 1;
				}

				strncpy(data->arg_pairs[pairs_pos].key, data->args[i], key_length);
				data->arg_pairs[pairs_pos].key[key_length] = '\0';

				strncpy(data->arg_pairs[pairs_pos].value, value, value_length);
				data->arg_pairs[pairs_pos].value[value_length] = '\0';

				if ((config & CMD_CONFIG_SPLIT_COMMA) != 0) {
					cmd_pair_split_comma(&data->arg_pairs[pairs_pos]);
				}

				pairs_pos++;
			}
	}

	#ifdef CMD_DBG_CMDLINE

	printf ("Program: %s\n", data->program);
	printf ("Command: %s\n", data->command);

	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX && data->args[i] != NULL; i++) {
		printf ("Argument %i: %s\n", i, data->args[i]);
	}

	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX && data->arg_pairs[i].key[0] != '\0'; i++) {
		printf ("Argument %i key: %s\n", i, data->arg_pairs[i].key);
		printf ("Argument %i value: %s\n", i, data->arg_pairs[i].value);
	}

	#endif

	return 0;
}

int cmd_match(struct cmd_data *data, const char *test) {
	return strcmp(data->command, test) == 0;
}

int cmdline_check_yesno (struct cmd_data *data, const char *string, int *result) {
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
