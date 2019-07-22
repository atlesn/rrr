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

//#define CMD_DBG_CMDLINE

static const char *cmd_blank_argument = "";
static const char *cmd_help = "help";

void cmd_init(struct cmd_data *data) {
	data->command = NULL;
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		data->args[i] = NULL;
		data->args_used[i] = 0;
		memset(&data->arg_pairs[i], '\0', sizeof(data->arg_pairs[i]));
	}
}

int cmd_check_all_args_used(struct cmd_data *data) {
	int err = 0;
	for (int i = 0; i < CMD_ARGUMENT_MAX && *(data->args[i]) != '\0'; i++) {
		if (data->args_used[i] != 1) {
			fprintf (stderr, "Error: Argument %i ('%s') was not used, possible junk or typo\n", i, data->args[i]);
			err = 1;
		}
	}
	return err;
}

int cmd_get_value_index(struct cmd_data *data, const char *key) {
	for (int i = 0; i < CMD_ARGUMENT_MAX && data->arg_pairs[i].key[0] != '\0'; i++) {
		if (strcmp(data->arg_pairs[i].key, key) == 0) {
			return i;
		}
	}

	return -1;
}

int cmd_convert_hex_byte(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);
	if (index == -1) {
		return 1;
	}

	if (data->arg_pairs[index].hex_is_converted) {
		return 0;
	}

	char *err;
	long int intermediate = strtol(data->arg_pairs[index].value, &err, 16);

	if (err[0] != '\0' || intermediate < 0 || intermediate > 0xff) {
		return 1;
	}

	data->arg_pairs[index].value_hex = intermediate;
	data->arg_pairs[index].hex_is_converted = 1;

	#ifdef CMD_DBG_CMDLINE

	printf ("Converted argument with key '%s' to hex '%x'\n", key, data->arg_pairs[index].value_hex);

	#endif

	return 0;
}

int cmd_convert_hex_64(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);
	if (index == -1) {
		return 1;
	}

	if (data->arg_pairs[index].hex64_is_converted) {
		return 0;
	}

	char *err;
	uint64_t intermediate = strtoull(data->arg_pairs[index].value, &err, 16);

	if (err[0] != '\0') {
		return 1;
	}

	data->arg_pairs[index].value_hex_64 = intermediate;
	data->arg_pairs[index].hex64_is_converted = 1;

	#ifdef CMD_DBG_CMDLINE

	printf ("Converted argument with key '%s' to hex64 '%" PRIx64 "'\n", key, data->arg_pairs[index].value_hex_64);

	#endif

	return 0;
}

int cmd_convert_uint64_10(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);
	if (index == -1) {
		return 1;
	}

	if (data->arg_pairs[index].uint64_is_converted == 1) {
		return 0;
	}

	char *err;
	data->arg_pairs[index].value_uint_64 = strtoull(data->arg_pairs[index].value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	data->arg_pairs[index].uint64_is_converted = 1;

	#ifdef CMD_DBG_CMDLINE

	printf ("Converted argument with key '%s' to uint64 %'" PRIx64 "'\n", key, data->arg_pairs[index].value_uint_64);

	#endif

	return 0;
}

int cmd_convert_integer_10(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);
	if (index == -1) {
		return 1;
	}

	if (data->arg_pairs[index].integer_is_converted) {
		return 0;
	}

	char *err;
	data->arg_pairs[index].value_int = strtol(data->arg_pairs[index].value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	data->arg_pairs[index].integer_is_converted = 1;

	#ifdef CMD_DBG_CMDLINE

	printf ("Converted argument with key '%s' to integer '%ld'\n", key, data->arg_pairs[index].value_int);

	#endif

	return 0;
}

char cmd_get_hex_byte(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);

	if (index == -1) {
		fprintf(stderr, "Bug: Called cmd_get_hex with unknown key '%s'\n", key);
		exit (EXIT_FAILURE);
	}

	if (data->arg_pairs[index].hex_is_converted != 1) {
		fprintf(stderr, "Bug: Called cmd_get_hex without cmd_convert_hex being called first\n");
		exit (EXIT_FAILURE);
	}

	data->args_used[index] = 1;

	return data->arg_pairs[index].value_hex;
}

uint64_t cmd_get_hex_64(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);

	if (index == -1) {
		fprintf(stderr, "Bug: Called cmd_get_hex_64 with unknown key '%s'\n", key);
		exit (EXIT_FAILURE);
	}

	if (data->arg_pairs[index].hex64_is_converted != 1) {
		fprintf(stderr, "Bug: Called cmd_get_hex_64 without cmd_convert_hex_64 being called first\n");
		exit (EXIT_FAILURE);
	}

	data->args_used[index] = 1;

	return data->arg_pairs[index].value_hex_64;
}

long int cmd_get_integer(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);

	if (index == -1) {
		fprintf(stderr, "Bug: Called cmd_get_integer with unknown key '%s'\n", key);
		exit (EXIT_FAILURE);
	}

	if (data->arg_pairs[index].integer_is_converted != 1) {
		fprintf(stderr, "Bug: Called cmd_get_integer without cmd_convert_integer being called first\n");
		exit (EXIT_FAILURE);
	}
	data->args_used[index] = 1;

	return data->arg_pairs[index].value_int;
}

uint64_t cmd_get_uint64(struct cmd_data *data, const char *key) {
	int index = cmd_get_value_index(data, key);

	if (index == -1) {
		fprintf(stderr, "Bug: Called cmd_get_uint64 with unknown key '%s'\n", key);
		exit (EXIT_FAILURE);
	}

	#ifdef CMD_DBG_CMDLINE
	if (data->arg_pairs[index].uint64_is_converted != 1) {
		fprintf(stderr, "Bug: Called cmd_get_uint64 without cmd_convert_uint64 being called first\n");
		exit (EXIT_FAILURE);
	}
	#endif

	data->args_used[index] = 1;

	return data->arg_pairs[index].value_uint_64;
}

const char *cmd_get_value(struct cmd_data *data, const char *key) {
	for (int i = 0; i < CMD_ARGUMENT_MAX && data->arg_pairs[i].key[0] != '\0'; i++) {
		if (strcmp(data->arg_pairs[i].key, key) == 0) {
			#ifdef CMD_DBG_CMDLINE
			printf ("Retrieve string argument %s: %s\n", key, data->arg_pairs[i].value);
			#endif

			data->args_used[i] = 1;
			return data->arg_pairs[i].value;
		}
	}

	return NULL;
}

const char *cmd_get_argument(struct cmd_data *data, int index) {
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

int cmd_parse(struct cmd_data *data, int argc, const char *argv[], unsigned long int config) {
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
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		data->args[i] = cmd_blank_argument;
	}

	// Store pointers to all arguments
	int arg_pos = argc_begin;
	for (int i = 0; i < CMD_ARGUMENT_MAX && arg_pos < argc; i++) {
		data->args[i] = argv[arg_pos];
		arg_pos++;
	}

	// Parse key-value pairs separated by =
	int pairs_pos = 0;
	for (int i = 0; i < CMD_ARGUMENT_MAX && data->args[i] != NULL; i++) {
			const char *pos;
			if ((pos = strstr(data->args[i], "=")) != NULL) {
				const char *value = pos + 1;
				int key_length = pos - data->args[i];
				int value_length = strlen(value);

				if (key_length == 0 || value_length == 0) {
					fprintf (stderr, "Error: Syntax error with = syntax in argument %i ('%s'), use key=value\n", i, data->args[i]);
					return 1;
				}

				if (key_length > CMD_ARGUMENT_SIZE - 1) {
					fprintf (stderr, "Error: Argument key %i too long ('%s'), maximum size is %i\n", i, data->args[i], CMD_ARGUMENT_SIZE - 1);
					return 1;
				}
				if (value_length > CMD_ARGUMENT_SIZE - 1) {
					fprintf (stderr, "Error: Argument value %i too long ('%s'), maximum size is %i\n", i, data->args[i], CMD_ARGUMENT_SIZE - 1);
					return 1;
				}

				strncpy(data->arg_pairs[pairs_pos].key, data->args[i], key_length);
				data->arg_pairs[pairs_pos].key[key_length] = '\0';

				strncpy(data->arg_pairs[pairs_pos].value, value, value_length);
				data->arg_pairs[pairs_pos].value[value_length] = '\0';

				pairs_pos++;
			}
	}

	#ifdef CMD_DBG_CMDLINE

	printf ("Program: %s\n", data->program);
	printf ("Command: %s\n", data->command);

	for (int i = 0; i < CMD_ARGUMENT_MAX && data->args[i] != NULL; i++) {
		printf ("Argument %i: %s\n", i, data->args[i]);
	}

	for (int i = 0; i < CMD_ARGUMENT_MAX && data->arg_pairs[i].key[0] != '\0'; i++) {
		printf ("Argument %i key: %s\n", i, data->arg_pairs[i].key);
		printf ("Argument %i value: %s\n", i, data->arg_pairs[i].value);
	}

	#endif

	return 0;
}

int cmd_match(struct cmd_data *data, const char *test) {
	return strcmp(data->command, test) == 0;
}

