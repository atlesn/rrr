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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "../global.h"
#include "configuration.h"

#include "instance_config.h"

#define RRR_CONFIGFILE_DEBUG

struct parse_pos {
	const char *data;
	int pos;
	int size;
	int line;
};

struct rrr_config *__rrr_config_new () {
	struct rrr_config *ret = malloc(sizeof(*ret));

	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory for rrr_config struct\n");
		return NULL;
	}

	ret->module_count = 0;
	ret->module_count_max = 0;
	ret->configs = NULL;

	return ret;
}

int __rrr_config_expand(struct rrr_config *target) {
	int old_size = target->module_count_max * sizeof(*target->configs);
	int new_size = old_size + (RRR_CONFIG_ALLOCATION_INTERVAL * sizeof(*target->configs));
	int new_max = target->module_count_max + RRR_CONFIG_ALLOCATION_INTERVAL;

	struct rrr_instance_config **configs_new = realloc(target->configs, new_size);

	if (configs_new == NULL) {
		VL_MSG_ERR("Could not reallocate memory for rrr_instance_config struct\n");
		return 1;
	}

	target->configs = configs_new;
	target->module_count_max = new_max;

	return 0;
}

int __rrr_config_push (struct rrr_config *target, struct rrr_instance_config *instance_config) {
	if (rrr_config_find_instance (target, instance_config->name) != NULL) {
		VL_MSG_ERR("Two instances was named %s\n", instance_config->name);
		return 1;
	}

	if (target->module_count == target->module_count_max) {
		if (__rrr_config_expand(target) != 0) {
			VL_MSG_ERR("Could not push new config struct\n");
			return 1;
		}
	}

	target->configs[target->module_count] = instance_config;
	target->module_count++;

	return 0;
}

int __rrr_config_check_eof (const struct parse_pos *pos) {
	return (pos->pos >= pos->size);
}

void __rrr_config_ignore_spaces (struct parse_pos *pos) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

	while ((c == ' ' || c == '\t' || c == '\n' || c == '\r') && pos->pos < pos->size) {
		char next = pos->pos + 1 < pos->size ? pos->data[pos->pos + 1] : '\0';

		if (c == '\r' && next == '\n') {
			// Windows
			pos->pos++;
			pos->line++;
		}
		else if (c == '\n') {
			// UNIX
			pos->line++;
		}
		else if (c == '\r') {
			// MAC
			pos->line++;
		}

		pos->pos++;
		if (__rrr_config_check_eof(pos)) {
			break;
		}

		pos->data[pos->pos];
		c = pos->data[pos->pos];
	}
}

void __rrr_config_parse_comment (struct parse_pos *pos) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

	while (c != '\r' && c != '\n' && pos->pos < pos->size) {
		pos->pos++;
		pos->data[pos->pos];
		c = pos->data[pos->pos];
	}

	__rrr_config_ignore_spaces(pos);
}

void __rrr_config_parse_letters (struct parse_pos *pos, int *start, int *end, int allow_space_tab, int allow_commas) {
	*start = pos->pos;
	*end = pos->pos;

	char c = pos->data[pos->pos];
	while (!__rrr_config_check_eof(pos)) {
		if (	(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '_' ||
				c == '-' ||
				(allow_space_tab && (c == ' ' || c == '\t')) ||
				(allow_commas && (c == ',' || c == ';'))
		) {
			// OK
		}
		else {
			break;
		}

		pos->pos++;
		if (__rrr_config_check_eof(pos)) {
			break;
		}
		c = pos->data[pos->pos];
	}

	*end = pos->pos - 1;
}

void __rrr_config_parse_non_newline (struct parse_pos *pos, int *start, int *end) {
	*start = pos->pos;
	*end = pos->pos;

	char c = pos->data[pos->pos];
	while (!__rrr_config_check_eof(pos)) {
		if (c == '\r' || c == '\n') {
			break;
		}

		pos->pos++;
		if (__rrr_config_check_eof(pos)) {
			break;
		}
		c = pos->data[pos->pos];
	}

	*end = pos->pos - 1;
}

int __rrr_config_extract_string (char **target, struct parse_pos *pos, const int begin, const int length) {
	*target = NULL;

	if (length == 0) {
		VL_MSG_ERR("BUG: length was 0 in __rrr_config_extract_string\n");
		exit(EXIT_FAILURE);
	}

	char *bytes = malloc(length + 1);

	if (bytes == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_config_extract_string\n");
		return 1;
	}

	memcpy(bytes, pos->data + begin, length);

	bytes[length] = '\0';

	*target = bytes;

	return 0;
}

int __rrr_config_parse_setting (struct parse_pos *pos, struct rrr_instance_settings *settings, int *did_parse) {
	int ret = 0;

	char c;
	int name_begin;
	int name_end;

	char *name = NULL;
	char *value = NULL;

	*did_parse = 0;

	__rrr_config_ignore_spaces(pos);

	if (__rrr_config_check_eof(pos)) {
		goto out;
	}

	if (pos->data[pos->pos] == '#') {
		__rrr_config_parse_comment(pos);
	}

	if (pos->pos >= pos->size) {
		goto out;
	}


	__rrr_config_parse_letters(pos, &name_begin, &name_end, 0, 0);

	if (name_end < name_begin) {
		ret = 0;
		goto out;
	}

	__rrr_config_ignore_spaces(pos);
	if (__rrr_config_check_eof(pos)) {
		VL_MSG_ERR("Unexpected end of file after setting name at line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	c = pos->data[pos->pos];
	if (c != '=') {
		VL_MSG_ERR("Expected = after setting name at line %d, found %c\n", pos->line, c);
		ret = 1;
		goto out;
	}

	pos->pos++;
	__rrr_config_ignore_spaces(pos);
	if (__rrr_config_check_eof(pos)) {
		VL_MSG_ERR("Unexpected end of file after = at line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	int value_begin;
	int value_end;
	__rrr_config_parse_non_newline(pos, &value_begin, &value_end);

	if (value_end < value_begin) {
		VL_MSG_ERR("Expected value after = at line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	int name_length = name_end - name_begin + 1;
	int value_length = value_end - value_begin + 1;

	if (__rrr_config_extract_string(&name, pos, name_begin, name_length) != 0) {
		VL_MSG_ERR("Could not extract setting name\n");
		ret = 1;
		goto out;
	}

	if (__rrr_config_extract_string(&value, pos, value_begin, value_length) != 0) {
		VL_MSG_ERR("Could not extract setting name\n");
		ret = 1;
		goto out;
	}

	if (rrr_settings_add_string(settings, name, value) != 0) {
		ret = 1;
		goto out;
	}

	*did_parse = 1;

	out:
	if (value != NULL) {
		free(value);
	}
	if (name != NULL) {
		free(name);
	}

	return ret;
}

int __rrr_config_parse_instance (struct rrr_config *config, struct parse_pos *pos, int *did_parse) {
	int ret = 0;
	*did_parse = 0;

	__rrr_config_ignore_spaces(pos);
	if (pos->pos >= pos->size) {
		ret = 0;
		goto out;
	}

	int begin = pos->pos;

	if (pos->pos >= pos->size) {
		VL_MSG_ERR("Unexpected end of instance definition at line %d\n", pos->line);
		return 1;
	}

	char c = pos->data[pos->pos];
	while (c != ']' && !__rrr_config_check_eof(pos)) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
		}
		else {
			VL_MSG_ERR("Unexpected character '%c' in instance definition in line %d\n", c, pos->line);
			ret = 1;
			goto out;
		}

		pos->pos++;

		if (pos->pos >= pos->size) {
			break;
		}

		c = pos->data[pos->pos];
	}

	if (__rrr_config_check_eof(pos)) {
		VL_MSG_ERR("Unexpected end of instance definition in line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	c = pos->data[pos->pos];
	if (c != ']') {
		VL_MSG_ERR("Syntax error in instance definition in line %d, possibly missing ]\n", pos->line);
		ret = 1;
		goto out;
	}

	int end = pos->pos - 1;
	int length = end - begin + 1;

	pos->pos++;

	if (end < begin) {
		VL_MSG_ERR("Instance name at line %d was too short\n", pos->line);
		ret = 1;
		goto out;
	}

	struct rrr_instance_config *instance_config = rrr_config_new_instance_config(pos->data + begin, length, RRR_CONFIG_MAX_SETTINGS);
	if (instance_config == NULL) {
		VL_MSG_ERR("Instance config creation result was NULL\n");
		ret = 1;
		goto out;
	}

	int did_parse_setting;
	while ((ret = __rrr_config_parse_setting(pos, instance_config->settings, &did_parse_setting)) == 0) {
		if (did_parse_setting != 1) {
			break;
		}
		else {
			__rrr_config_ignore_spaces(pos);
		}
	}

	if (ret == 1) {
		VL_MSG_ERR("Settings parsing failed for instance %s at line %d\n", instance_config->name, pos->line);
		*did_parse = 0;
	}

#ifdef RRR_CONFIGFILE_DEBUG
	printf("\nDumping settings for instance %s:\n", instance_config->name);
	rrr_settings_dump(instance_config->settings);
#endif

	if (ret == 0) {
		*did_parse = 1;
	}

	out_free_config:
	if (ret == 0) {
		ret = __rrr_config_push(config, instance_config);
		if (ret != 0) {
			VL_MSG_ERR("Could not save instance %s to global config\n", instance_config->name);
		}
	}

	if (ret != 0) {
		rrr_config_destroy_instance_config(instance_config);
	}

	out:
	return ret;
}

int __rrr_config_parse_any (struct rrr_config *config, struct parse_pos *pos) {
	int ret = 0;

	__rrr_config_ignore_spaces(pos);


	if (__rrr_config_check_eof(pos)) {
		return 0;
	}

	const char c = pos->data[pos->pos];

	if (++pos->pos < pos->size) {
		if (c == '#') {
			__rrr_config_parse_comment(pos);
		}
		else if (c == '[') {
			int did_parse;
			ret = __rrr_config_parse_instance(config, pos, &did_parse);
			if (did_parse == 0 && ret == 0) {
				// No more instances, no errors
			}
			else if (ret == 1) {
				// Error occured
			}
		}
		else {
			VL_MSG_ERR("Syntax error in config file at line %d, unexpected '%c'\n", pos->line, c);
			ret = 1;
		}
	}
	else {
		VL_MSG_ERR("Syntax error at end of file (line %d)\n", pos->line);
		ret = 1;
	}

	return ret;
}

int __rrr_config_parse_file (struct rrr_config *config, const void *data, const int size) {
	int ret = 0;

	struct parse_pos pos;

	pos.data = data;
	pos.pos = 0;
	pos.size = size;
	pos.line = 1;

	while (!__rrr_config_check_eof(&pos)) {
		ret = __rrr_config_parse_any(config, &pos);
		if (ret != 0) {
			VL_MSG_ERR("Error in configuration file\n");
			break;
		}
	}

	return ret;
}

struct rrr_instance_config *rrr_config_find_instance (struct rrr_config *source, const char *name) {
	struct rrr_instance_config *ret = NULL;

	for (int i = 0; i < source->module_count; i++) {
		struct rrr_instance_config *test = source->configs[i];
		if (strcmp(test->name, name) == 0) {
			ret = test;
			break;
		}
	}

	return ret;
}

void rrr_config_destroy (struct rrr_config *target) {
	for (int i = 0; i < target->module_count; i++) {
		rrr_config_destroy_instance_config(target->configs[i]);
	}
	free(target->configs);
	free(target);
}

struct rrr_config *rrr_config_parse_file (const char *filename) {
	struct rrr_config *ret = __rrr_config_new();
	int err = 0;

	if (ret == NULL) {
		err = 1;
		goto out;
	}

	FILE *cfgfile = fopen(filename, "r");

	if (cfgfile == NULL) {
		VL_MSG_ERR("Could not open configuration file %s: %s\n", filename, strerror(errno));
		err = 1;
		goto out;
	}

	fseek(cfgfile, 0L, SEEK_END);
	long int size = ftell(cfgfile);

	if (size > RRR_CONFIG_MAX_SIZE) {
		VL_MSG_ERR("Configuration file %s was too big (%li > %d)\n", filename, size, RRR_CONFIG_MAX_SIZE);
		err = 1;
		goto out_close;
	}

	fseek(cfgfile, 0L, 0);

	void *file_data = malloc(size);
	if (file_data == NULL) {
		VL_MSG_ERR("Could not allocate memory for configuration file\n");
		err = 1;
		goto out_close;
	}

	size_t bytes = fread(file_data, 1, size, cfgfile);
	if (bytes != size) {
		VL_MSG_ERR("The whole configuration file was not read (result %lu): %s\n", bytes, strerror(ferror(cfgfile)));
		err = 1;
		goto out_free;
	}

	VL_DEBUG_MSG_1("Read %li bytes from configuration file\n", size);

	err = __rrr_config_parse_file(ret, file_data, size);

	out_free:
	free(file_data);

	out_close:
	fclose(cfgfile);

	out:
	if (err == 1) {
		if (ret != NULL) {
			rrr_config_destroy(ret);
			ret = NULL;
		}
	}

	return ret;
}

