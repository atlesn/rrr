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

#include "parse.h"
#include "log.h"
#include "configuration.h"
#include "rrr_strerror.h"
#include "array_tree.h"

#include "instance_config.h"

struct rrr_config *__rrr_config_new (void) {
	struct rrr_config *ret = malloc(sizeof(*ret));

	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory for rrr_config struct\n");
		return NULL;
	}

	memset(ret, '\0', sizeof(*ret));

	return ret;
}

int __rrr_config_expand(struct rrr_config *target) {
	int old_size = target->module_count_max * sizeof(*target->configs);
	int new_size = old_size + (RRR_CONFIG_ALLOCATION_INTERVAL * sizeof(*target->configs));
	int new_max = target->module_count_max + RRR_CONFIG_ALLOCATION_INTERVAL;

	struct rrr_instance_config_data **configs_new = realloc(target->configs, new_size);

	if (configs_new == NULL) {
		RRR_MSG_0("Could not reallocate memory for rrr_instance_config struct\n");
		return 1;
	}

	target->configs = configs_new;
	target->module_count_max = new_max;

	return 0;
}

int __rrr_config_push (struct rrr_config *target, struct rrr_instance_config_data *instance_config) {
	if (rrr_config_find_instance (target, instance_config->name) != NULL) {
		RRR_MSG_0("Two instances was named %s\n", instance_config->name);
		return 1;
	}

	if (target->module_count == target->module_count_max) {
		if (__rrr_config_expand(target) != 0) {
			RRR_MSG_0("Could not push new config struct\n");
			return 1;
		}
	}

	target->configs[target->module_count] = instance_config;
	target->module_count++;

	return 0;
}

int __rrr_config_parse_setting (struct rrr_parse_pos *pos, struct rrr_instance_settings *settings, int *did_parse) {
	int ret = 0;

	char c;
	int name_begin;
	int name_end;

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

	rrr_parse_match_letters (
			pos,
			&name_begin,
			&name_end,
			RRR_PARSE_MATCH_NUMBERS|RRR_PARSE_MATCH_LETTERS
	);

	if (name_end < name_begin) {
		ret = 0;
		goto out;
	}

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file after setting name at line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	c = pos->data[pos->pos];
	if (c != '=') {
		RRR_MSG_0("Expected = after setting name at line %d, found %c\n", pos->line, c);
		ret = 1;
		goto out;
	}

	int line_orig = pos->line;

	pos->pos++;
	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file after = at line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	if (pos->line != line_orig) {
		RRR_MSG_0("Unexpected newline after = at line %d, parameter value missing\n", pos->line);
		ret = 1;
		goto out;
	}

	int value_begin;
	int value_end;
	rrr_parse_non_newline(pos, &value_begin, &value_end);

	// Ignore trailing spaces
	while (value_end > value_begin && (pos->data[value_end] == ' ' || pos->data[value_end] == '\t')) {
			value_end--;
	}

	if (value_end < value_begin) {
		RRR_MSG_0("Expected value after = at line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	int name_length = name_end - name_begin + 1;
	int value_length = value_end - value_begin + 1;

	if (rrr_parse_extract_string(&name, pos, name_begin, name_length) != 0) {
		RRR_MSG_0("Could not extract setting name\n");
		ret = 1;
		goto out;
	}

	if (rrr_parse_extract_string(&value, pos, value_begin, value_length) != 0) {
		RRR_MSG_0("Could not extract setting name\n");
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

int __rrr_config_parse_instance (struct rrr_config *config, struct rrr_parse_pos *pos, int *did_parse) {
	int ret = 0;
	*did_parse = 0;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (pos->pos >= pos->size) {
		ret = 0;
		goto out;
	}

	int begin = pos->pos;

	if (pos->pos >= pos->size) {
		RRR_MSG_0("Unexpected end of instance definition at line %d\n", pos->line);
		return 1;
	}

	char c = pos->data[pos->pos];
	while (c != ']' && !RRR_PARSE_CHECK_EOF(pos)) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			// These are ok
		}
		else {
			RRR_MSG_0("Unexpected character '%c' in instance definition in line %d\n", c, pos->line);
			ret = 1;
			goto out;
		}

		pos->pos++;

		if (pos->pos >= pos->size) {
			break;
		}

		c = pos->data[pos->pos];
	}

	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of instance definition in line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	c = pos->data[pos->pos];
	if (c != ']') {
		RRR_MSG_0("Syntax error in instance definition in line %d, possibly missing ]\n", pos->line);
		ret = 1;
		goto out;
	}

	int end = pos->pos - 1;
	int length = end - begin + 1;

	pos->pos++;

	if (end < begin) {
		RRR_MSG_0("Instance name at line %d was too short\n", pos->line);
		ret = 1;
		goto out;
	}

	struct rrr_instance_config_data *instance_config = rrr_instance_config_new(pos->data + begin, length, RRR_CONFIG_MAX_SETTINGS);
	if (instance_config == NULL) {
		RRR_MSG_0("Instance config creation result was NULL\n");
		ret = 1;
		goto out;
	}

	int did_parse_setting;
	while ((ret = __rrr_config_parse_setting(pos, instance_config->settings, &did_parse_setting)) == 0) {
		if (did_parse_setting != 1) {
			break;
		}
		else {
			rrr_parse_ignore_spaces_and_increment_line(pos);
		}
	}

	if (ret == 1) {
		RRR_MSG_0("Settings parsing failed for instance %s at line %d\n", instance_config->name, pos->line);
		*did_parse = 0;
	}

/*	if (RRR_DEBUGLEVEL_1) {
		RRR_MSG_1("\nDumping settings for instance %s:\n", instance_config->name);
		rrr_settings_dump(instance_config->settings);
	}*/

	if (ret == 0) {
		*did_parse = 1;
	}

	if (ret == 0) {
		ret = __rrr_config_push(config, instance_config);
		if (ret != 0) {
			RRR_MSG_0("Could not save instance %s to global config\n", instance_config->name);
		}
	}

	if (ret != 0) {
		rrr_instance_config_destroy(instance_config);
	}

	out:
	return ret;
}

int __rrr_config_parse_array_tree (struct rrr_config *config, struct rrr_parse_pos *pos) {
	int ret = 0;

	struct rrr_array_tree *new_tree = NULL;
	char *name_tmp = NULL;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		goto out_missing_name;
	}

	int start;
	int end;

	rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_LETTERS);

	if (end < start) {
		goto out_missing_name;
	}

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos) || *(pos->data + pos->pos) != '}') {
		goto out_missing_end_curly;
	}
	pos->pos++;

	size_t name_length = end - start + 1;
	if ((name_tmp = malloc(name_length + 1)) == NULL) {
		goto out_failed_alloc;
	}

	memcpy(name_tmp, pos->data + start, name_length);
	name_tmp[name_length] = '\0';

	if (rrr_array_tree_parse (
			&new_tree,
			pos,
			name_tmp
	) != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_array_tree_validate (
			new_tree
	) != 0) {
		RRR_MSG_0("Array tree validation failed while parsing configuration\n");
		ret = 1;
		goto out;
	}

	if (pos->pos > pos->size) {
		RRR_BUG("BUG: rrr_array_tree_parse parsed beyond end in __rrr_config_parse_array_tree\n");
	}

	RRR_LL_APPEND(&config->array_trees, new_tree);
	new_tree = NULL;

	goto out;
	out_failed_alloc:
		RRR_MSG_0("Could not allocate memory for name in __rrr_config_parse_array_tree\n");
		ret = 1;
		goto out;
	out_missing_name:
		RRR_MSG_0("Missing name for array tree after {\n");
		ret = 1;
		goto out;
	out_missing_end_curly:
		RRR_MSG_0("Missing end curly bracket } after array tree name\n");
		ret = 1;
		goto out;
	out:
		if (new_tree != NULL) {
			rrr_array_tree_destroy(new_tree);
		}
		RRR_FREE_IF_NOT_NULL(name_tmp);
		return ret;
}

int __rrr_config_parse_any (struct rrr_config *config, struct rrr_parse_pos *pos) {
	int ret = 0;

	rrr_parse_ignore_spaces_and_increment_line(pos);


	if (RRR_PARSE_CHECK_EOF(pos)) {
		return 0;
	}

	const char c = pos->data[pos->pos];

	if (++pos->pos < pos->size) {
		if (c == '#') {
			rrr_parse_comment(pos);
		}
		else if (c == '{') {
			ret = __rrr_config_parse_array_tree(config, pos);
		}
		else if (c == '[') {
			int did_parse;
			ret = __rrr_config_parse_instance(config, pos, &did_parse);
			if (did_parse == 0 && ret == 0) {
				// XXX : Do we ever end up here?
				// No more instances, no errors
			}
			else if (ret == 1) {
				// Error occured
			}
		}
		else {
			RRR_MSG_0("Syntax error in config file at line %d, unexpected '%c'\n", pos->line, c);
			ret = 1;
		}
	}
	else {
		RRR_MSG_0("Syntax error at end of file (line %d)\n", pos->line);
		ret = 1;
	}

	return ret;
}

int __rrr_config_parse_file (struct rrr_config *config, const void *data, const int size) {
	int ret = 0;

	struct rrr_parse_pos pos;

	rrr_parse_pos_init(&pos, data, size);

	while (!RRR_PARSE_CHECK_EOF(&pos)) {
		ret = __rrr_config_parse_any(config, &pos);
		if (ret != 0) {
			break;
		}
	}

	if (ret != 0) {
		RRR_MSG_0("Parsing of configuration file failed at line %i position %i\n",
				pos.line, pos.pos - pos.line_begin_pos + 1);
	}

	return ret;
}

struct rrr_instance_config_data *rrr_config_find_instance (struct rrr_config *source, const char *name) {
	struct rrr_instance_config_data *ret = NULL;

	for (int i = 0; i < source->module_count; i++) {
		struct rrr_instance_config_data *test = source->configs[i];
		if (strcmp(test->name, name) == 0) {
			ret = test;
			break;
		}
	}

	return ret;
}

void rrr_config_destroy (struct rrr_config *target) {
	for (int i = 0; i < target->module_count; i++) {
		rrr_instance_config_destroy(target->configs[i]);
	}
	rrr_array_tree_list_destroy(&target->array_trees);
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

	// TODO : Use rrr_socket read whole file function

	FILE *cfgfile = fopen(filename, "r");

	if (cfgfile == NULL) {
		RRR_MSG_0("Could not open configuration file %s: %s\n", filename, rrr_strerror(errno));
		err = 1;
		goto out;
	}

	if (fseek(cfgfile, 0L, SEEK_END) != 0) {
		RRR_MSG_0("Could not fseek to the end in configuration file %s: %s\n", filename, rrr_strerror(errno));
		err = 1;
		goto out_close;
	}
	ssize_t size_signed = ftell(cfgfile);
	if (size_signed < 0) {
		RRR_MSG_0("Could not get size of configuration file %s: %s\n", filename, rrr_strerror(errno));
		err = 1;
		goto out_close;
	}

	size_t size = size_signed;
	if (size > RRR_CONFIG_MAX_SIZE) {
		RRR_MSG_0("Configuration file %s was too big (%li > %d)\n", filename, size, RRR_CONFIG_MAX_SIZE);
		err = 1;
		goto out_close;
	}

	if (fseek(cfgfile, 0L, 0) != 0) {
		RRR_MSG_0("Could not fseek to the beginning in configuration file %s: %s\n", filename, rrr_strerror(errno));
		err = 1;
		goto out_close;
	}

	void *file_data = malloc(size);
	if (file_data == NULL) {
		RRR_MSG_0("Could not allocate memory for configuration file\n");
		err = 1;
		goto out_close;
	}

	size_t bytes = fread(file_data, 1, size, cfgfile);
	if (bytes != size) {
		RRR_MSG_0("The whole configuration file was not read (result %lu): %s\n", bytes, rrr_strerror(ferror(cfgfile)));
		err = 1;
		goto out_free;
	}

	RRR_DBG_1("Read %li bytes from configuration file\n", size);

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

int rrr_config_dump (struct rrr_config *config) {
	int ret = 0;
	for (int i = 0; i < config->module_count; i++) {
		struct rrr_instance_config_data *instance_config = config->configs[i];

		RRR_MSG_1("== CONFIGURATION FOR %s BEGIN =============\n", instance_config->name);

		if (rrr_instance_config_dump(instance_config) != 0) {
			ret = 1;
		}

		RRR_MSG_1("== CONFIGURATION FOR %s END ===============\n", instance_config->name);
	}

	if (ret != 0) {
		printf ("Warning: Some error(s) occurred while dumping the configuration, some settings could possibly not be converted to strings\n");
	}

	return ret;
}
