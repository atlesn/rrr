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

#define RRR_CONFIGFILE_DEBUG

struct parse_pos {
	const char *data;
	int pos;
	int size;
	int line;
};

void __config_ignore_spaces (struct parse_pos *pos) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

#ifdef RRR_CONFIGFILE_DEBUG
	printf("Parsing spaces pos %d: ", pos->pos);
#endif

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

#ifdef RRR_CONFIGFILE_DEBUG
		printf(".");
#endif

		pos->pos++;
		if (pos->pos >= pos->size) {
			break;
		}

		pos->data[pos->pos];
		c = pos->data[pos->pos];
	}
#ifdef RRR_CONFIGFILE_DEBUG
	printf("\n");
#endif
}

void __config_parse_comment (struct parse_pos *pos) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

#ifdef RRR_CONFIGFILE_DEBUG
	printf("Parsing comment: ");
#endif

	while (c != '\r' && c != '\n' && pos->pos < pos->size) {
#ifdef RRR_CONFIGFILE_DEBUG
		printf ("%c", c);
#endif
		pos->pos++;
		pos->data[pos->pos];
		c = pos->data[pos->pos];
	}

#ifdef RRR_CONFIGFILE_DEBUG
	printf("\n");
#endif

	__config_ignore_spaces(pos);
}

void __config_destroy_module_config(struct rrr_module_config *config) {
	rrr_settings_destroy(config->settings);
	free(config->name);
	free(config);
}

struct rrr_module_config *__config_new_module_config (const char *name_begin, const int name_length) {
	struct rrr_module_config *ret = NULL;

	char *name = malloc(name_length + 1);
	if (name == NULL) {
		VL_MSG_ERR("Could not allocate memory for name in __config_new_module_config");
		goto out;
	}

	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory for name in __config_new_module_config");
		goto out_free_name;
	}

	memcpy(name, name_begin, name_length);
	name[name_length] = '\0';

	ret->name = name;
	ret->settings = rrr_settings_new(RRR_CONFIG_MAX_SETTINGS);
	if (ret->settings == NULL) {
		VL_MSG_ERR("Could not create settings structure in __config_new_module_config");
		goto out_free_config;
	}


	goto out;

	out_free_config:
	free(ret);
	ret = NULL;

	out_free_name:
	free(name);

	out:
	return ret;
}

void __config__parse_letters (struct parse_pos *pos, int *start, int *end, int allow_space_tab) {
	*start = pos->pos;
	*end = pos->pos;

	char c = pos->data[pos->pos];
	while (pos->pos < pos->size) {
		if (	(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '_' ||
				c == '-' ||
				(allow_space_tab && (c == ' ' || c == '\t'))
		) {
			// OK
		}
		else {
			break;
		}

		pos->pos++;
		if (pos->pos >= pos->size) {
			break;
		}
		c = pos->data[pos->pos];
	}

	*end = pos->pos - 1;
}

int __config_extract_string (char **target, struct parse_pos *pos, const int pos, const int length) {

}

int __config_parse_setting (struct parse_pos *pos, struct rrr_module_config *config, int *did_parse) {
	int ret = 0;

	*did_parse = 0;

	__config_ignore_spaces(pos);

	if (pos->pos >= pos->size) {
		return 1;
	}

	char c;
	int name_begin;
	int name_end;
	__config_parse_letters(pos, &name_begin, &name_end, 0);

	if (name_end == name_begin) {
		VL_MSG_ERR("Expected setting name at line %d\n", pos->line);
		return 1;
	}

	__config_ignore_spaces(pos);
	if (pos->pos >= pos->size) {
		VL_MSG_ERR("Unexpected end of file after setting name at line %d\n", pos->line);
		return 1;
	}

	c = pos->data[pos->pos];
	if (c != '=') {
		VL_MSG_ERR("Expected = after setting name at line %d, found %c\n", pos->line, c);
		return 1;
	}

	__config_ignore_spaces(pos);
	if (pos->pos >= pos->size) {
		VL_MSG_ERR("Unexpected end of file after = at line %d\n", pos->line);
		return 1;
	}

	int value_begin;
	int value_end;
	__config_parse_letters(pos, &value_begin, &value_end, 1);

	if (value_begin == value_end) {
		VL_MSG_ERR("Expected value after = at line %d\n", pos->line);
		return 1;
	}

	int name_length = name_end - name_begin + 1;
	int value_length = value_end - value_begin + 1;

	char *name = malloc(name_length + 1);
	char *value = malloc(value_length + 1);

	memcpy(name, pos->data + name_begin, name_length);
	memcpy(value, pos->data + value_begin, value_length);

	name[name_length] = '\0';
	value[value_length] = '\0';

	if (rrr_settings_add_string(config, name, value) != 0) {
		ret = 1;
	}

	free(value);
	free(name);

	return ret;
}

int __config_parse_module (struct parse_pos *pos) {
	int ret = 0;

#ifdef RRR_CONFIGFILE_DEBUG
	printf("Parsing module: ");
#endif

	int begin = pos->pos;

	if (pos->pos >= pos->size) {
		VL_MSG_ERR("Unexpected end of module definition at line %d\n", pos->line);
		return 1;
	}

	char c = pos->data[pos->pos];
	while (c != ']' && pos->pos < pos->size) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			printf("%c", c);
		}
		else {
			VL_MSG_ERR("Unexpected character '%c' in module definition in line %d\n", c, pos->line);
			ret = 1;
			goto out;
		}

		pos->pos++;

		if (pos->pos >= pos->size) {
			break;
		}

		c = pos->data[pos->pos];
	}

	if (pos->pos >= pos->size) {
		VL_MSG_ERR("Unexpected end of module definition in line %d\n", pos->line);
		ret = 1;
		goto out;
	}

	c = pos->data[pos->pos];
	if (c != ']') {
		VL_MSG_ERR("Syntax error in module definition in line %d, possibly missing ]\n", pos->line);
		ret = 1;
		goto out;
	}

	int end = pos->pos - 1;
	int length = end - begin + 1;

	pos->pos++;

	if (end < begin) {
		VL_MSG_ERR("Module name at line %d was too short\n", pos->line);
		ret = 1;
		goto out;
	}

	struct rrr_module_config *config = __config_new_module_config(pos->data + begin, length);
	if (config == NULL) {
		ret = 1;
		goto out;
	}

	while (__config_parse_setting(pos, config) == 0) {
#ifdef RRR_CONFIGFILE_DEBUG
		printf("Parsed a setting at line %d\n", pos->line);
#endif
	}

#ifdef RRR_CONFIGFILE_DEBUG
	printf("\nDumping settings for module %s:\n", config->name);
#endif
	rrr_settings_dump(config->settings);

	out_free_config:
	__config_destroy_module_config(config);

	out:
	return ret;
}

int __config_parse_any (struct parse_pos *pos) {
	int ret = 0;

#ifdef RRR_CONFIGFILE_DEBUG
	printf("Parsing any pos %d size %d data %08x:\n", pos->pos, pos->size, (unsigned int) pos->data);
#endif

	__config_ignore_spaces(pos);


	if (pos->pos >= pos->size) {
		return 0;
	}

	const char c = pos->data[pos->pos];

	if (++pos->pos < pos->size) {
		if (c == '#') {
			__config_parse_comment(pos);
		}
		else if (c == '[') {
			ret = __config_parse_module(pos);
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

int __config_parse_file (const void *data, const int size) {
	int ret = 0;

	struct parse_pos pos;

	pos.data = data;
	pos.pos = 0;
	pos.size = size;
	pos.line = 1;

	while (pos.pos < size) {
		ret = __config_parse_any(&pos);
		if (ret != 0) {
			break;
		}
	}

	return ret;
}

int config_parse_file (const char *filename) {
	int ret = 0;
	FILE *cfgfile = fopen(filename, "r");

	if (cfgfile == NULL) {
		VL_MSG_ERR("Could not open configuration file %s: %s\n", filename, strerror(errno));
		ret = 1;
		goto out;
	}

	fseek(cfgfile, 0L, SEEK_END);
	long int size = ftell(cfgfile);

	if (size > RRR_CONFIG_MAX_SIZE) {
		VL_MSG_ERR("Configuration file %s was too big (%li > %d)\n", filename, size, RRR_CONFIG_MAX_SIZE);
		ret = 1;
		goto out_close;
	}

	fseek(cfgfile, 0L, 0);

	void *file_data = malloc(size);
	if (file_data == NULL) {
		VL_MSG_ERR("Could not allocate memory for configuration file\n");
		ret = 1;
		goto out_close;
	}

	size_t bytes = fread(file_data, 1, size, cfgfile);
	if (bytes != size) {
		VL_MSG_ERR("The whole configuration file was not read (result %lu): %s\n", bytes, strerror(ferror(cfgfile)));
		ret = 1;
		goto out_free;
	}

	VL_DEBUG_MSG_1("Read %li bytes from configuration file\n", size);

	ret = __config_parse_file(file_data, size);

	out_free:
	free(file_data);

	out_close:
	fclose(cfgfile);

	out:
	return ret;
}
