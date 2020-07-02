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

#ifndef RRR_INSTANCE_CONFIG_H
#define RRR_INSTANCE_CONFIG_H

#include "../global.h"
#include "settings.h"

#define RRR_INSTANCE_CONFIG_IF_EXISTS_THEN(string, then)													\
	do { if ( rrr_instance_config_setting_exists(config, string)) { then;									\
	}} while (0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(string, target, default_yesno)								\
do {int yesno = default_yesno;																				\
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, string)) != 0) {								\
		if (ret != RRR_SETTING_NOT_FOUND) {																	\
			RRR_MSG_0("Error while parsing %s in instance %s, please use yes or no\n",						\
				string, config->name);																		\
			ret = 1; goto out;																				\
		}																									\
		ret = 0;																							\
	} data->target = (yesno >= 0 ? yesno : default_yesno); } while(0)


#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(string, target)								\
do {if ((ret = rrr_settings_get_string_noconvert_silent(&data->target, config->settings, string)) != 0) {	\
		if (ret != RRR_SETTING_NOT_FOUND) {																	\
			RRR_MSG_0("Error while parsing setting %s in instance %s\n", string, config->name);				\
			ret = 1; goto out;																				\
		} ret = 0;																							\
	} else {																								\
		if (rrr_utf8_validate(data->target, strlen(data->target)) != 0) {									\
			RRR_MSG_0("Setting %s in instance %s was not valid UTF-8\n", string, config->name);				\
			ret = 1; goto out;																				\
		}																									\
	}} while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(string, target, default_uint)							\
do {rrr_setting_uint tmp_uint = (default_uint);																\
	if ((ret = rrr_instance_config_read_unsigned_integer(&tmp_uint, config, string)) != 0) {				\
		if (ret == RRR_SETTING_NOT_FOUND) {																	\
			tmp_uint = default_uint;																		\
			ret = 0;																						\
		} else {																							\
			RRR_MSG_0("Could not parse setting %s of instance %s\n", string, config->name);					\
			ret = 1; goto out;																				\
		}																									\
	} data->target = tmp_uint; } while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT(string, target, default_uint)								\
do {RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(string, target, default_uint);								\
	if (data->target < 1 || data->target > 65535) {															\
		RRR_MSG_0("Invalid port number %u for setting %s of instance %s, must be in the range 1-65535",		\
			data->target, string, config->name);															\
		ret = 1; goto out;																					\
	}} while(0)

struct rrr_array;
struct rrr_map;

struct rrr_instance_config {
	char *name;
	struct rrr_instance_settings *settings;
};

static inline int rrr_instance_config_setting_exists (
		struct rrr_instance_config *source,
		const char *name
) {
	return rrr_settings_exists(source->settings, name);
}

static inline int rrr_instance_config_get_string_noconvert (
		char **target,
		struct rrr_instance_config *source,
		const char *name
) {
	return rrr_settings_get_string_noconvert(target, source->settings, name);
}

static inline int rrr_instance_config_get_string_noconvert_silent (
		char **target,
		struct rrr_instance_config *source,
		const char *name
) {
	return rrr_settings_get_string_noconvert_silent(target, source->settings, name);
}

static inline int rrr_instance_config_read_unsigned_integer (
		rrr_setting_uint *target,
		struct rrr_instance_config *source,
		const char *name
) {
	return rrr_settings_read_unsigned_integer (target, source->settings, name);
}

static inline int rrr_instance_config_check_yesno (
		int *result,
		struct rrr_instance_config *source,
		const char *name
) {
	return rrr_settings_check_yesno (result, source->settings, name);
}

static inline int rrr_instance_config_traverse_split_commas_silent_fail (
		struct rrr_instance_config *source,
		const char *name,
		int (*callback)(const char *value, void *arg),
		void *arg
) {
	return rrr_settings_traverse_split_commas_silent_fail (source->settings, name, callback, arg);
}

static inline int rrr_instance_config_split_commas_to_array (
		struct rrr_settings_list **target,
		struct rrr_instance_config *source,
		const char *name
) {
	return rrr_settings_split_commas_to_array (target, source->settings, name);
}

static inline int rrr_instance_config_dump (
		struct rrr_instance_config *source
) {
	return rrr_settings_dump (source->settings);
}

void rrr_instance_config_destroy (
		struct rrr_instance_config *config
);

struct rrr_instance_config *rrr_instance_config_new (
		const char *name_begin,
		const int name_length,
		const int max_settings
);

int rrr_instance_config_read_port_number (
		rrr_setting_uint *target,
		struct rrr_instance_config *source,
		const char *name
);

int rrr_instance_config_check_all_settings_used (
		struct rrr_instance_config *config
);

int rrr_instance_config_parse_array_definition_from_config_silent_fail (
		struct rrr_array *target,
		struct rrr_instance_config *config,
		const char *cmd_key
);

int rrr_instance_config_parse_comma_separated_associative_to_map (
		struct rrr_map *target,
		struct rrr_instance_config *config,
		const char *cmd_key,
		const char *delimeter
);

int rrr_instance_config_parse_comma_separated_to_map (
		struct rrr_map *target,
		struct rrr_instance_config *config,
		const char *cmd_key
);

#endif /* RRR_INSTANCE_CONFIG_H */
