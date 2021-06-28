/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include "settings.h"

#define RRR_INSTANCE_CONFIG_PREFIX_BEGIN(prefix)															\
	do { const char *__prefix = prefix; char *config_string = NULL

// Define the out: here to make sure we free upon errors, user must remove existing out: label
#define RRR_INSTANCE_CONFIG_PREFIX_END()																	\
	out:																									\
	RRR_FREE_IF_NOT_NULL(config_string); } while(0)

#define RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX(name_,suffix)											\
	do {if (rrr_instance_config_string_set(&config_string, __prefix, name_, suffix) != 0) {					\
		RRR_MSG_0("Could not generate config string from prefix in instance %s\n", config->name);			\
		ret = 1; goto out;																					\
	}} while(0)

#define RRR_INSTANCE_CONFIG_STRING_SET(name)																\
	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX(name,NULL)

#define RRR_INSTANCE_CONFIG_IF_EXISTS_THEN(string, then)													\
	do { if ( rrr_instance_config_setting_exists(config, string)) { then;									\
	}} while (0)

#define RRR_INSTANCE_CONFIG_IF_NOT_EXISTS_THEN(string, then)												\
	do { if (!rrr_instance_config_setting_exists(config, string)) { then;									\
	}} while (0)

#define RRR_INSTANCE_CONFIG_EXISTS(string) \
	rrr_instance_config_setting_exists(config, string)

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

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(string, target, def)										\
do {if ((ret = rrr_instance_config_parse_optional_utf8(&data->target, config, string, def)) != 0) {			\
		goto out;																							\
	}} while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(string, target)								\
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(string, target, NULL)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED_RAW(string, target, default_uint)							\
do {rrr_setting_uint tmp_uint = (default_uint);																\
	if ((ret = rrr_instance_config_read_unsigned_integer(&tmp_uint, config, string)) != 0) {				\
		if (ret == RRR_SETTING_NOT_FOUND) {																	\
			tmp_uint = default_uint;																		\
			ret = 0;																						\
		} else {																							\
			RRR_MSG_0("Could not parse setting %s of instance %s\n", string, config->name);					\
			ret = 1; goto out;																				\
		}																									\
	} target = tmp_uint; } while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(string, target, default_uint)							\
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED_RAW(string, data->target, default_uint)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT(string, target, default_uint)								\
do {RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(string, target, default_uint);								\
	if (data->target < 1 || data->target > 65535) {															\
		RRR_MSG_0("Invalid port number %" PRIrrrbl " for setting %s of instance %s, must be in the range 1-65535",	\
			data->target, string, config->name);															\
		ret = 1; goto out;																					\
	}} while(0)

struct rrr_array;
struct rrr_array_tree;
struct rrr_map;

struct rrr_instance_config_data {
	char *name;
	struct rrr_instance_settings *settings;
	const struct rrr_array_tree_list *global_array_trees;
};

static inline int rrr_instance_config_setting_exists (
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_exists(source->settings, name);
}

static inline int rrr_instance_config_get_string_noconvert (
		char **target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_get_string_noconvert(target, source->settings, name);
}

static inline int rrr_instance_config_get_string_noconvert_silent (
		char **target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_get_string_noconvert_silent(target, source->settings, name);
}

static inline int rrr_instance_config_read_unsigned_integer (
		rrr_setting_uint *target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_read_unsigned_integer (target, source->settings, name);
}

static inline int rrr_instance_config_check_yesno (
		int *result,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_check_yesno (result, source->settings, name);
}

static inline int rrr_instance_config_traverse_split_commas_silent_fail (
		struct rrr_instance_config_data *source,
		const char *name,
		int (*callback)(const char *value, void *arg),
		void *arg
) {
	return rrr_settings_traverse_split_commas_silent_fail (source->settings, name, callback, arg);
}

static inline int rrr_instance_config_split_commas_to_array (
		struct rrr_settings_list **target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_split_commas_to_array (target, source->settings, name);
}

static inline int rrr_instance_config_dump (
		struct rrr_instance_config_data *source
) {
	return rrr_settings_dump (source->settings);
}

int rrr_instance_config_string_set (
		char **target,
		const char *prefix,
		const char *name,
		const char *suffix
);
void rrr_instance_config_destroy (
		struct rrr_instance_config_data *config
);
struct rrr_instance_config_data *rrr_instance_config_new (
		const char *name_begin,
		const int name_length,
		const int max_settings,
		const struct rrr_array_tree_list *global_array_trees
);
int rrr_instance_config_read_port_number (
		rrr_setting_uint *target,
		struct rrr_instance_config_data *source,
		const char *name
);
int rrr_instance_config_check_all_settings_used (
		struct rrr_instance_config_data *config
);
int rrr_instance_config_parse_array_tree_definition_from_config_silent_fail (
		struct rrr_array_tree **target_array_tree,
		struct rrr_instance_config_data *config,
		const char *cmd_key
);
int rrr_instance_config_parse_comma_separated_associative_to_map (
		struct rrr_map *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key,
		const char *delimeter
);
int rrr_instance_config_parse_comma_separated_to_map (
		struct rrr_map *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key
);
int rrr_instance_config_parse_optional_utf8 (
		char **target,
		struct rrr_instance_config_data *config,
		const char *string,
		const char *def
);

#endif /* RRR_INSTANCE_CONFIG_H */
