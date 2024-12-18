/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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
#include "util/linked_list.h"
#include "util/rrr_time.h"

#define RRR_INSTANCE_CONFIG_PREFIX_BEGIN(prefix)                                                            \
    do { const char *__prefix = prefix; char *config_string = NULL

// Define the out: here to make sure we free upon errors, user must remove existing out: label
#define RRR_INSTANCE_CONFIG_PREFIX_END()                                                                    \
    out:                                                                                                    \
    RRR_FREE_IF_NOT_NULL(config_string); } while(0)

#define RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX(name_,suffix)                                            \
    do {if (rrr_instance_config_string_set(&config_string, __prefix, name_, suffix) != 0) {                 \
        RRR_MSG_0("Could not generate config string from prefix in instance %s\n", config->name);           \
        ret = 1; goto out;                                                                                  \
    }} while(0)

#define RRR_INSTANCE_CONFIG_STRING_SET(name)                                                                \
    RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX(name,NULL)

#define RRR_INSTANCE_CONFIG_SET_USED(name)                                                                  \
    do { rrr_instance_config_set_used(config, name); } while (0)

#define RRR_INSTANCE_CONFIG_IF_EXISTS_THEN(string, then)                                                    \
    do { if ( rrr_instance_config_setting_exists(config, string)) { then;                                   \
    }} while (0)

#define RRR_INSTANCE_CONFIG_IF_NOT_EXISTS_THEN(string, then)                                                \
    do { if (!rrr_instance_config_setting_exists(config, string)) { then;                                   \
    }} while (0)

#define RRR_INSTANCE_CONFIG_EXISTS(string) \
    rrr_instance_config_setting_exists(config, string)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(string, target, default_yesno)                             \
do {int yesno = default_yesno;                                                                              \
    if ((ret = rrr_instance_config_check_yesno(&yesno, config, string)) != 0) {                             \
        if (ret != RRR_SETTING_NOT_FOUND) {                                                                 \
            RRR_MSG_0("Error while parsing %s in instance %s, please use yes or no\n",                      \
                string, config->name);                                                                      \
            ret = 1; goto out;                                                                              \
        }                                                                                                   \
        ret = 0;                                                                                            \
    } data->target = (yesno >= 0 ? yesno : default_yesno); } while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(string, target, def)                                        \
do {if ((ret = rrr_instance_config_parse_optional_utf8(&data->target, config, string, def)) != 0) {         \
        goto out;                                                                                           \
    }} while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC(string, target, target_len)                                \
do {if ((ret = rrr_instance_config_parse_optional_topic_and_length(&data->target, &data->target_len, config, string)) != 0) { \
        goto out;                                                                                           \
    }} while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC_FILTER(string, target)                                     \
do {if ((ret = rrr_instance_config_parse_optional_topic_filter(&data->target, NULL, config, string)) != 0) {\
        goto out;                                                                                           \
    }} while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(string, target)                                \
    RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(string, target, NULL)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED_RAW(string, target, default_uint)                       \
do {rrr_setting_uint tmp_uint = (default_uint);                                                             \
    if ((ret = rrr_instance_config_read_unsigned_integer(&tmp_uint, config, string)) != 0) {                \
        if (ret == RRR_SETTING_NOT_FOUND) {                                                                 \
            tmp_uint = default_uint;                                                                        \
            ret = 0;                                                                                        \
        } else {                                                                                            \
            RRR_MSG_0("Could not parse setting %s of instance %s\n", string, config->name);                 \
            ret = 1; goto out;                                                                              \
        }                                                                                                   \
    } target = tmp_uint; } while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(string, target, default_uint)                           \
    RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED_RAW(string, data->target, default_uint)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_MS(string, target, default_ms)                                   \
do {rrr_time_ms_t tmp_time_ms;                                                                              \
    RRR_ASSERT(sizeof(tmp_time_ms.ms) >= sizeof(rrr_setting_uint),size_of_rrr_time_ms_t_ms_must_be_at_least_size_of_rrr_setting_uint); \
    RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED_RAW(string, tmp_time_ms.ms, default_ms.ms);                 \
    data->target = rrr_time_us_from_ms(tmp_time_ms);                                                        \
    } while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_DOUBLE_RAW(string, target, default_double)                       \
do {rrr_setting_double tmp_double = (default_double);                                                       \
    if ((ret = rrr_instance_config_read_double(&tmp_double, config, string)) != 0) {                        \
        if (ret == RRR_SETTING_NOT_FOUND) {                                                                 \
            tmp_double = default_double;                                                                    \
            ret = 0;                                                                                        \
        } else {                                                                                            \
            RRR_MSG_0("Could not parse setting %s of instance %s\n", string, config->name);                 \
            ret = 1; goto out;                                                                              \
        }                                                                                                   \
    } target = tmp_double; } while(0)

#define RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_DOUBLE(string, target, default_double)                           \
    RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_DOUBLE_RAW(string, data->target, default_double)

enum rrr_instance_config_write_method {
	RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE,
	RRR_INSTANCE_CONFIG_WRITE_METHOD_RRR_MESSAGE,
	RRR_INSTANCE_CONFIG_WRITE_METHOD_ARRAY_VALUES
};

struct rrr_array;
struct rrr_array_tree;
struct rrr_discern_stack_collection;
struct rrr_map;
struct rrr_instance_friend_collection;
struct rrr_instance_collection;
struct rrr_instance;
struct rrr_mqtt_topic_token;

struct rrr_instance_config_data {
	RRR_LL_NODE(struct rrr_instance_config_data);
	char *name;
	struct rrr_settings *settings;
	struct rrr_settings_used settings_used;
	const struct rrr_array_tree_list *global_array_trees;
	const struct rrr_discern_stack_collection *global_routes;
	const struct rrr_discern_stack_collection *global_methods;
};

struct rrr_instance_config_collection {
	RRR_LL_HEAD(struct rrr_instance_config_data);
	struct rrr_config *config;
};

static inline int rrr_instance_config_replace_string (
		struct rrr_instance_config_data *target,
		const char *name,
		const char *value
) {
	return rrr_settings_replace_string(target->settings, name, value);
}

static inline int rrr_instance_config_setting_exists (
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_exists(&source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_get_string_noconvert (
		char **target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_get_string_noconvert(target, &source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_get_string_noconvert_silent (
		char **target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_get_string_noconvert_silent(target, &source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_read_unsigned_integer (
		rrr_setting_uint *target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_read_unsigned_integer (target, &source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_read_double (
		rrr_setting_double *target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_read_double (target, &source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_check_yesno (
		int *result,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_check_yesno (result, &source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_traverse_split_commas_silent_fail (
		struct rrr_instance_config_data *source,
		const char *name,
		int (*callback)(const char *value, void *arg),
		void *arg
) {
	return rrr_settings_traverse_split_commas_silent_fail (&source->settings_used, source->settings, name, callback, arg);
}

static inline int rrr_instance_config_split_commas_to_array (
		struct rrr_settings_list **target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return rrr_settings_split_commas_to_array (target, &source->settings_used, source->settings, name);
}

static inline int rrr_instance_config_collection_count (
		struct rrr_instance_config_collection *collection
) {
	return RRR_LL_COUNT(collection);
}

static inline void rrr_instance_config_set_used (
		struct rrr_instance_config_data *source,
		const char *name
) {
	rrr_settings_set_used(&source->settings_used, source->settings, name);
}

static inline void rrr_instance_config_set_unused (
		struct rrr_instance_config_data *source,
		const char *name
) {
	rrr_settings_set_unused(&source->settings_used, source->settings, name);
}

void rrr_instance_config_move_from_settings (
		struct rrr_instance_config_data *config,
		struct rrr_settings_used *settings_used,
		struct rrr_settings **settings
);
void rrr_instance_config_move_to_settings (
		struct rrr_settings_used *settings_used,
		struct rrr_settings **settings,
		struct rrr_instance_config_data *config
);
void rrr_instance_config_update_used (
		struct rrr_instance_config_data *config,
		const char *name,
		int was_used
);
int rrr_instance_config_string_set (
		char **target,
		const char *prefix,
		const char *name,
		const char *suffix
);
void rrr_instance_config_collection_destroy (
		struct rrr_instance_config_collection *configs
);
int rrr_instance_config_read_optional_port_number (
		uint16_t *target,
		struct rrr_instance_config_data *source,
		const char *name
);
int rrr_instance_config_read_port_number (
		uint16_t *target,
		struct rrr_instance_config_data *source,
		const char *name
);
int rrr_instance_config_check_all_settings_used (
		struct rrr_instance_config_data *config
);
void rrr_instance_config_verify_all_settings_used (
		struct rrr_instance_config_data *config
);
int rrr_instance_config_parse_array_tree_definition_from_config_silent_fail (
		struct rrr_array_tree **target_array_tree,
		struct rrr_instance_config_data *config,
		const char *cmd_key
);
int rrr_instance_config_parse_route_definition_from_config_silent_fail (
		struct rrr_discern_stack_collection *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key
);
int rrr_instance_config_parse_method_definition_from_config_silent_fail (
		struct rrr_discern_stack_collection *target,
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
int rrr_instance_config_parse_optional_write_method (
		struct rrr_map *array_values,
		enum rrr_instance_config_write_method *method,
		struct rrr_instance_config_data *config,
		const char *string_write_rrr_message,
		const char *string_array_values
);
int rrr_instance_config_parse_optional_utf8 (
		char **target,
		struct rrr_instance_config_data *config,
		const char *string,
		const char *def
);
int rrr_instance_config_parse_optional_topic_and_length (
		char **target,
		uint16_t *target_length,
		struct rrr_instance_config_data *config,
		const char *string
);
int rrr_instance_config_parse_optional_topic_filter (
		struct rrr_mqtt_topic_token **target,
		char **target_str,
		struct rrr_instance_config_data *config,
		const char *string
);
int rrr_instance_config_dump (
		struct rrr_instance_config_collection *collection
);
int rrr_instance_config_parse_file (
		struct rrr_instance_config_collection **result,
		const char *filename
);
int rrr_instance_config_friend_collection_populate_from_config (
		struct rrr_instance_friend_collection *target,
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_data *config,
		const char *setting
);
int rrr_instance_config_friend_collection_populate_receivers_from_config (
		struct rrr_instance_friend_collection *target,
		struct rrr_instance_collection *instances_all,
		const struct rrr_instance *instance,
		struct rrr_instance_config_data *config,
		const char *setting
);

#endif /* RRR_INSTANCE_CONFIG_H */
