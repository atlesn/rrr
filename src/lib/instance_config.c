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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "log.h"
#include "settings.h"
#include "instance_config.h"
#include "instances.h"
#include "map.h"
#include "array.h"
#include "array_tree.h"
#include "parse.h"
#include "allocator.h"
#include "configuration.h"
#include "util/gnu.h"
#include "util/linked_list.h"
#include "mqtt/mqtt_topic.h"
			
#define RRR_INSTANCE_CONFIG_MAX_SETTINGS 32

void rrr_instance_config_move_from_settings (
		struct rrr_instance_config_data *config,
		struct rrr_settings_used *settings_used,
		struct rrr_settings **settings
) {
	assert(config->settings == NULL);

	memcpy(&config->settings_used, settings_used, sizeof(config->settings_used));
	memset(settings_used, '\0', sizeof(*settings_used));

	config->settings = *settings;
	*settings = NULL;
}

void rrr_instance_config_move_to_settings (
		struct rrr_settings_used *settings_used,
		struct rrr_settings **settings,
		struct rrr_instance_config_data *config
) {
	memcpy(settings_used, &config->settings_used, sizeof(*settings_used));
	memset(&config->settings_used, '\0', sizeof(config->settings_used));

	*settings = config->settings;
	config->settings = NULL;
}

struct rrr_instance_config_update_used_callback_data {
	struct rrr_instance_config_data *config;
	const char *name;
	int was_used;
	int did_update;
};

static int __rrr_instance_config_update_used_callback (
		int *was_used,
		const struct rrr_setting *setting,
		void *callback_args
) {
	struct rrr_instance_config_update_used_callback_data *callback_data = callback_args;

	if (strcmp (setting->name, callback_data->name) == 0) {
		if (*was_used && !callback_data->was_used) {
			RRR_MSG_0("Warning: Setting %s in instace %s was marked as used, but it has changed to not used during configuration\n",
				setting->name, callback_data->config->name);
		}
		*was_used = callback_data->was_used;
		callback_data->did_update = 1;
	}

	return 0;
}

void rrr_instance_config_update_used (
		struct rrr_instance_config_data *config,
		const char *name,
		int was_used
) {
	struct rrr_instance_config_update_used_callback_data callback_data = {
		config,
		name,
		was_used,
		0
	};

	rrr_settings_iterate (
			&config->settings_used,
			config->settings,
			__rrr_instance_config_update_used_callback,
			&callback_data
	);

	if (callback_data.did_update != 1) {
		RRR_MSG_0("Warning: Setting %s in instance %s was not originally set in configuration file, discarding it.\n",
			name, config->name);
	}
}

int rrr_instance_config_string_set (
		char **target,
		const char *prefix,
		const char *name,
		const char *suffix
) {
	RRR_FREE_IF_NOT_NULL(*target);
	if (rrr_asprintf(target, "%s%s%s", prefix, name, (suffix != NULL ? suffix : "")) < 0) {
		RRR_MSG_0("Could not allocate memory in rrr_instance_config_string_set\n");
		return 1;
	}
	return 0;
}

static void __rrr_instance_config_destroy (
		struct rrr_instance_config_data *config
) {
	rrr_settings_used_cleanup(&config->settings_used);
	rrr_settings_destroy(config->settings);
	rrr_free(config->name);
	rrr_free(config);
}

static int __rrr_instance_config_new (
		struct rrr_instance_config_data **result,
		const char *name,
		const rrr_length max_settings,
		const struct rrr_array_tree_list *global_array_trees,
		const struct rrr_discern_stack_collection *global_routes,
		const struct rrr_discern_stack_collection *global_methods
) {
	int ret = 0;

	struct rrr_instance_config_data *instance_config = NULL;

	*result = NULL;

	if ((instance_config = rrr_allocate_zero(sizeof(*instance_config))) == NULL) {
		RRR_MSG_0("Could not allocate memory for name in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((instance_config->name = rrr_strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate memory for name in %s\b", __func__);
		ret = 1;
		goto out_free_config;
	}

	if ((instance_config->settings = rrr_settings_new(max_settings)) == NULL) {
		RRR_MSG_0("Could not create settings structure in %s\n", __func__);
		ret = 1;
		goto out_free_name;
	}

	if ((ret = rrr_settings_used_init(&instance_config->settings_used, instance_config->settings)) != 0) {
		RRR_MSG_0("Could not initialize settings used structure in %s\n", __func__);
		goto out_free_settings;
	}

	instance_config->global_array_trees = global_array_trees;
	instance_config->global_routes = global_routes;
	instance_config->global_methods = global_methods;

	*result = instance_config;

	goto out;
//	out_cleanup_settings_used:
//		rrr_settings_used_cleanup(&instance_config->settings_used);
	out_free_settings:
		rrr_settings_destroy(instance_config->settings);
	out_free_name:
		rrr_free(instance_config->name);
	out_free_config:
		rrr_free(instance_config);
	out:
		return ret;
}

void rrr_instance_config_collection_destroy (
		struct rrr_instance_config_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_instance_config_data, __rrr_instance_config_destroy(node));
	rrr_config_destroy(collection->config);
	free(collection);
}

static int __rrr_instance_config_collection_new (
		struct rrr_instance_config_collection **result
) {
	int ret = 0;

	struct rrr_instance_config_collection *collection = NULL;

	*result = NULL;

	if ((collection = rrr_allocate_zero(sizeof(*collection))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_instance_config_new\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_config_new(&collection->config)) != 0) {
		goto out_free;
	}

	*result = collection;

	goto out;
	out_free:
		rrr_free(collection);
	out:
		return ret;
}

static int __rrr_instance_config_read_port_number (
		uint16_t *target,
		struct rrr_instance_config_data *source,
		const char *name,
		int do_allow_zero,
		int do_allow_not_found
) {
	int ret = 0;

	*target = 0;

	rrr_setting_uint tmp_uint = 0;
	ret = rrr_settings_read_unsigned_integer (&tmp_uint, &source->settings_used, source->settings, name);

	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			char *tmp_string;

			rrr_settings_read_string (&tmp_string, &source->settings_used, source->settings, name); // Ignore error
			RRR_MSG_0("Syntax error in port setting %s. Could not parse '%s' as number.\n",
					name, (tmp_string != NULL ? tmp_string : "")
			);

			RRR_FREE_IF_NOT_NULL(tmp_string);

			ret = 1;
			goto out;
		}
		else if (ret == RRR_SETTING_NOT_FOUND && do_allow_not_found) {
			ret = 0;
			goto out;
		}
	}
	else {
		if ((!do_allow_zero && tmp_uint < 1) || tmp_uint > 65535) {
			RRR_MSG_0 ("port setting %s out of range, must be 1-65535 but was %" PRIrrrbl ".\n",
					name, tmp_uint
			);
			ret = 1;
			goto out;
		}
	}

	*target = (uint16_t) tmp_uint;

	out:
	return ret;
}

int rrr_instance_config_read_optional_port_number (
		uint16_t *target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return __rrr_instance_config_read_port_number(target, source, name, 1, 1);
}

int rrr_instance_config_read_port_number (
		uint16_t *target,
		struct rrr_instance_config_data *source,
		const char *name
) {
	return __rrr_instance_config_read_port_number(target, source, name, 0, 0);
}

int rrr_instance_config_check_all_settings_used (
		struct rrr_instance_config_data *config
) {
	int ret = rrr_settings_check_all_used (config->settings, &config->settings_used);

	if (ret != 0) {
		RRR_MSG_0("Warning: Not all settings of instance %s were used, possible typo in configuration file\n",
			config->name);
	}

	return ret;
}

void rrr_instance_config_verify_all_settings_used (
		struct rrr_instance_config_data *config
) {
	if (rrr_settings_check_all_used (config->settings, &config->settings_used) != 0) {
		RRR_BUG("BUG: Not all settings of instance %s were used in %s, abort.\n",
			__func__, config->name);
	}
}

static int __rrr_instance_config_parse_name_or_definition_from_config_silent_fail (
		struct rrr_instance_config_data *config,
		const char *cmd_key,
		const char *tag_start,
		const char *tag_end,
		int (*name_callback)(const char *tag, void *arg),
		int (*interpret_callback)(const char *str, void *arg),
		void *callback_arg
) {
	int ret = 0;

	char *name_tmp = NULL;
	char *target_str_tmp = NULL;

	if ((ret = rrr_settings_get_string_noconvert_silent(&target_str_tmp, &config->settings_used, config->settings, cmd_key)) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			goto out;
		}
		else {
			RRR_MSG_0("Error while parsing setting %s in instance %s\n", cmd_key, config->name);
			ret = 1;
			goto out;
		}
	}

	struct rrr_parse_pos pos;

	rrr_parse_pos_init(&pos, target_str_tmp, rrr_length_from_size_t_bug_const(strlen(target_str_tmp)));
	rrr_parse_ignore_space_and_tab(&pos);

	if (rrr_parse_match_word(&pos, tag_start)) {
		int comma;
		do {
			comma = 0;

			RRR_FREE_IF_NOT_NULL(name_tmp);
			if ((ret = rrr_parse_str_extract_name(&name_tmp, &pos, *tag_end)) != 0) {
				RRR_MSG_0("Failed to parse name indicated by %s\n", tag_start);
				goto out;
			}

			if (name_tmp == NULL) {
				RRR_MSG_0("Name within %s%s was empty\n", tag_start, tag_end);
				ret = 1;
				goto out;
			}

			if ((ret = name_callback(name_tmp, callback_arg)) != 0) {
				goto out;
			}

			rrr_parse_ignore_space_and_tab(&pos);

			if (rrr_parse_match_word(&pos, ",")) {
				rrr_parse_ignore_space_and_tab(&pos);
				if (!rrr_parse_match_word(&pos, tag_start)) {
					RRR_MSG_0("Expected tag start %s after comma\n");
					ret = 1;
					goto out;
				}
				comma = 1;
			}
		} while (comma);

		goto out;
	}

	if ((ret = interpret_callback(target_str_tmp, callback_arg)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(target_str_tmp);
	RRR_FREE_IF_NOT_NULL(name_tmp);
	return ret;
}

struct rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_callback_data {
	struct rrr_instance_config_data *config;
	struct rrr_array_tree *new_tree;
};

static int __rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_name_callback (
		const char *name,
		void *arg
) {
	struct rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_callback_data *callback_data = arg;

	int ret = 0;

	if (callback_data->new_tree != NULL) {
		RRR_MSG_0("Multiple array tree definitions are not allowed\n");
		ret = 1;
		goto out;
	}

	const struct rrr_array_tree *array_tree = rrr_array_tree_list_get_tree_by_name (
			callback_data->config->global_array_trees,
			name
	);

	if (array_tree == NULL) {
		RRR_MSG_0("Array tree with name '%s' not found, check spelling\n", name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_array_tree_clone_without_data(&callback_data->new_tree, array_tree)) != 0) {
		goto out;
	}
	
	out:
	return ret;
}

static int __rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_interpret_callback (
		const char *str,
		void *arg
) {
	struct rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_callback_data *callback_data = arg;

	int ret = 0;

	char *tmp;

	if ((tmp = rrr_strdup(str)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	rrr_length definition_length = rrr_length_from_size_t_bug_const(strlen(tmp));

	// Replace terminating \0 with semicolon. We don't actually use the \0 to
	// figure out where the end is when parsing the array. This adding of ;
	// allows simple array definition to be specified without ; at the end.
	tmp[definition_length] = ';';

	assert(callback_data->new_tree == NULL);

	if (rrr_array_tree_interpret_raw (
			&callback_data->new_tree,
			tmp,
			rrr_length_inc_bug_const(definition_length),  // DO NOT use strlen here, string no longer has \0
			"-"
	)) {
		RRR_MSG_0("Error while interpreting array tree\n");
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	return ret;
}

int rrr_instance_config_parse_array_tree_definition_from_config_silent_fail (
		struct rrr_array_tree **target_array_tree,
		struct rrr_instance_config_data *config,
		const char *cmd_key
) {
	int ret = 0;

	*target_array_tree = NULL;

	struct rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_callback_data callback_data = {
		config,
		NULL
	};

	if ((ret = __rrr_instance_config_parse_name_or_definition_from_config_silent_fail (
			config,
			cmd_key,
			"{",
			"}",
			__rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_name_callback,
			__rrr_instance_config_parse_array_tree_definition_from_config_silent_fail_interpret_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			goto out;
		}
		else {
			RRR_MSG_0("Failed while interpreting parameter %s of instance %s\n",
					cmd_key,
					config->name);
		}
		goto out;
	}

	assert(callback_data.new_tree != NULL);

	*target_array_tree = callback_data.new_tree;

	out:
	return ret;
}

struct rrr_instance_config_parse_discern_stack_from_config_silent_fail_callback_data {
	const struct rrr_discern_stack_collection *source;
	struct rrr_discern_stack_collection *target;
};

static int __rrr_instance_config_parse_discern_stack_from_config_silent_fail_name_callback (
		const char *name,
		void *arg
) {
	int ret = 0;
	
	struct rrr_instance_config_parse_discern_stack_from_config_silent_fail_callback_data *callback_data = arg;

	const struct rrr_discern_stack *stack = rrr_discern_stack_collection_get (
			callback_data->source,
			name
	);

	if (stack == NULL) {
		RRR_MSG_0("Definition with name '%s' not found, check spelling\n", name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_discern_stack_collection_add_cloned (callback_data->target, stack)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_instance_config_parse_discern_stack_from_config_silent_fail_interpret_callback (
		const char *str,
		void *arg
) {
	int ret = 0;

	struct rrr_instance_config_parse_discern_stack_from_config_silent_fail_callback_data *callback_data = arg;

	enum rrr_discern_stack_fault fault;
	struct rrr_parse_pos pos;

	rrr_parse_pos_init(&pos, str, rrr_length_from_size_t_bug_const(strlen(str)));

	assert(RRR_LL_COUNT(callback_data->target) == 0);

	if ((ret = rrr_discern_stack_interpret (callback_data->target, &fault, &pos, "anonymous")) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_instance_config_parse_discern_stack_from_config_silent_fail (
		struct rrr_discern_stack_collection *target,
		struct rrr_instance_config_data *config,
		const struct rrr_discern_stack_collection *source,
		const char *cmd_key,
		const char *tag_start,
		const char *tag_end
) {
	int ret = 0;


	struct rrr_instance_config_parse_discern_stack_from_config_silent_fail_callback_data callback_data = {
		source,
		target
	};

	if ((ret = __rrr_instance_config_parse_name_or_definition_from_config_silent_fail (
			config,
			cmd_key,
			tag_start,
			tag_end,
			__rrr_instance_config_parse_discern_stack_from_config_silent_fail_name_callback,
			__rrr_instance_config_parse_discern_stack_from_config_silent_fail_interpret_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			goto out;
		}
		else {
			RRR_MSG_0("Failed while interpreting parameter %s of instance %s\n",
					cmd_key,
					config->name);
		}
		goto out;
	}

	out:
	return ret;
}

int rrr_instance_config_parse_route_definition_from_config_silent_fail (
		struct rrr_discern_stack_collection *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key
) {
	return __rrr_instance_config_parse_discern_stack_from_config_silent_fail (
			target,
			config,
			config->global_routes,
			cmd_key,
			"<",
			">"
	);
}

int rrr_instance_config_parse_method_definition_from_config_silent_fail (
		struct rrr_discern_stack_collection *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key
) {
	return __rrr_instance_config_parse_discern_stack_from_config_silent_fail (
			target,
			config,
			config->global_methods,
			cmd_key,
			"(",
			")"
	);
}

struct parse_associative_list_to_map_callback_data {
	struct rrr_map *target;
	const char *delimeter;
};

static int __parse_associative_list_to_map_callback (
		const char *value,
		void *arg
) {
	struct parse_associative_list_to_map_callback_data *data = arg;
	return rrr_map_parse_pair(value, data->target, data->delimeter);
}

int rrr_instance_config_parse_comma_separated_associative_to_map (
		struct rrr_map *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key,
		const char *delimeter
) {
	struct parse_associative_list_to_map_callback_data callback_data = {
			target, delimeter
	};

	return rrr_instance_config_traverse_split_commas_silent_fail (
			config,
			cmd_key,
			__parse_associative_list_to_map_callback,
			&callback_data
	);
}

int rrr_instance_config_parse_comma_separated_to_map (
		struct rrr_map *target,
		struct rrr_instance_config_data *config,
		const char *cmd_key
) {
	struct parse_associative_list_to_map_callback_data callback_data = {
			target, NULL
	};

	return rrr_instance_config_traverse_split_commas_silent_fail (
			config,
			cmd_key,
			__parse_associative_list_to_map_callback,
			&callback_data
	);
}

static int __rrr_instance_config_parse_comma_separated_to_map_check_unary_all (
		struct rrr_map *target,
		int *is_all,
		struct rrr_instance_config_data *config,
		const char *string
) {
	int ret = 0;

	*is_all = 0;

	int result = 0;
	if ((ret = rrr_settings_cmpto(&result, &config->settings_used, config->settings, string, "*")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			ret = 0;
		}
		goto out;
	}

	if (result == 0) {
		*is_all = 1;
		goto out;
	}

	struct parse_associative_list_to_map_callback_data callback_data = {
		target, NULL
	};

	if ((ret = rrr_instance_config_traverse_split_commas_silent_fail (
			config,
			string,
			__parse_associative_list_to_map_callback,
			&callback_data
	)) != 0) {
		assert(ret != RRR_SETTING_NOT_FOUND);
		goto out;
	}

	out:
	return ret;
}

int rrr_instance_config_parse_optional_write_method (
		struct rrr_map *array_values,
		enum rrr_instance_config_write_method *method,
		struct rrr_instance_config_data *config,
		const char *string_write_rrr_message,
		const char *string_array_values
) {
	int ret = 0;

	int yesno = 0;
	int is_all = 0;

	// Either rrr_message or array values (tags) may be set. If array
	// values are used, this field may be set to * to indicate use of all
	// values in array. String arguments may be NULL if option is not used.

	*method = RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE;

 	if ((string_write_rrr_message != NULL) &&
	    (ret = rrr_settings_check_yesno(&yesno, &config->settings_used, config->settings, string_write_rrr_message)) != 0
	) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Failed to parse yes/no parameter '%s' of instance %s\n",
					string_write_rrr_message,
					config->name);
			goto out;
		}
		ret = 0;
	}

	/* -1 means not found, 0 means no, 1 means yes */
	if (yesno == 1) {
		*method = RRR_INSTANCE_CONFIG_WRITE_METHOD_RRR_MESSAGE;
	}

	if (string_array_values != NULL) {
		if ((ret = __rrr_instance_config_parse_comma_separated_to_map_check_unary_all (
				array_values,
				&is_all,
				config,
				string_array_values
		)) != 0) {
			RRR_MSG_0("Error while parsing parameter '%s' of instance %s\n",
					string_array_values, config->name);
			ret = 1;
			goto out;
		}

		if (is_all || RRR_LL_COUNT(array_values) > 0) {
			if (*method == RRR_INSTANCE_CONFIG_WRITE_METHOD_RRR_MESSAGE) {
				RRR_MSG_0("Cannot have '%s' set while '%s' is 'yes' in instance %s\n",
						string_write_rrr_message,
						string_array_values,
						config->name);
				ret = 1;
				goto out;
			}

			assert(*method == RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE);

			*method = RRR_INSTANCE_CONFIG_WRITE_METHOD_ARRAY_VALUES;
		}
	}

	out:
	return ret;
}

int rrr_instance_config_parse_optional_utf8 (
		char **target,
		struct rrr_instance_config_data *config,
		const char *string,
		const char *def
) {
	int ret = 0;

	if ((ret = rrr_settings_get_string_noconvert_silent(target, &config->settings_used, config->settings, string)) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			if (def != NULL && (*target = rrr_strdup(def)) == NULL) {
				RRR_MSG_0("Could not allocate memory for default value of setting %s in instance %s\n",
					string, config->name);
				ret = 1;
				goto out;
			}
		}
		else {
			RRR_MSG_0("Error while parsing setting %s in instance %s\n", string, config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		if (rrr_utf8_validate(*target, rrr_length_from_size_t_bug_const(strlen(*target))) != 0) {
			RRR_MSG_0("Setting %s in instance %s was not valid UTF-8\n", string, config->name);
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_instance_config_parse_optional_topic_and_length (
		char **target,
		uint16_t *target_length,
		struct rrr_instance_config_data *config,
		const char *string
) {
	int ret = 0;

	char *topic = NULL;
	size_t topic_length = 0;

	if ((ret = rrr_instance_config_parse_optional_utf8 (&topic, config, string, NULL)) != 0) {
		goto out;
	}

	if (topic != NULL && *(topic) != '\0') {
		topic_length = strlen(topic);
		if (topic_length > 0xffff) {
			RRR_MSG_0("Length of MQTT topic parameter %s exceeds maximum length (%llu>%i) in instance %s\n",
				string,
				(unsigned long long int) topic_length,
				0xffff,
				config->name
			);
			ret = 1;
			goto out;
		}
		if (rrr_mqtt_topic_validate_name(topic) != 0) {
			RRR_MSG_0("Validation of MQTT topic parameter %s with value '%s' failed in instance %s\n",
				string,
				topic,
				config->name
			);
			ret = 1;
			goto out;
		 }
	}

	*target_length = (uint16_t) topic_length;
	*target = topic;
	topic = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(topic);
	return ret;
}

int rrr_instance_config_parse_optional_topic_filter (
		struct rrr_mqtt_topic_token **target,
		char **target_str,
		struct rrr_instance_config_data *config,
		const char *string
) {
	int ret = 0;

	if (target != NULL) {
		*target = NULL;
	}
	if (target_str != NULL) {
		*target_str = NULL;
	}

	char *filter = NULL;

	if ((ret = rrr_instance_config_parse_optional_utf8 (&filter, config, string, NULL)) != 0 || filter == NULL) {
		goto out;
	}

	if (rrr_mqtt_topic_filter_validate_name(filter) != 0) {
		RRR_MSG_0("Invalid parameter %s in instance %s\n", string, config->name);
		ret = 1;
		goto out;
	}

	if (target != NULL) {
		if (rrr_mqtt_topic_tokenize(target, filter) != 0) {
			RRR_MSG_0("Error while tokenizing topic filter in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if (target_str != NULL) {
		*target_str = filter;
		filter = NULL;
	}

	out:
	RRR_FREE_IF_NOT_NULL(filter);
	return ret;
}

static struct rrr_instance_config_data *__rrr_instance_config_find_instance (
		struct rrr_instance_config_collection *source,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(source, struct rrr_instance_config_data);
		if (strcmp(node->name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();

	return NULL;
}

static int __rrr_instance_config_push (
		struct rrr_instance_config_collection *target,
		struct rrr_instance_config_data *instance_config
) {
	if (__rrr_instance_config_find_instance (target, instance_config->name) != NULL) {
		RRR_MSG_0("Two instances was named %s\n", instance_config->name);
		return 1;
	}

	RRR_LL_APPEND(target, instance_config);

	return 0;
}

static int __rrr_instance_config_new_setting_callback (
		RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS
) {
	struct rrr_instance_config_data *instance_config = block;
	struct rrr_instance_config_collection *collection = callback_arg;

	(void)(collection);

	if (rrr_settings_add_string(instance_config->settings, name, value) != 0) {
		return 1;
	}

	return 0;
}

static int __rrr_instance_config_new_block_callback (
		RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS
) {
	struct rrr_instance_config_collection *collection = callback_arg;

	int ret = 0;

	struct rrr_instance_config_data *instance_config = NULL;

	if ((ret = __rrr_instance_config_new (
			&instance_config,
			name,
			RRR_INSTANCE_CONFIG_MAX_SETTINGS,
			rrr_config_get_array_tree_list(config),
			rrr_config_get_routes(config),
			rrr_config_get_methods(config)
	)) != 0) {
		goto out;
	}

	if ((ret =  __rrr_instance_config_push (collection, instance_config)) != 0) {
		goto out_destroy_instance;
	}

	*block = instance_config;

	goto out;
	out_destroy_instance:
		__rrr_instance_config_destroy(instance_config);
	out:
		return ret;
}

int rrr_instance_config_dump (struct rrr_instance_config_collection *collection) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_instance_config_data);
		RRR_MSG_1("== CONFIGURATION FOR %s BEGIN =============\n", node->name);

		// Continue despite error
		ret |= rrr_settings_dump (node->settings);

		RRR_MSG_1("== CONFIGURATION FOR %s END ===============\n", node->name);
	RRR_LL_ITERATE_END();

	if (ret != 0) {
		RRR_MSG_0 ("Warning: Some error(s) occurred while dumping the configuration, some settings could possibly not be converted to strings\n");
	}

	return ret;
}

int rrr_instance_config_parse_file (
		struct rrr_instance_config_collection **result,
		const char *filename
) {
	int ret = 0;

	struct rrr_instance_config_collection *collection = NULL;

	*result = NULL;

	if ((ret = __rrr_instance_config_collection_new (&collection)) != 0) {
		goto out;
	}

	if ((ret = rrr_config_parse_file (
			collection->config,
			filename,
			__rrr_instance_config_new_block_callback,
			__rrr_instance_config_new_setting_callback,
			collection
	)) != 0) {
		goto out_destroy_collection;
	}

	*result = collection;

	goto out;
	out_destroy_collection:
		rrr_instance_config_collection_destroy(collection);
	out:
	return ret;
}

struct rrr_instance_config_friend_collection_populate_from_config_callback_data {
	struct rrr_instance_collection *instances;
	struct rrr_instance_friend_collection *collection;
};

static int __rrr_instance_config_friend_collection_populate_from_config_callback (
		const char *value,
		void *arg
) {
	struct rrr_instance_config_friend_collection_populate_from_config_callback_data *data = arg;

	int ret = 0;

	struct rrr_instance *instance = rrr_instance_find(data->instances, value);

	if (instance == NULL) {
		RRR_MSG_0("Could not find instance '%s'\n", value);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Added %s\n", INSTANCE_M_NAME(instance));

	if ((ret = rrr_instance_friend_collection_append(data->collection, instance, NULL)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_instance_config_friend_collection_populate_from_config (
		struct rrr_instance_friend_collection *target,
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_data *config,
		const char *setting
) {
	int ret = 0;

	struct rrr_instance_config_friend_collection_populate_from_config_callback_data add_data = {
		instances,
		target
	};

	if ((ret = rrr_settings_traverse_split_commas_silent_fail (
			&config->settings_used,
			config->settings,
			setting,
			&__rrr_instance_config_friend_collection_populate_from_config_callback,
			&add_data
	))!= 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_instance_config_friend_collection_populate_receivers_from_config (
		struct rrr_instance_friend_collection *target,
		struct rrr_instance_collection *instances_all,
		const struct rrr_instance *instance,
		struct rrr_instance_config_data *config,
		const char *setting
) {
	int ret = 0;

	if ((ret = rrr_instance_config_friend_collection_populate_from_config (
			target,
			instances_all,
			config,
			setting
	)) != 0) {
		RRR_MSG_0("Failed to add receivers from %s in %s\n", setting, __func__);
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(target, struct rrr_instance_friend);
		if (!rrr_instance_has_sender (node->instance, instance)) {
			RRR_MSG_0("Specified receiver %s in %s of instance %s does not have this instance specified as sender\n",
				INSTANCE_M_NAME(node->instance),
				setting,
				INSTANCE_M_NAME(instance)
			);
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();
	
	out:
	return ret;
}
