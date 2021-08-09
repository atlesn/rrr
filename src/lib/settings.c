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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "allocator.h"

#include "socket/rrr_socket.h"
#include "settings.h"
#include "util/rrr_endian.h"
#include "util/macro_utils.h"
#include "util/posix.h"

static void __rrr_settings_list_destroy (
		struct rrr_settings_list *list
) {
	if (list->data != NULL) {
		rrr_free(list->data);
	}
	if (list->list != NULL) {
		rrr_free(list->list);
	}
	rrr_free(list);
}

static int __rrr_settings_init (
		struct rrr_instance_settings *target,
		const rrr_length count
) {
	int ret = 0;

	memset(target, '\0', sizeof(*target));

	target->settings = rrr_allocate(sizeof(*(target->settings)) * count);
	if (target->settings == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_settings_init\n");
		ret = 1;
		goto out;
	}

	if (rrr_posix_mutex_init (&target->mutex, 0) != 0) {
		RRR_MSG_0("Could initialize lock in __rrr_settings_init\n");
		ret = 1;
		goto out_free;
	}

	target->settings_max = count;
	target->settings_count = 0;
	target->initialized = 1;

	goto out;
	out_free:
		rrr_free(target->settings);
	out:
		return ret;
}

struct rrr_instance_settings *rrr_settings_new (
		const rrr_length count
) {
	struct rrr_instance_settings *ret = rrr_allocate(sizeof(*ret));

	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory for module settings structure");
		return NULL;
	}

	if (__rrr_settings_init(ret, count) != 0) {
		rrr_free(ret);
		return NULL;
	}

	return ret;
}

static void __rrr_settings_destroy_setting (
		struct rrr_setting *setting
) {
	rrr_free(setting->data);
}

void rrr_settings_destroy (
		struct rrr_instance_settings *target
) {
	pthread_mutex_lock(&target->mutex);

	if (target->initialized != 1) {
		RRR_BUG("BUG: Tried to double-destroy settings structure\n");
	}

	for (unsigned int i = 0; i < target->settings_count; i++) {
		__rrr_settings_destroy_setting(&target->settings[i]);
	}

	target->settings_count = 0;
	target->settings_max = 0;
	target->initialized = 0;

	pthread_mutex_unlock(&target->mutex);
	pthread_mutex_destroy(&target->mutex);

	rrr_free(target->settings);
	rrr_free(target);
}

static void __rrr_settings_lock (
		struct rrr_instance_settings *settings
) {
	if (settings->initialized != 1) {
		RRR_BUG("BUG: Tried to lock destroyed settings structure\n");
	}
	pthread_mutex_lock(&settings->mutex);
}

static void __rrr_settings_unlock (
		struct rrr_instance_settings *settings
) {
	if (settings->initialized != 1) {
		RRR_BUG("BUG: Tried to unlock destroyed settings structure\n");
	}
	pthread_mutex_unlock(&settings->mutex);
}

static struct rrr_setting *__rrr_settings_find_setting_nolock (
		struct rrr_instance_settings *source,
		const char *name
) {
	for (unsigned int i = 0; i < source->settings_count; i++) {
		struct rrr_setting *test = &source->settings[i];

		if (strcmp(test->name, name) == 0) {
			test->was_used = 1;
			return test;
		}
	}

	return NULL;
}

static struct rrr_setting *__rrr_settings_reserve_nolock (
		struct rrr_instance_settings *target,
		const char *name,
		int return_existing
) {
	struct rrr_setting *ret = NULL;

	if ((ret = __rrr_settings_find_setting_nolock(target, name)) != NULL) {
		if (return_existing) {
			return ret;
		}

		RRR_MSG_0("Settings name %s defined twice\n", name);
		return NULL;
	}

	if (target->settings_count > target->settings_max) {
		RRR_BUG("BUG: setting_count was > settings_max");
	}

	if (target->settings_count == target->settings_max) {
		RRR_MSG_0("Could not reserve setting because the maximum number of settings (%d) was reached",
				target->settings_max);
		return NULL;
	}

	ret = &target->settings[rrr_length_inc_bug_old_value(&target->settings_count)];

	return ret;
}

static int __rrr_settings_set_setting_name (
		struct rrr_setting *setting,
		const char *name
) {
	if (strlen(name) + 1 > RRR_SETTINGS_MAX_NAME_SIZE) {
		RRR_MSG_0("Settings name %s was longer than maximum %d\n", name, RRR_SETTINGS_MAX_NAME_SIZE);
		return 1;
	}

	sprintf(setting->name, "%s", name);

	return 0;
}

static int __rrr_settings_add_raw (
		struct rrr_instance_settings *target,
		const char *name,
		const void *old_data,
		const rrr_length size,
		rrr_u32 type,
		int replace_existing
) {
	int ret = 0;

	void *new_data = rrr_allocate(size);

	if (new_data == NULL) {
		RRR_MSG_0("Could not allocate memory for setting struct\n");
		ret = 1;
		goto out;
	}

	memcpy(new_data, old_data, size);

	__rrr_settings_lock(target);

	struct rrr_setting *setting = __rrr_settings_reserve_nolock(target, name, replace_existing);
	if (setting == NULL) {
		RRR_MSG_0("Could not create setting struct for %s\n", name);
		ret = 1;
		goto out_unlock;
	}

	memset (setting, '\0', sizeof(*setting));

	if ((ret = __rrr_settings_set_setting_name(setting, name)) != 0) {
		goto out_unlock;
	}

	setting->data = new_data;
	new_data = NULL;

	setting->data_size = size;
	setting->type = type;
	setting->was_used = 0;

	out_unlock:
	RRR_FREE_IF_NOT_NULL(new_data);

	__rrr_settings_unlock(target);

	out:
	return ret;
}

static int __rrr_settings_get_string_noconvert (
		char **target,
		struct rrr_instance_settings *source,
		const char *name,
		int silent_not_found
) {
	int ret = 0;
	*target = NULL;

	__rrr_settings_lock(source);

	struct rrr_setting *setting = __rrr_settings_find_setting_nolock(source, name);

	if (setting == NULL) {
		if (!silent_not_found) {
			RRR_MSG_0("Could not locate setting '%s'\n", name);
		}
		ret = RRR_SETTING_NOT_FOUND;
		goto out;
	}

	if (setting->type != RRR_SETTINGS_TYPE_STRING) {
		RRR_MSG_0("Tried to get string value of %s with no conversion but it was of wrong type %d\n", setting->name, setting->type);
		ret = 1;
		goto out;
	}

	if (setting->data_size <= 1) {
		RRR_BUG("BUG: Data size was <= 1 in rrr_settings_get_string_noconvert\n");
	}

	const char *data = setting->data;

	if (data[setting->data_size - 1] != '\0') {
		RRR_BUG("BUG: Data string type was not null terminated in rrr_settings_get_string_noconvert\n");
	}

	char *string = rrr_allocate(setting->data_size);
	if (string == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_settings_get_string_noconvert\n");
		ret = 1;
		goto out;
	}

	memcpy(string, data, setting->data_size);

	*target = string;

	out:
	__rrr_settings_unlock(source);
	return ret;
}

int rrr_settings_exists (
		struct rrr_instance_settings *source,
		const char *name
) {
	int ret = 0;

	__rrr_settings_lock(source);

	if (__rrr_settings_find_setting_nolock(source, name) != NULL) {
		ret = 1;
		goto out;
	}

	out:
	__rrr_settings_unlock(source);
	return ret;
}

int rrr_settings_get_string_noconvert (
		char **target,
		struct rrr_instance_settings *source,
		const char *name
) {
	return __rrr_settings_get_string_noconvert(target, source, name, 0);
}

int rrr_settings_get_string_noconvert_silent (
		char **target,
		struct rrr_instance_settings *source,
		const char *name
) {
	return __rrr_settings_get_string_noconvert(target, source, name, 1);
}

static int __rrr_settings_traverse_split_commas (
		struct rrr_instance_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg), void *arg,
		int silent_fail
) {
	int ret = 0;

	char *value = NULL;

	if (__rrr_settings_get_string_noconvert (&value, source, name, silent_fail) != 0) {
		if (silent_fail) {
			goto out;
		}
		RRR_MSG_0("Could not get setting %s for comma splitting\n", name);
		ret = 1;
		goto out;
	}

	char *current_pos = value;
	char *comma_pos;
	while (*current_pos != '\0') {
		comma_pos = strchr(current_pos, ',');
		if (comma_pos == NULL) {
			ret = callback(current_pos, arg);
			break;
		}

		*comma_pos = '\0';
		ret = callback(current_pos, arg);
		if (ret != 0) {
			break;
		}
		*comma_pos = ',';

		current_pos = comma_pos + 1;
	}

	out:
	if (value != NULL) {
		rrr_free(value);
	}
	return ret;
}

int rrr_settings_traverse_split_commas (
		struct rrr_instance_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg), void *arg
) {
	return __rrr_settings_traverse_split_commas(source, name, callback, arg, 0);
}

int rrr_settings_traverse_split_commas_silent_fail (
		struct rrr_instance_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg), void *arg
) {
	return __rrr_settings_traverse_split_commas(source, name, callback, arg, 1);
}

int rrr_settings_split_commas_to_array (
		struct rrr_settings_list **target_ptr,
		struct rrr_instance_settings *source,
		const char *name
) {
	int ret = 0;
	char *value = NULL;

	*target_ptr = NULL;

	struct rrr_settings_list *target = rrr_allocate(sizeof(*target));
	if (target == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_settings_split_commas_to_array\n");
		ret = 1;
		goto out;
	}

	memset(target, '\0', sizeof(*target));

	if (rrr_settings_get_string_noconvert (&value, source, name) != 0) {
		RRR_MSG_0("Could not get setting %s for comma splitting and array building\n", name);
		ret = 1;
		goto out;
	}

	if (*value == '\0') {
		ret = 0;
		goto out;
	}

	size_t length = strlen(value);

	if (length > RRR_LENGTH_MAX) {
		RRR_MSG_0("Value too long ing rrr_settings_split_commas_to_array (%llu)\n", (long long unsigned) length);
		ret = 1;
		goto out;
	}

	target->data = rrr_allocate(length + 1);
	if (target->data == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_settings_split_commas_to_array\n");
		ret = 1;
		goto out;
	}

	rrr_length elements = 1;
	for (rrr_length i = 0; i < length; i++) {
		if (value[i] == ',') {
			if ((ret = rrr_length_inc_err(&elements)) != 0) {
				RRR_MSG_0("Too many elements in rrr_settings_split_commas_to_array\n");
				goto out;
			}
		}
	}

	target->list = rrr_allocate(elements * sizeof(char*));
	if (target->list == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_settings_split_commas_to_array\n");
		ret = 1;
		goto out;
	}

	strcpy(target->data, value);

	rrr_length pos = 0;
	target->list[pos] = target->data;
	rrr_length_inc_bug(&pos);

	for (rrr_length i = 0; i < length; i++) {
		if (target->data[i] == ',') {
			target->data[i] = '\0';
			if (i + 1 < length && target->data[i + 1] != '\0') {
				target->list[rrr_length_inc_bug_old_value(&pos)] = target->data + i + 1;
			}
		}
	}

	target->length = pos;

	out:
	if (value != NULL) {
		rrr_free(value);
	}

	if (ret != 0 && target != NULL) {
		__rrr_settings_list_destroy(target);
	}
	else {
		*target_ptr = target;
	}

	return ret;
}

static int __rrr_settings_replace_or_add_string (
		struct rrr_instance_settings *target,
		const char *name,
		const char *value,
		int do_replace
) {
	const void *data = value;
	size_t length = strlen(value);

	if (length > RRR_LENGTH_MAX - 1) {
		RRR_MSG_0("Value too long in rrr_settings_replace_or_add_string\n");
		return 1;
	}

	rrr_length size = (rrr_length) length + 1;

	return __rrr_settings_add_raw(target, name, data, size, RRR_SETTINGS_TYPE_STRING, do_replace);
}

int rrr_settings_replace_string (
		struct rrr_instance_settings *target,
		const char *name,
		const char *value
) {
	return __rrr_settings_replace_or_add_string(target, name, value, 1 /* Do replace */);
}

int rrr_settings_add_string (
		struct rrr_instance_settings *target,
		const char *name,
		const char *value
) {
	return __rrr_settings_replace_or_add_string(target, name, value, 0 /* Do not replace */);
}

int rrr_settings_replace_unsigned_integer (
		struct rrr_instance_settings *target,
		const char *name,
		rrr_setting_uint value
) {
	return __rrr_settings_add_raw(target, name, &value, sizeof(value), RRR_SETTINGS_TYPE_UINT, 1);
}

int rrr_settings_add_unsigned_integer (
		struct rrr_instance_settings *target,
		const char *name,
		rrr_setting_uint value
) {
	return __rrr_settings_add_raw(target, name, &value, sizeof(value), RRR_SETTINGS_TYPE_UINT, 0);
}

int rrr_settings_setting_to_string_nolock (
		char **target,
		struct rrr_setting *setting
) {
	int ret = 0;
	*target = NULL;

	char *value;
	if (setting->type == RRR_SETTINGS_TYPE_STRING) {
		if ((value = rrr_allocate(setting->data_size)) == NULL) {
			goto out_malloc_err;
		}
		sprintf(value, "%s", (char*) setting->data);
	}
	else if (setting->type == RRR_SETTINGS_TYPE_UINT) {
		if ((value = rrr_allocate(RRR_SETTINGS_UINT_AS_TEXT_MAX)) == NULL) {
			goto out_malloc_err;
		}
		sprintf(value, "%llu", *((unsigned long long *) setting->data));
	}
	else {
		RRR_BUG("BUG: Could not convert setting of type %d to string\n", setting->type);
	}

	*target = value;

	return ret;

	out_malloc_err:
	RRR_MSG_0("Could not allocate memory while converting setting to string");
	return RRR_SETTING_ERROR;
}

int rrr_settings_setting_to_uint_nolock (
		rrr_setting_uint *target,
		struct rrr_setting *setting
) {
	int ret = 0;
	char *tmp_string = NULL;
	*target = 0;

	if (setting->type == RRR_SETTINGS_TYPE_UINT) {
		if (sizeof(*target) != setting->data_size) {
			RRR_BUG("BUG: Setting unsigned integer size mismatch\n");
		}
		*target = *((rrr_setting_uint*) setting->data);
	}
	else if (setting->type == RRR_SETTINGS_TYPE_STRING) {
		ret = rrr_settings_setting_to_string_nolock(&tmp_string, setting);
		if (ret != 0) {
			RRR_MSG_0("Could not get string of '%s' while converting to unsigned integer\n", setting->name);
			goto out;
		}

		// strtoull will accept negative numbers, we need to check here first
		for (unsigned const char *pos = (unsigned const char *) tmp_string; *pos != '\0'; pos++) {
			if (*pos < '0' || *pos > '9') {
				RRR_MSG_0("Unknown character '%c' in supposed unsigned integer '%s'\n",
						*pos, tmp_string);
				ret = 1;
				goto out;
			}
		}

		char *end;
		rrr_setting_uint tmp = strtoull(tmp_string, &end, 10);

		if (*end != '\0') {
			ret = RRR_SETTING_PARSE_ERROR;
			RRR_MSG_0("Syntax error while converting setting '%s' with value '%s' to unsigned integer\n", setting->name, tmp_string);
			goto out;
		}

		*target = tmp;
	}
	else {
		RRR_BUG("BUG: Could not convert setting of type %d to unsigned int\n", setting->type);
	}

	out:
	if (tmp_string != NULL) {
		rrr_free(tmp_string);
	}

	return ret;
}

int rrr_settings_read_string (
		char **target,
		struct rrr_instance_settings *settings,
		const char *name
) {
	int ret = 0;
	*target = NULL;

	__rrr_settings_lock(settings);

	struct rrr_setting *setting = __rrr_settings_find_setting_nolock(settings, name);
	if (setting == NULL) {
		ret = RRR_SETTING_NOT_FOUND;
		goto out_unlock;
	}

	ret = rrr_settings_setting_to_string_nolock (target, setting);

	out_unlock:
	__rrr_settings_unlock(settings);

	return ret;
}

int rrr_settings_read_unsigned_integer (
		rrr_setting_uint *target,
		struct rrr_instance_settings *settings,
		const char *name
) {
	int ret = 0;
	*target = 0;

	__rrr_settings_lock(settings);

	struct rrr_setting *setting = __rrr_settings_find_setting_nolock(settings, name);
	if (setting == NULL) {
		ret = RRR_SETTING_NOT_FOUND;
		goto out_unlock;
	}

	ret = rrr_settings_setting_to_uint_nolock (target, setting);

	out_unlock:
	__rrr_settings_unlock(settings);

	return ret;
}

int rrr_settings_check_yesno (
		int *result,
		struct rrr_instance_settings *settings,
		const char *name
) {
	*result = -1;
	int ret = 0;

	char *string = NULL;
	if ((ret = rrr_settings_read_string (&string, settings, name)) != 0) {
		goto out;
	}

	*result = 0;

	if (*string == 'y' || *string == 'Y' || *string == '1') {
		*result = 1;
	}
	else if (*string == 'n' || *string == 'N' || *string == '0') {
		*result = 0;
	}
	else {
		ret = RRR_SETTING_PARSE_ERROR;
	}

	out:
	if (string != NULL) {
		rrr_free(string);
	}

	return ret;
}

int rrr_settings_check_all_used (
		struct rrr_instance_settings *settings
) {
	int ret = 0;

	__rrr_settings_lock(settings);
	for (unsigned int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];

		if (setting->was_used == 0) {
			RRR_MSG_0("Warning: Setting %s has not been used\n", setting->name);
			ret = 1;
		}
	}
	__rrr_settings_unlock(settings);

	return ret;
}

int rrr_settings_dump (
		struct rrr_instance_settings *settings
) {
	int ret = 0;

	__rrr_settings_lock(settings);

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];

		const char *name = setting->name;
		char *value;
		ret = rrr_settings_setting_to_string_nolock(&value, setting);

		if (ret != 0) {
			RRR_MSG_0("Warning: Error in settings dump function\n");
			goto next;
		}

		RRR_MSG_1("%s=%s\n", name, value);

		next:
		RRR_FREE_IF_NOT_NULL(value);
	}

	__rrr_settings_unlock(settings);

	return ret;
}

int rrr_settings_iterate_nolock (
		struct rrr_instance_settings *settings,
		int (*callback)(struct rrr_setting *settings, void *callback_args),
		void *callback_args
) {
	int ret = 0;

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];

		ret = callback(setting, callback_args);

		if (ret != 0) {
			break;
		}
	}

	return ret;
}

int rrr_settings_iterate (
		struct rrr_instance_settings *settings,
		int (*callback)(struct rrr_setting *settings, void *callback_args),
		void *callback_args
) {
	int ret = 0;

	__rrr_settings_lock(settings);
	ret = rrr_settings_iterate_nolock(settings, callback, callback_args);
	__rrr_settings_unlock(settings);

	return ret;
}

struct rrr_settings_update_used_callback_data {
	const char *name;
	rrr_u32 was_used;
	int did_update;
};

static int __rrr_settings_update_used_callback (
		struct rrr_setting *settings,
		void *callback_args
) {
	struct rrr_settings_update_used_callback_data *data = callback_args;

	if (strcmp (settings->name, data->name) == 0) {
		if (settings->was_used == 1 && data->was_used == 0) {
			RRR_MSG_0("Warning: Setting %s was marked as used, but python3 config function changed it to not used\n", settings->name);
		}
		settings->was_used = data->was_used;
		data->did_update = 1;
	}

	return 0;
}

void rrr_settings_update_used (
		struct rrr_instance_settings *settings,
		const char *name,
		rrr_u32 was_used,
		int (*iterator)(
				struct rrr_instance_settings *settings,
				int (*callback)(struct rrr_setting *settings, void *callback_args),
				void *callback_args
		)
) {
	struct rrr_settings_update_used_callback_data callback_data = {
			name, was_used, 0
	};

	iterator(settings, __rrr_settings_update_used_callback, &callback_data);

	if (callback_data.did_update != 1) {
		RRR_MSG_0("Warning: Setting %s was not originally set in configuration file, discarding it.\n", name);
	}
}

static int __rrr_setting_pack(struct rrr_setting_packed **target, struct rrr_setting *source) {
	int ret = 0;
	struct rrr_setting_packed *result = NULL;

	*target = NULL;

	if (source->data_size > RRR_SETTINGS_MAX_DATA_SIZE) {
		RRR_MSG_0("Cannot pack setting %s with data size %u, size exceeds limit\n", source->name, source->data_size);
		ret = 1;
		goto out;
	}

	result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in  __rrr_setting_pack\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	result->type = source->type;
	result->was_used = source->was_used;
	result->data_size = source->data_size;
	memcpy(result->name, source->name, sizeof(result->name));
	memcpy(result->data, source->data, source->data_size);

	rrr_msg_populate_head (
			(struct rrr_msg *) result,
			RRR_MSG_TYPE_SETTING,
			sizeof(*result),
			0
	);

	*target = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);

	return ret;
}

int rrr_settings_iterate_packed (
		struct rrr_instance_settings *settings,
		int (*callback)(struct rrr_setting_packed *setting_packed, void *callback_arg),
		void *callback_arg
) {
	int ret = 0;

	__rrr_settings_lock(settings);

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];
		struct rrr_setting_packed *setting_packed = NULL;

		if (__rrr_setting_pack(&setting_packed, setting) != 0) {
			RRR_MSG_0("Could not pack setting in rrr_settings_iterate_packed\n");
			ret = 1;
			goto out;
		}

		ret = callback(setting_packed, callback_arg);

		rrr_free(setting_packed);

		if (ret != 0) {
			break;
		}
	}

	out:
	__rrr_settings_unlock(settings);

	return ret;
}

void rrr_settings_packed_to_host (
		struct rrr_setting_packed *setting_packed
) {
	setting_packed->type = rrr_be32toh(setting_packed->type);
	setting_packed->was_used = rrr_be32toh(setting_packed->was_used);
	setting_packed->data_size = rrr_be32toh(setting_packed->data_size);
}

void rrr_settings_packed_prepare_for_network (
		struct rrr_setting_packed *message
) {
	message->type = rrr_htobe32(message->type);
	message->was_used = rrr_htobe32(message->was_used);
	message->data_size = rrr_htobe32(message->data_size);
}


int rrr_settings_packed_validate (
		const struct rrr_setting_packed *setting
) {
	int ret = 0;

	const char *end = setting->name + sizeof(setting->name) - 1;
	int null_ok = 0;
	for (const char *pos = setting->name; pos != end; pos++) {
		if (*pos == '\0') {
			null_ok = 1;
		}
	}

	if (setting->msg_size != sizeof(*setting)) {
		RRR_MSG_0("Received a setting in rrr_settings_packed_validate with invalid header size field (%u)\n", setting->msg_size);
		ret = 1;
	}
	if (null_ok != 1) {
		RRR_MSG_0("Received a setting in rrr_settings_packed_validate without terminating null-character in its name\n");
		ret = 1;
	}
	if (setting->data_size > sizeof(setting->data)) {
		RRR_MSG_0("Received a setting in rrr_settings_packed_validate with invalid data size field (%u)\n", setting->data_size);
		ret = 1;
	}
	if (setting->type > RRR_SETTINGS_TYPE_MAX) {
		RRR_MSG_0("Received a setting in rrr_settings_packed_validate with invalid type field (%u)\n", setting->type);
		ret = 1;
	}

	return ret;
}
