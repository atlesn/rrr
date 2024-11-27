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
		struct rrr_settings *target,
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

	target->settings_max = count;
	target->settings_count = 0;
	target->initialized = 1;

	goto out;
//	out_free:
//		rrr_free(target->settings);
	out:
		return ret;
}

struct rrr_settings *rrr_settings_new (
		const rrr_length count
) {
	struct rrr_settings *ret = rrr_allocate(sizeof(*ret));

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

struct rrr_settings *rrr_settings_copy (
		const struct rrr_settings *source
) {
	struct rrr_settings *settings;
	void *data;

	if ((settings = rrr_settings_new(source->settings_max)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		goto out;
	}

	settings->settings_count = source->settings_count;
	settings->settings_max = source->settings_max;

	for (unsigned int i = 0; i < source->settings_count; i++) {
		const struct rrr_setting *setting_source = &source->settings[i];
		struct rrr_setting *setting_target = &settings->settings[i];

		if ((data = rrr_allocate_zero(setting_source->data_size)) == NULL) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			goto out_destroy;
		}

		memcpy(data, setting_source->data, setting_source->data_size);
		memcpy(setting_target, setting_source, sizeof(*setting_target));

		setting_target->data = data;
	}

	goto out;
	out_destroy:
		rrr_settings_destroy(settings);
		settings = NULL;
	out:
		return settings;
}

int rrr_settings_used_init (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings
) {
	assert(used->was_used == NULL && "already initialized");

	if ((used->was_used = rrr_allocate_zero(sizeof(*used->was_used) * settings->settings_max)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return 1;
	}

	return 0;
}

int rrr_settings_used_copy (
		struct rrr_settings_used *target,
		const struct rrr_settings_used *source,
		const struct rrr_settings *settings
) {
	int ret = 0;

	if ((ret = rrr_settings_used_init(target, settings)) != 0) {
		goto out;
	}

	memcpy(target->was_used, source->was_used, sizeof(*target->was_used) * settings->settings_max);

	out:
	return ret;
}

void rrr_settings_used_cleanup (
		struct rrr_settings_used *used
) {
	rrr_free(used->was_used);
	used->was_used = NULL;
}

static void __rrr_settings_destroy_setting (
		struct rrr_setting *setting
) {
	rrr_free(setting->data);
}

void rrr_settings_destroy (
		struct rrr_settings *target
) {
	if (target->initialized != 1) {
		RRR_BUG("BUG: Tried to double-destroy settings structure\n");
	}

	for (unsigned int i = 0; i < target->settings_count; i++) {
		__rrr_settings_destroy_setting(&target->settings[i]);
	}

	target->settings_count = 0;
	target->settings_max = 0;
	target->initialized = 0;

	rrr_free(target->settings);
	rrr_free(target);
}

static struct rrr_setting *__rrr_settings_find_setting (
		struct rrr_settings *source,
		const char *name
) {
	for (unsigned int i = 0; i < source->settings_count; i++) {
		struct rrr_setting *test = &source->settings[i];

		if (strcmp(test->name, name) == 0) {
			return test;
		}
	}

	return NULL;
}

static const struct rrr_setting *__rrr_settings_find_setting_const (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
) {
	for (unsigned int i = 0; i < source->settings_count; i++) {
		struct rrr_setting *test = &source->settings[i];

		if (strcmp(test->name, name) == 0) {
			if (used != NULL)
				used->was_used[i] = 1;
			return test;
		}
	}

	return NULL;
}

static struct rrr_setting *__rrr_settings_reserve (
		struct rrr_settings *target,
		const char *name,
		int return_existing
) {
	struct rrr_setting *ret = NULL;

	if ((ret = __rrr_settings_find_setting(target, name)) != NULL) {
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
		struct rrr_settings *target,
		const char *name,
		const void *old_data,
		const rrr_length size,
		rrr_u32 type,
		int replace_existing
) {
	int ret = 0;

	struct rrr_setting *setting;
	void *new_data;

	if ((new_data = rrr_allocate(size)) == NULL) {
		RRR_MSG_0("Could not allocate memory for setting struct\n");
		ret = 1;
		goto out;
	}

	memcpy(new_data, old_data, size);

	if ((setting = __rrr_settings_reserve(target, name, replace_existing)) == NULL) {
		RRR_MSG_0("Could not create setting struct for %s\n", name);
		ret = 1;
		goto out_free;
	}

	memset (setting, '\0', sizeof(*setting));

	if ((ret = __rrr_settings_set_setting_name(setting, name)) != 0) {
		goto out_free;
	}

	setting->data = new_data;
	setting->data_size = size;
	setting->type = type;

	goto out;
	out_free:
		rrr_free(new_data);
	out:
		return ret;
}

static int __rrr_settings_get_string_noconvert (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name,
		int silent_not_found
) {
	int ret = 0;
	*target = NULL;

	const struct rrr_setting *setting;

	if ((setting = __rrr_settings_find_setting_const(used, source, name)) == NULL) {
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
	return ret;
}

int rrr_settings_exists (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
) {
	int ret = 0;

	if (__rrr_settings_find_setting_const(used, source, name) != NULL) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_settings_get_string_noconvert (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
) {
	return __rrr_settings_get_string_noconvert(target, used, source, name, 0);
}

int rrr_settings_get_string_noconvert_silent (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
) {
	return __rrr_settings_get_string_noconvert(target, used, source, name, 1);
}

static int __rrr_settings_traverse_split_commas (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg), void *arg,
		int silent_fail
) {
	int ret = 0;

	char *value = NULL;

	if (__rrr_settings_get_string_noconvert (&value, used, source, name, silent_fail) != 0) {
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
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg), void *arg
) {
	return __rrr_settings_traverse_split_commas(used, source, name, callback, arg, 0);
}

int rrr_settings_traverse_split_commas_silent_fail (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg), void *arg
) {
	return __rrr_settings_traverse_split_commas(used, source, name, callback, arg, 1);
}

int rrr_settings_split_commas_to_array (
		struct rrr_settings_list **target_ptr,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
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

	if (rrr_settings_get_string_noconvert (&value, used, source, name) != 0) {
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
		struct rrr_settings *target,
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
		struct rrr_settings *target,
		const char *name,
		const char *value
) {
	return __rrr_settings_replace_or_add_string(target, name, value, 1 /* Do replace */);
}

int rrr_settings_add_string (
		struct rrr_settings *target,
		const char *name,
		const char *value
) {
	return __rrr_settings_replace_or_add_string(target, name, value, 0 /* Do not replace */);
}

int rrr_settings_add_unsigned_integer (
		struct rrr_settings *target,
		const char *name,
		rrr_setting_uint value
) {
	return __rrr_settings_add_raw(target, name, &value, sizeof(value), RRR_SETTINGS_TYPE_UINT, 0);
}

int rrr_settings_setting_to_string (
		char **target,
		const struct rrr_setting *setting
) {
	int ret = 0;
	*target = NULL;

	char *value;
	if (setting->type == RRR_SETTINGS_TYPE_STRING) {
		if ((value = rrr_allocate(setting->data_size + 1)) == NULL) {
			goto out_malloc_err;
		}
		sprintf(value, "%s", (char*) setting->data);
	}
	else if (setting->type == RRR_SETTINGS_TYPE_UINT) {
		if ((value = rrr_allocate(RRR_SETTINGS_UINT_AS_TEXT_MAX)) == NULL) {
			goto out_malloc_err;
		}
		snprintf(value, RRR_SETTINGS_UINT_AS_TEXT_MAX, "%llu", *((unsigned long long *) setting->data));
		value[RRR_SETTINGS_UINT_AS_TEXT_MAX - 1] = '\0';
	}
	else if (setting->type == RRR_SETTINGS_TYPE_DOUBLE) {
		if ((value = rrr_allocate(RRR_SETTINGS_LDBL_AS_TEXT_MAX)) == NULL) {
			goto out_malloc_err;
		}
		snprintf(value, RRR_SETTINGS_LDBL_AS_TEXT_MAX, "%Lf", *((rrr_setting_double *) setting->data));
		value[RRR_SETTINGS_LDBL_AS_TEXT_MAX - 1] = '\0';
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

int rrr_settings_setting_to_uint (
		rrr_setting_uint *target,
		const struct rrr_setting *setting
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
	if (setting->type == RRR_SETTINGS_TYPE_DOUBLE) {
		if (sizeof(rrr_setting_double) != setting->data_size) {
			RRR_BUG("BUG: Setting double size mismatch\n");
		}
		*target = (rrr_setting_uint) *((rrr_setting_double*) setting->data);
	}
	else if (setting->type == RRR_SETTINGS_TYPE_STRING) {
		ret = rrr_settings_setting_to_string(&tmp_string, setting);
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

int rrr_settings_setting_to_double (
		rrr_setting_double *target,
		const struct rrr_setting *setting
) {
	int ret = 0;
	char *tmp_string = NULL;
	*target = 0;

	if (setting->type == RRR_SETTINGS_TYPE_UINT) {
		if (sizeof(rrr_setting_uint) != setting->data_size) {
			RRR_BUG("BUG: Setting unsigned integer size mismatch\n");
		}
		*target = (rrr_setting_double) *((rrr_setting_uint*) setting->data);
	}
	if (setting->type == RRR_SETTINGS_TYPE_DOUBLE) {
		if (sizeof(rrr_setting_double) != setting->data_size) {
			RRR_BUG("BUG: Setting double size mismatch\n");
		}
		*target = *((rrr_setting_double*) setting->data);
	}
	else if (setting->type == RRR_SETTINGS_TYPE_STRING) {
		ret = rrr_settings_setting_to_string(&tmp_string, setting);
		if (ret != 0) {
			RRR_MSG_0("Could not get string of '%s' while converting to double\n", setting->name);
			goto out;
		}

		// strtoull will accept negative numbers, we need to check here first
		for (unsigned const char *pos = (unsigned const char *) tmp_string; *pos != '\0'; pos++) {
			if ((*pos < '0' || *pos > '9') && *pos != '.') {
				RRR_MSG_0("Unknown character '%c' in supposed double '%s'\n",
						*pos, tmp_string);
				ret = 1;
				goto out;
			}
		}

		char *end;
		rrr_setting_double tmp = strtod(tmp_string, &end);

		if (*end != '\0') {
			ret = RRR_SETTING_PARSE_ERROR;
			RRR_MSG_0("Syntax error while converting setting '%s' with value '%s' to double\n", setting->name, tmp_string);
			goto out;
		}

		*target = tmp;
	}
	else {
		RRR_BUG("BUG: Could not convert setting of type %d to double\n", setting->type);
	}

	out:
	if (tmp_string != NULL) {
		rrr_free(tmp_string);
	}

	return ret;
}

int rrr_settings_read_string (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
) {
	const struct rrr_setting *setting;

	*target = NULL;

	if ((setting = __rrr_settings_find_setting_const(used, settings, name)) == NULL) {
		return RRR_SETTING_NOT_FOUND;
	}

	return rrr_settings_setting_to_string (target, setting);
}

int rrr_settings_read_unsigned_integer (
		rrr_setting_uint *target,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
) {
	const struct rrr_setting *setting;

	*target = 0;

	if ((setting = __rrr_settings_find_setting_const(used, settings, name)) == NULL) {
		return RRR_SETTING_NOT_FOUND;
	}

	return rrr_settings_setting_to_uint (target, setting);
}

int rrr_settings_read_double (
		rrr_setting_double *target,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
) {
	const struct rrr_setting *setting;

	*target = 0;

	if ((setting = __rrr_settings_find_setting_const(used, settings, name)) == NULL) {
		return RRR_SETTING_NOT_FOUND;
	}

	return rrr_settings_setting_to_double (target, setting);
}

int rrr_settings_check_yesno (
		int *result,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
) {
	int ret = 0;

	char *string;

	*result = -1;

	if ((ret = rrr_settings_read_string (&string, used, settings, name)) != 0) {
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

	rrr_free(string);

	out:
	return ret;
}

int rrr_settings_check_all_used (
		const struct rrr_settings *settings,
		const struct rrr_settings_used *used
) {
	int ret = 0;

	const struct rrr_setting *setting;

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		if (!used->was_used[i]) {
			setting = &settings->settings[i];
			RRR_MSG_0("Warning: Setting %s has not been used\n", setting->name);
			ret = 1;
		}
	}

	return ret;
}

int rrr_settings_cmpto (
		int *result,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name,
		const char *value
) {
	int ret = 0;

	*result = 0;

	char *string;

	if ((ret = rrr_settings_read_string (&string, used, settings, name)) != 0) {
		goto out;
	}

	*result = strcmp(string, value);

	rrr_free(string);

	out:
	return ret;
}

int rrr_settings_dump (
		const struct rrr_settings *settings
) {
	int ret = 0;

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];

		const char *name = setting->name;
		char *value;
		ret = rrr_settings_setting_to_string(&value, setting);

		if (ret != 0) {
			RRR_MSG_0("Warning: Error in settings dump function\n");
			goto next;
		}

		RRR_MSG_1("%s=%s\n", name, value);

		next:
		RRR_FREE_IF_NOT_NULL(value);
	}

	return ret;
}

int rrr_settings_iterate (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		int (*callback)(int *was_used, const struct rrr_setting *setting, void *callback_args),
		void *callback_args
) {
	int ret = 0;

	int was_used;
	struct rrr_setting *setting;

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		was_used = used->was_used[i];
		setting = &settings->settings[i];

		if ((ret = callback(&was_used, setting, callback_args)) != 0) {
			goto out;
		}

		used->was_used[i] = was_used != 0;
	}

	out:
	return ret;
}

static void __rrr_settings_set_used (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name,
		int was_used
) {
	for (unsigned int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];

		if (!(strcmp(setting->name, name) == 0))
			continue;

		used->was_used[i] = was_used != 0;

		break;
	}
}

void rrr_settings_set_unused (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
) {
	__rrr_settings_set_used(used, settings, name, 0 /* Unused */);
}

void rrr_settings_set_used (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
) {
	__rrr_settings_set_used(used, settings, name, 1 /* Used */);
}

static int __rrr_setting_pack (
		struct rrr_setting_packed **target,
		const struct rrr_setting *source,
		int was_used
) {
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
	result->was_used = was_used;
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
		const struct rrr_settings *settings,
		const struct rrr_settings_used *used,
		int (*callback)(const struct rrr_setting_packed *setting_packed, void *callback_arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_setting *setting;
	struct rrr_setting_packed *setting_packed;

	for (unsigned int i = 0; i < settings->settings_count; i++) {
		setting = &settings->settings[i];

		if (__rrr_setting_pack(&setting_packed, setting, used->was_used[i]) != 0) {
			RRR_MSG_0("Could not pack setting in %s\n", __func__);
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
