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

#include "settings.h"
#include "../global.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

int __rrr_settings_init(struct rrr_module_settings *target, const int count) {
	memset(target, '\0', sizeof(*target));

	target->settings = malloc(sizeof(*(target->settings)) * count);
	if (target->settings == NULL) {
		VL_MSG_ERR("Could not allocate memory for settings structure\n");
		return 1;
	}

	target->settings_max = count;
	target->settings_count = 0;
	pthread_mutex_init(&target->mutex, NULL);

	target->initialized = 1;

	return 0;
}

struct rrr_module_settings *rrr_settings_new(const int count) {
	struct rrr_module_settings *ret = malloc(sizeof(*ret));

	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory for module settings structure");
	}

	if (__rrr_settings_init(ret, count) != 0) {
		free(ret);
		return NULL;
	}

	return ret;
}

void __rrr_settings_destroy_setting(struct rrr_setting *setting) {
	free(setting->data);
}

void rrr_settings_destroy(struct rrr_module_settings *target) {
	pthread_mutex_lock(&target->mutex);

	if (target->initialized != 1) {
		VL_MSG_ERR("BUG: Tried to double-destroy settings structure\n");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < target->settings_count; i++) {
		__rrr_settings_destroy_setting(&target->settings[i]);
	}

	target->settings_count = 0;
	target->settings_max = 0;
	target->initialized = 0;

	pthread_mutex_unlock(&target->mutex);
	pthread_mutex_destroy(&target->mutex);

	free(target->settings);
	free(target);
}

void __rrr_settings_lock(struct rrr_module_settings *settings) {
	if (settings->initialized != 1) {
		VL_MSG_ERR("BUG: Tried to lock destroyed settings structure\n");
		exit(EXIT_FAILURE);
	}
	VL_DEBUG_MSG_4 ("Settings %p lock\n", settings);
	pthread_mutex_lock(&settings->mutex);
}

void __rrr_settings_unlock(struct rrr_module_settings *settings) {
	if (settings->initialized != 1) {
		VL_MSG_ERR("BUG: Tried to unlock destroyed settings structure\n");
		exit(EXIT_FAILURE);
	}
	VL_DEBUG_MSG_4 ("Settings %p unlock\n", settings);
	pthread_mutex_unlock(&settings->mutex);
}

struct rrr_setting *__rrr_settings_find_setting_nolock (struct rrr_module_settings *source, const char *name) {
	for (int i = 0; i < source->settings_count; i++) {
		struct rrr_setting *test = &source->settings[i];

		if (strcmp(test->name, name) == 0) {
			return test;
		}
	}

	return NULL;
}

struct rrr_setting *__rrr_settings_reserve_nolock (struct rrr_module_settings *target, const char *name) {
	struct rrr_setting *ret = NULL;

	if (target->settings_count > target->settings_max) {
		VL_MSG_ERR("BUG: setting_count was > settings_max");
		exit(EXIT_FAILURE);
	}

	if (target->settings_count == target->settings_max) {
		VL_MSG_ERR("Could not reserve setting because the maximum number of settings (%d) was reached",
				target->settings_max);
		return NULL;
	}

	if (__rrr_settings_find_setting_nolock(target, name) != NULL) {
		VL_MSG_ERR("Settings name %s defined twice\n", name);
		return NULL;
	}

	int pos = target->settings_count;
	target->settings_count++;

	ret = &target->settings[pos];

	return ret;
}

int __rrr_settings_set_setting_name(struct rrr_setting *setting, const char *name) {
	if (strlen(name) + 1 > RRR_SETTINGS_MAX_NAME_SIZE) {
		VL_MSG_ERR("Settings name %s was longer than maximum %d\n", name, RRR_SETTINGS_MAX_NAME_SIZE);
		return 1;
	}

	sprintf(setting->name, "%s", name);

	return 0;
}

int __rrr_settings_add_raw (struct rrr_module_settings *target, const char *name, const void *old_data, const int size, rrr_setting_type type) {
	int ret = 0;

	void *new_data = malloc(size);

	if (new_data == NULL) {
		VL_MSG_ERR("Could not allocate memory for setting struct\n");
		ret = 1;
		goto out;
	}

	memcpy(new_data, old_data, size);

	__rrr_settings_lock(target);

	struct rrr_setting *setting = __rrr_settings_reserve_nolock(target, name);
	if (setting == NULL) {
		VL_MSG_ERR("Could not create setting struct for %s\n", name);
		ret = 1;
		goto out_unlock;
	}

	if (__rrr_settings_set_setting_name(setting, name) != 0) {
		goto out_unlock;
	}

	setting->data = new_data;
	setting->data_size = size;
	setting->type = type;

	out_unlock:
	if (ret != 0) {
		if (new_data != NULL) {
			free(new_data);
		}
	}

	__rrr_settings_unlock(target);

	out:
	return ret;
}

int rrr_settings_get_string_noconvert (char **target, struct rrr_module_settings *source, const char *name) {
	int ret = 0;
	*target = NULL;

	__rrr_settings_lock(source);

	struct rrr_setting *setting = __rrr_settings_find_setting_nolock(source, name);

	if (setting == NULL) {
		VL_MSG_ERR("Could not locate setting '%s'\n", name);
		ret = 1;
		goto out;
	}

	if (setting->type != RRR_SETTINGS_TYPE_STRING) {
		VL_MSG_ERR("Tried to get string value of %s with no conversion but it was of wrong type %d\n", setting->name, setting->type);
		ret = 1;
		goto out;
	}

	if (setting->data_size <= 1) {
		VL_MSG_ERR("BUG: Data size was <= 1 in rrr_settings_get_string_noconvert\n");
		exit(EXIT_FAILURE);
	}

	const char *data = setting->data;

	if (data[setting->data_size - 1] != '\0') {
		VL_MSG_ERR("BUG: Data string type was not null terminated in rrr_settings_get_string_noconvert\n");
		exit(EXIT_FAILURE);
	}

	char *string = malloc(setting->data_size);
	if (string == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_settings_get_string_noconvert\n");
		ret = 1;
		goto out;
	}

	memcpy(string, data, setting->data_size);

	*target = string;

	out:
	__rrr_settings_unlock(source);
	return ret;
}

int rrr_settings_traverse_split_commas (
		struct rrr_module_settings *source, const char *name,
		int (*callback)(const char *value, void *arg), void *arg
) {
	int ret = 0;

	char *value = NULL;

	if (rrr_settings_get_string_noconvert (&value, source, name) != 0) {
		VL_MSG_ERR("Could not get setting %s for comma splitting\n", name);
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
		current_pos = comma_pos + 1;
	}

	out:
	if (value != NULL) {
		free(value);
	}
	return ret;
}


int rrr_settings_add_string (struct rrr_module_settings *target, const char *name, const char *value) {
	const void *data = value;
	int size = strlen(value) + 1;

	return __rrr_settings_add_raw(target, name, data, size, RRR_SETTINGS_TYPE_STRING);
}

int rrr_settings_add_unsigned_integer (struct rrr_module_settings *target, const char *name, rrr_setting_uint value) {
	const void *data = &value;
	int size = sizeof(rrr_setting_uint);

	return __rrr_settings_add_raw(target, name, data, size, RRR_SETTINGS_TYPE_UINT);
}

int __rrr_settings_setting_to_string (char **target, struct rrr_setting *setting) {
	int ret = 0;
	*target = NULL;

	char *value;
	if (setting->type == RRR_SETTINGS_TYPE_STRING) {
		if ((value = malloc(setting->data_size)) == NULL) {
			goto out_malloc_err;
		}
		sprintf(value, "%s", (char*) setting->data);
	}
	else if (setting->type == RRR_SETTINGS_TYPE_UINT) {
		if ((value = malloc(RRR_SETTINGS_UINT_AS_TEXT_MAX)) == NULL) {
			goto out_malloc_err;
		}
		sprintf(value, "%llu", *((unsigned long long *) setting->data));
	}
	else {
		VL_MSG_ERR("BUG: Could not convert setting of type %d to string\n", setting->type);
		exit (EXIT_FAILURE);
	}

	*target = value;

	return ret;

	out_malloc_err:
	VL_MSG_ERR("Could not allocate memory while converting setting to string");
	return 1;
}

int __rrr_settings_setting_to_uint (rrr_setting_uint *target, struct rrr_setting *setting) {
	if (setting->type == RRR_SETTINGS_TYPE_UINT) {
		if (sizeof(*target) != setting->data_size) {
			VL_MSG_ERR("BUG: Setting unsigned integer size mismatch\n");
		}
		target = setting->data;
	}
	else {
		VL_MSG_ERR("BUG: Could not convert setting of type %d to string\n", setting->type);
		exit (EXIT_FAILURE);
	}

	return 0;
}

int rrr_settings_read_string (char **target, struct rrr_module_settings *settings, const char *name) {
	int ret = 0;
	*target = NULL;

	__rrr_settings_lock(settings);

	struct rrr_setting *setting = __rrr_settings_find_setting_nolock(settings, name);
	if (setting == NULL) {
		ret = 1;
		goto out_unlock;
	}

	ret = __rrr_settings_setting_to_string (target, setting);

	out_unlock:
	__rrr_settings_unlock(settings);

	return ret;
}

int rrr_settings_read_unsigned_integer (rrr_setting_uint *target, struct rrr_module_settings *settings, const char *name) {
	int ret = 0;
	*target = 0;

	__rrr_settings_lock(settings);

	struct rrr_setting *setting = __rrr_settings_find_setting_nolock(settings, name);
	if (setting == NULL) {
		ret = 1;
		goto out_unlock;
	}

	ret = __rrr_settings_setting_to_uint (target, setting);

	out_unlock:
	__rrr_settings_unlock(settings);

	return ret;
}

int rrr_settings_dump (struct rrr_module_settings *settings) {
	int ret = 0;

	for (int i = 0; i < settings->settings_count; i++) {
		struct rrr_setting *setting = &settings->settings[i];

		const char *name = setting->name;
		char *value;
		ret = __rrr_settings_setting_to_string(&value, setting);

		if (ret != 0) {
			VL_MSG_ERR("Error in settings dump function\n");
			break;
		}

		printf("%s=%s\n", name, value);

		free(value);
	}

	return ret;
}
