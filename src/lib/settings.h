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

#ifndef RRR_SETTINGS_H
#define RRR_SETTINGS_H

#include <pthread.h>

#include "../global.h"

#define RRR_SETTINGS_TYPE_STRING 1
#define RRR_SETTINGS_TYPE_UINT 1

#define RRR_SETTINGS_UINT_AS_TEXT_MAX 64

#define RRR_SETTINGS_MAX_NAME_SIZE 255

typedef unsigned int rrr_setting_type;
typedef unsigned long long int rrr_setting_uint;

struct rrr_setting {
	int type;
	char name[RRR_SETTINGS_MAX_NAME_SIZE];
	int data_size;
	void *data;
};

struct rrr_module_settings {
	pthread_mutex_t mutex;
	int initialized;

	int settings_count;
	int settings_max;
	struct rrr_setting *settings;
};

struct rrr_module_settings *rrr_settings_new(const int count);
void rrr_settings_destroy(struct rrr_module_settings *target);
int rrr_settings_add_string (struct rrr_module_settings *target, const char *name, const char *value);
int rrr_settings_add_unsigned_integer (struct rrr_module_settings *target, const char *name, rrr_setting_uint value);
int rrr_settings_read_string (char **target, struct rrr_module_settings *settings, const char *name);
int rrr_settings_read_unsigned_integer (rrr_setting_uint *target, struct rrr_module_settings *settings, const char *name);
int rrr_settings_dump (struct rrr_module_settings *settings);

#endif /* RRR_SETTINGS_H */
