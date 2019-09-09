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

#include "rrr_socket_msg.h"

#define RRR_SETTINGS_TYPE_STRING 1
#define RRR_SETTINGS_TYPE_UINT 2
#define RRR_SETTINGS_TYPE_MAX 2

#define RRR_SETTING_IS_STRING(setting) ((setting)->type==RRR_SETTINGS_TYPE_STRING)
#define RRR_SETTING_IS_UINT(setting) ((setting)->type==RRR_SETTINGS_TYPE_UINT)

#define RRR_SETTINGS_UINT_AS_TEXT_MAX 64

#define RRR_SETTINGS_MAX_NAME_SIZE 244
#define RRR_SETTINGS_MAX_DATA_SIZE 1024

typedef unsigned int rrr_setting_type;
typedef unsigned long long int rrr_setting_uint;

#define RRR_SETTING_ERROR 1
#define RRR_SETTING_PARSE_ERROR 2
#define RRR_SETTING_NOT_FOUND 3

struct rrr_setting {
	vl_u32 type;
	char name[RRR_SETTINGS_MAX_NAME_SIZE];
	vl_u32 data_size;
	void *data;
	vl_u32 was_used;
};

struct rrr_setting_packed {
	RRR_SOCKET_MSG_HEAD;
	char name[RRR_SETTINGS_MAX_NAME_SIZE];
	vl_u32 type;
	vl_u32 was_used;
	vl_u32 data_size;
	char data[RRR_SETTINGS_MAX_DATA_SIZE];
} __attribute((packed));

struct rrr_instance_settings {
	pthread_mutex_t mutex;
	int initialized;

	unsigned int settings_count;
	unsigned int settings_max;
	struct rrr_setting *settings;
};

struct rrr_settings_list {
	char *data;
	char **list;
	unsigned int length;
};

static inline struct rrr_socket_msg *rrr_setting_safe_cast (struct rrr_setting_packed *setting) {
	struct rrr_socket_msg *ret = (struct rrr_socket_msg *) setting;
	ret->msg_type = RRR_SOCKET_MSG_TYPE_SETTING;
	ret->msg_size = sizeof(*setting);
	ret->msg_value = 0;
	return ret;
}

void rrr_settings_list_destroy (struct rrr_settings_list *list);

struct rrr_instance_settings *rrr_settings_new(const int count);
void rrr_settings_destroy(struct rrr_instance_settings *target);
int rrr_settings_traverse_split_commas (struct rrr_instance_settings *source, const char *name,
		int (*callback)(const char *value, void *arg), void *arg);
int rrr_settings_traverse_split_commas_silent_fail (struct rrr_instance_settings *source, const char *name,
		int (*callback)(const char *value, void *arg), void *arg);
int rrr_settings_split_commas_to_array (struct rrr_settings_list **target, struct rrr_instance_settings *source, const char *name);
int rrr_settings_get_string_noconvert (char **target, struct rrr_instance_settings *source, const char *name);
int rrr_settings_get_string_noconvert_silent (char **target, struct rrr_instance_settings *source, const char *name);
int rrr_settings_replace_string (struct rrr_instance_settings *target, const char *name, const char *value);
int rrr_settings_add_string (struct rrr_instance_settings *target, const char *name, const char *value);
int rrr_settings_replace_unsigned_integer (struct rrr_instance_settings *target, const char *name, rrr_setting_uint value);
int rrr_settings_add_unsigned_integer (struct rrr_instance_settings *target, const char *name, rrr_setting_uint value);
int rrr_settings_setting_to_string_nolock (char **target, struct rrr_setting *setting);
int rrr_settings_setting_to_uint_nolock (rrr_setting_uint *target, struct rrr_setting *setting);
int rrr_settings_read_string (char **target, struct rrr_instance_settings *settings, const char *name);
int rrr_settings_read_unsigned_integer (rrr_setting_uint *target, struct rrr_instance_settings *settings, const char *name);
int rrr_settings_check_yesno (int *result, struct rrr_instance_settings *settings, const char *name);
int rrr_settings_check_all_used (struct rrr_instance_settings *settings);
int rrr_settings_dump (struct rrr_instance_settings *settings);
int rrr_settings_iterate_nolock (
		struct rrr_instance_settings *settings,
		int (*callback)(struct rrr_setting *settings, void *callback_args),
		void *callback_args
);
int rrr_settings_iterate (
		struct rrr_instance_settings *settings,
		int (*callback)(struct rrr_setting *settings, void *callback_args),
		void *callback_args
);
int rrr_settings_iterate_packed (
		struct rrr_instance_settings *settings,
		int (*callback)(struct rrr_setting_packed *setting_packed, void *callback_arg),
		void *callback_arg
);
void rrr_settings_update_used (
		struct rrr_instance_settings *settings,
		const char *name,
		int was_used,
		int (*iterator)(
				struct rrr_instance_settings *settings,
				int (*callback)(struct rrr_setting *settings, void *callback_args),
				void *callback_args
		)
);
void rrr_settings_packed_to_host (struct rrr_setting_packed *setting_packed);
void rrr_settings_packed_prepare_for_network (struct rrr_setting_packed *message);
int rrr_settings_packed_validate (const struct rrr_setting_packed *setting_packed);

#endif /* RRR_SETTINGS_H */
