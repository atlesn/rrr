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

#ifndef RRR_SETTINGS_H
#define RRR_SETTINGS_H

#include <limits.h>

#include "messages/msg.h"
#include "util/utf8.h"
#include "read_constants.h"
#include "rrr_types.h"

#define RRR_SETTINGS_TYPE_STRING 1
#define RRR_SETTINGS_TYPE_UINT 2
#define RRR_SETTINGS_TYPE_DOUBLE 3
#define RRR_SETTINGS_TYPE_MAX 3

#define RRR_SETTING_IS_STRING(setting) ((setting)->type==RRR_SETTINGS_TYPE_STRING)
#define RRR_SETTING_IS_UINT(setting) ((setting)->type==RRR_SETTINGS_TYPE_UINT)

#define RRR_SETTINGS_UINT_AS_TEXT_MAX 64
#define RRR_SETTINGS_LDBL_AS_TEXT_MAX 512

#define RRR_SETTINGS_MAX_NAME_SIZE 244
#define RRR_SETTINGS_MAX_DATA_SIZE 1024

typedef rrr_biglength rrr_setting_uint;
typedef long double rrr_setting_double;

// Use bit flag compatible values
#define RRR_SETTING_ERROR			RRR_READ_HARD_ERROR
#define RRR_SETTING_PARSE_ERROR		RRR_READ_SOFT_ERROR
#define RRR_SETTING_NOT_FOUND		RRR_READ_INCOMPLETE

struct rrr_setting {
	rrr_u32 type;
	char name[RRR_SETTINGS_MAX_NAME_SIZE];
	rrr_u32 data_size;
	void *data;
};

struct rrr_setting_packed {
	RRR_MSG_HEAD;
	char name[RRR_SETTINGS_MAX_NAME_SIZE];
	rrr_u32 type;
	rrr_u32 was_used;
	rrr_u32 data_size;
	char data[RRR_SETTINGS_MAX_DATA_SIZE];
} __attribute((packed));

struct rrr_settings {
	int initialized;

	rrr_length settings_count;
	rrr_length settings_max;
	struct rrr_setting *settings;
};

struct rrr_settings_used {
	rrr_u8 *was_used;
};

struct rrr_settings_list {
	char *data;
	char **list;
	rrr_length length;
};

struct rrr_settings *rrr_settings_new (
		const rrr_length count
);
struct rrr_settings *rrr_settings_copy (
		const struct rrr_settings *source
);
int rrr_settings_used_init (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings
);
int rrr_settings_used_copy (
		struct rrr_settings_used *target,
		const struct rrr_settings_used *source,
		const struct rrr_settings *settings
);
void rrr_settings_used_cleanup (
		struct rrr_settings_used *used
);
void rrr_settings_destroy (
		struct rrr_settings *target
);
int rrr_settings_traverse_split_commas (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg),
		void *arg
);
int rrr_settings_traverse_split_commas_silent_fail (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name,
		int (*callback)(const char *value, void *arg),
		void *arg
);
int rrr_settings_split_commas_to_array (
		struct rrr_settings_list **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
);
int rrr_settings_exists (
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
);
int rrr_settings_get_string_noconvert (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
);
int rrr_settings_get_string_noconvert_silent (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *source,
		const char *name
);
int rrr_settings_replace_string (
		struct rrr_settings *target,
		const char *name,
		const char *value
);
int rrr_settings_add_string (
		struct rrr_settings *target,
		const char *name,
		const char *value
);
int rrr_settings_add_unsigned_integer (
		struct rrr_settings *target,
		const char *name,
		rrr_setting_uint value
);
int rrr_settings_setting_to_string (
		char **target,
		const struct rrr_setting *setting
);
int rrr_settings_setting_to_uint (
		rrr_setting_uint *target,
		const struct rrr_setting *setting
);
int rrr_settings_setting_to_double (
		rrr_setting_double *target,
		const struct rrr_setting *setting
);
int rrr_settings_read_string (
		char **target,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
);
int rrr_settings_read_unsigned_integer (
		rrr_setting_uint *target,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
);
int rrr_settings_read_double (
		rrr_setting_double *target,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
);
int rrr_settings_check_yesno (
		int *result,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
);
int rrr_settings_check_all_used (
		const struct rrr_settings *settings,
		const struct rrr_settings_used *used
);
int rrr_settings_cmpto (
		int *result,
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name,
		const char *value
);
int rrr_settings_dump (
		const struct rrr_settings *settings
);
int rrr_settings_iterate (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		int (*callback)(int *was_used, const struct rrr_setting *setting, void *callback_args),
		void *callback_args
);
int rrr_settings_iterate_packed (
		const struct rrr_settings *settings,
		const struct rrr_settings_used *used,
		int (*callback)(const struct rrr_setting_packed *setting_packed, void *callback_arg),
		void *callback_arg
);
void rrr_settings_set_used (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
);
void rrr_settings_set_unused (
		struct rrr_settings_used *used,
		const struct rrr_settings *settings,
		const char *name
);
void rrr_settings_packed_to_host (
		struct rrr_setting_packed *setting_packed
);
void rrr_settings_packed_prepare_for_network (
		struct rrr_setting_packed *message
);
int rrr_settings_packed_validate (
		const struct rrr_setting_packed *setting_packed
);

#endif /* RRR_SETTINGS_H */
