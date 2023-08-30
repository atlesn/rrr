/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_ARRAY_H
#define RRR_ARRAY_H

#include <stdint.h>
#include <stdio.h>

#include "type.h"
#include "fixed_point.h"
#include "read_constants.h"
#include "cmdlineparser/cmdline.h"
#include "util/linked_list.h"
#include "rrr_inttypes.h"

#define RRR_ARRAY_VERSION 7

#define RRR_ARRAY_OK 				RRR_READ_OK
#define RRR_ARRAY_HARD_ERROR		RRR_READ_HARD_ERROR
#define RRR_ARRAY_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_ARRAY_PARSE_INCOMPLETE	RRR_READ_INCOMPLETE
#define RRR_ARRAY_ITERATE_STOP	RRR_READ_EOF

struct rrr_map;
struct rrr_msg_msg;
struct rrr_nullsafe_str;

struct rrr_array_value_packed {
	rrr_type type;
	rrr_type_flags flags;
	rrr_length tag_length;
	rrr_length total_length;
	rrr_length elements;
	char data[1];
} __attribute((packed));

struct rrr_array {
	RRR_LL_HEAD(struct rrr_type_value);
	RRR_LL_NODE(struct rrr_array);
	uint16_t version;
};

struct rrr_array_collection {
	RRR_LL_HEAD(struct rrr_array);
};

int rrr_array_clone_without_data (
		struct rrr_array *target,
		const struct rrr_array *source
);
int rrr_array_append_from (
		struct rrr_array *target,
		const struct rrr_array *source
);
int rrr_array_clone (
		struct rrr_array **target,
		const struct rrr_array *source
);
int rrr_array_push_value_vain_with_tag (
		struct rrr_array *array,
		const char *tag
);
int rrr_array_push_value_u64_with_tag (
		struct rrr_array *array,
		const char *tag,
		uint64_t value
);
int rrr_array_push_value_i64_with_tag (
		struct rrr_array *array,
		const char *tag,
		int64_t value
);
int rrr_array_push_value_fixp_with_tag (
		struct rrr_array *array,
		const char *tag,
		rrr_fixp value
);
int rrr_array_push_value_str_with_tag_with_size (
		struct rrr_array *array,
		const char *tag,
		const char *value,
		rrr_length value_size
);
int rrr_array_push_value_blob_with_tag_with_size (
		struct rrr_array *array,
		const char *tag,
		const char *value,
		rrr_length value_size
);
int rrr_array_push_value_blob_with_tag_nullsafe (
		struct rrr_array *array,
		const char *tag,
		const struct rrr_nullsafe_str *str
);
int rrr_array_push_value_str_with_tag_nullsafe (
		struct rrr_array *array,
		const char *tag,
		const struct rrr_nullsafe_str *str
);
int rrr_array_push_value_str_with_tag (
		struct rrr_array *array,
		const char *tag,
		const char *value
);
int rrr_array_get_value_unsigned_64_by_tag (
		uint64_t *result,
		struct rrr_array *array,
		const char *tag,
		unsigned int index
);
int rrr_array_get_value_signed_64_by_tag (
		int64_t *result,
		struct rrr_array *array,
		const char *tag,
		unsigned int index
);
int rrr_array_get_value_str_by_tag (
		char **result,
		struct rrr_array *array,
		const char *tag
);
/* TODO : Standardize function call names (with or without index argumemt) */
int rrr_array_get_value_first_unsigned_64_by_tag (
		uint64_t *result,
		struct rrr_array *array,
		const char *tag
);
int rrr_array_get_value_first_str_by_tag (
		char **result,
		struct rrr_array *array,
		const char *tag
);
int rrr_array_get_value_first_ull_by_tag (
		unsigned long long *result,
		struct rrr_array *array,
		const char *tag
);
void rrr_array_strip_type (
		struct rrr_array *array,
		const struct rrr_type_definition *definition
);
void rrr_array_clear (
		struct rrr_array *array
);
void rrr_array_clear_void (
		void *array
);
void rrr_array_clear_by_tag_checked (
		unsigned int *cleared_count,
		struct rrr_array *array,
		const char *tag
);
void rrr_array_clear_by_tag (
		struct rrr_array *array,
		const char *tag
);
void rrr_array_destroy (
		struct rrr_array *array
);
void rrr_array_collection_clear (
		struct rrr_array_collection *collection
);
void rrr_array_trim (
		struct rrr_array *array,
		int target_length
);
void rrr_array_rotate_reverse (
		struct rrr_array *array
);
void rrr_array_rotate_forward (
		struct rrr_array *array
);
struct rrr_type_value *rrr_array_value_get_by_index (
		struct rrr_array *definition,
		int idx
);
struct rrr_type_value *rrr_array_value_get_by_tag (
		struct rrr_array *definition,
		const char *tag
);
const struct rrr_type_value *rrr_array_value_get_by_tag_const (
		const struct rrr_array *definition,
		const char *tag
);
int rrr_array_has_tag (
		const struct rrr_array *definition,
		const char *tag
);
int rrr_array_selected_tags_split (
		int *found_tags,
		const struct rrr_array *definition,
		const struct rrr_map *tags,
		int (*callback)(const struct rrr_type_value *node_orig, const struct rrr_array *node_values, void *arg),
		void *callback_arg
);
int rrr_array_selected_tags_export (
		char **target,
		rrr_biglength *target_size,
		int *found_tags,
		const struct rrr_array *definition,
		const struct rrr_map *tags
);
int rrr_array_new_message_from_array (
		struct rrr_msg_msg **final_message,
		const struct rrr_array *definition,
		uint64_t time,
		const char *topic,
		rrr_u16 topic_length
);
int rrr_array_message_iterate (
		const struct rrr_msg_msg *message_orig,
		int (*callback)(RRR_TYPE_RAW_FIELDS, void *arg),
		void *callback_arg
);
int rrr_array_message_iterate_values (
		const struct rrr_msg_msg *message_orig,
		int (*callback)(
				const struct rrr_type_value *value,
				void *arg
		),
		void *callback_arg
);
int rrr_array_message_has_tag (
		const struct rrr_msg_msg *message_orig,
		const char *tag
);
int rrr_array_message_clone_value_by_tag (
		struct rrr_type_value **target,
		const struct rrr_msg_msg *message_orig,
		const char *tag
);
int rrr_array_message_append_to_array_by_tag (
		struct rrr_array *target,
		const struct rrr_msg_msg *message_orig,
		const char *tag
);
int rrr_array_message_append_to_array (
		uint16_t *array_version,
		struct rrr_array *target,
		const struct rrr_msg_msg *message_orig
);
int rrr_array_dump (
		const struct rrr_array *definition
);
rrr_biglength rrr_array_get_allocated_size (
		const struct rrr_array *definition
);
static inline int rrr_array_count(const struct rrr_array *array) {
	return RRR_LL_COUNT(array);
}

#endif /* RRR_ARRAY_H */
