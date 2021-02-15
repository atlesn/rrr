/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NULLSAFE_STR_H
#define RRR_NULLSAFE_STR_H

#include <stdio.h>

#include "../rrr_types.h"

typedef rrr_length rrr_nullsafe_len;

#define PRIrrr_nullsafe_len PRIrrrl

#define RRR_NULLSAFE_LEN_MAX rrr_nullsafe_len_MAX

struct rrr_nullsafe_str;

void rrr_nullsafe_str_destroy_if_not_null (
		struct rrr_nullsafe_str **str
);
void rrr_nullsafe_str_destroy_if_not_null_void (
		void *str_dbl_ptr
);
void rrr_nullsafe_str_move (
		struct rrr_nullsafe_str **target,
		struct rrr_nullsafe_str **source
);
int rrr_nullsafe_str_new_or_replace_raw (
		struct rrr_nullsafe_str **result,
		const void *str,
		rrr_nullsafe_len len
);
int rrr_nullsafe_str_new_or_replace_raw_allocated (
		struct rrr_nullsafe_str **result,
		void **str,
		rrr_nullsafe_len len
);
int rrr_nullsafe_str_new_or_replace (
		struct rrr_nullsafe_str **result,
		const struct rrr_nullsafe_str *source
);
int rrr_nullsafe_str_new_or_replace_empty (
		struct rrr_nullsafe_str **result
);
int rrr_nullsafe_str_append_raw (
		struct rrr_nullsafe_str *nullsafe,
		const void *str,
		rrr_nullsafe_len len
);
int rrr_nullsafe_str_append_asprintf (
		struct rrr_nullsafe_str *nullsafe,
		const void *format,
		...
);
int rrr_nullsafe_str_append (
		struct rrr_nullsafe_str *target,
		const struct rrr_nullsafe_str *str
);
int rrr_nullsafe_str_append_with_converter (
		struct rrr_nullsafe_str *target,
		const struct rrr_nullsafe_str *str,
		int (*converter_callback)(struct rrr_nullsafe_str **result, const struct rrr_nullsafe_str *str)
);
int rrr_nullsafe_str_append_with_creator (
		struct rrr_nullsafe_str *target,
		int (*creator)(struct rrr_nullsafe_str **result, void *arg),
		void *creator_arg
);
int rrr_nullsafe_str_prepend_raw (
		struct rrr_nullsafe_str *nullsafe,
		const void *str,
		rrr_nullsafe_len len
);
int rrr_nullsafe_str_prepend_asprintf (
		struct rrr_nullsafe_str *nullsafe,
		const void *format,
		...
);
void rrr_nullsafe_str_set_allocated (
		struct rrr_nullsafe_str *str,
		void **ptr,
		rrr_nullsafe_len len
);
int rrr_nullsafe_str_set (
		struct rrr_nullsafe_str *nullsafe,
		const void *src,
		rrr_nullsafe_len len
);
int rrr_nullsafe_str_chr (
		const struct rrr_nullsafe_str *nullsafe,
		char c,
		int (*callback)(const void *start, size_t len_remaining, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_split_raw (
		const struct rrr_nullsafe_str *nullsafe,
		char c,
		int (*callback)(const void *start, size_t chunk_size, int is_last, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_split (
		const struct rrr_nullsafe_str *nullsafe,
		char c,
		int (*callback)(const struct rrr_nullsafe_str *str, int is_last, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_str (
		const struct rrr_nullsafe_str *haystack,
		const struct rrr_nullsafe_str *needle,
		int (*callback)(
				const struct rrr_nullsafe_str *haystack_orig,
				const struct rrr_nullsafe_str *needle_orig,
				const struct rrr_nullsafe_str *pos_at_needle,
				const struct rrr_nullsafe_str *pos_after_needle,
				void *arg
		),
		void *callback_arg
);
int rrr_nullsafe_str_str_raw (
		const void *haystack_str,
		rrr_nullsafe_len haystack_len,
		const struct rrr_nullsafe_str *needle,
		int (*callback)(
				const struct rrr_nullsafe_str *haystack_orig,
				const struct rrr_nullsafe_str *needle_orig,
				const struct rrr_nullsafe_str *pos_at_needle,
				const struct rrr_nullsafe_str *pos_after_needle,
				void *arg
		),
		void *callback_arg
);
int rrr_nullsafe_str_begins_with (
		const struct rrr_nullsafe_str *str,
		const struct rrr_nullsafe_str *substr
);
int rrr_nullsafe_str_dup (
		struct rrr_nullsafe_str **target,
		const struct rrr_nullsafe_str *source
);
rrr_nullsafe_len rrr_nullsafe_str_len (
		const struct rrr_nullsafe_str *nullsafe
);
void rrr_nullsafe_str_tolower (
		struct rrr_nullsafe_str *nullsafe
);
int rrr_nullsafe_str_isset (
		const struct rrr_nullsafe_str *nullsafe
);
int rrr_nullsafe_str_cmpto_case (
		const struct rrr_nullsafe_str *nullsafe,
		const char *str
);
int rrr_nullsafe_str_cmpto (
		const struct rrr_nullsafe_str *nullsafe,
		const char *str
);
void rrr_nullsafe_str_util_output_strip_null_append_null_trim_raw_null_ok (
		char *buf,
		rrr_nullsafe_len buf_size,
		const char *str,
		rrr_nullsafe_len len
);
void rrr_nullsafe_str_output_strip_null_append_null_trim (
		const struct rrr_nullsafe_str *nullsafe,
		char *buf,
		rrr_nullsafe_len buf_size
);
void rrr_nullsafe_str_copyto (
		rrr_nullsafe_len *written_size,
		void *target,
		rrr_nullsafe_len target_size,
		const struct rrr_nullsafe_str *nullsafe
);
int rrr_nullsafe_str_with_str_do (
		const struct rrr_nullsafe_str *str,
		int (*callback)(const struct rrr_nullsafe_str *str, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_with_tmp_str_do (
		const void *str,
		rrr_nullsafe_len len,
		int (*callback)(const struct rrr_nullsafe_str *str, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_with_raw_do (
		struct rrr_nullsafe_str *nullsafe,
		int (*callback)(rrr_nullsafe_len *len, void *str, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_with_raw_null_terminated_do (
		const struct rrr_nullsafe_str *nullsafe,
		int (*callback)(const char *str, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_raw_null_terminated_dump (
		const struct rrr_nullsafe_str *nullsafe
);
int rrr_nullsafe_str_with_raw_do_const (
		const struct rrr_nullsafe_str *nullsafe,
		int (*callback)(const void *str, rrr_nullsafe_len len, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_with_raw_do_double_const (
		const struct rrr_nullsafe_str *nullsafe_a,
		const struct rrr_nullsafe_str *nullsafe_b,
		int (*callback)(const void *str_a, rrr_nullsafe_len len_a, const void *str_b, rrr_nullsafe_len len_b, void *arg),
		void *callback_arg
);
char *rrr_nullsafe_str_with_raw_do_const_return_str (
		const struct rrr_nullsafe_str *nullsafe,
		char *(*callback)(const void *str, rrr_nullsafe_len len, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_with_raw_truncated_do (
		const struct rrr_nullsafe_str *nullsafe,
		rrr_nullsafe_len pos,
		rrr_nullsafe_len len,
		int (*callback)(const void *str, rrr_nullsafe_len len, void *arg),
		void *callback_arg
);
int rrr_nullsafe_str_foreach_byte_do (
		const struct rrr_nullsafe_str *nullsafe,
		int (*callback)(char byte, void *arg),
		void *callback_arg
);

#endif /* RRR_NULLSAFE_STR_H */
