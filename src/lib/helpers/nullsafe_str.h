/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include "../type.h"

struct rrr_nullsafe_str {
	void *str;
	rrr_length len;
};

void rrr_nullsafe_str_destroy_if_not_null (
	struct rrr_nullsafe_str **str
);
void rrr_nullsafe_str_move (
		struct rrr_nullsafe_str **target,
		struct rrr_nullsafe_str **source
);
int rrr_nullsafe_str_new_or_replace (
	struct rrr_nullsafe_str **result,
	const void *str,
	rrr_length len
);
int rrr_nullsafe_str_append (
		struct rrr_nullsafe_str *nullsafe,
		const void *str,
		rrr_length len
);
void rrr_nullsafe_str_set_allocated (
	struct rrr_nullsafe_str *str,
	void **ptr,
	rrr_length len
);
int rrr_nullsafe_str_set (
	struct rrr_nullsafe_str *nullsafe,
	const void *src,
	rrr_length len
);
const char *rrr_nullsafe_str_chr (
	const struct rrr_nullsafe_str *nullsafe,
	char c
);
int rrr_nullsafe_str_dup (
	struct rrr_nullsafe_str **target,
	const struct rrr_nullsafe_str *source
);
rrr_length rrr_nullsafe_str_len (
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
void rrr_nullsafe_str_output_strip_null_append_null_trim (
	const struct rrr_nullsafe_str *nullsafe,
	char *buf,
	rrr_length buf_size
);
void rrr_nullsafe_str_copyto (
	rrr_length *written_size,
	void *target,
	rrr_length target_size,
	const struct rrr_nullsafe_str *nullsafe
);

#endif /* RRR_NULLSAFE_STR_H */
