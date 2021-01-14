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

#ifndef RRR_STRING_BUILDER_H
#define RRR_STRING_BUILDER_H

#include "type.h"

struct rrr_string_builder {
	rrr_biglength size;
	rrr_biglength wpos;
	char *buf;
};

#define RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder,str,err_str)		\
		do {if (rrr_string_builder_append((string_builder), str) != 0) {	\
			RRR_MSG_0("%s", err_str);										\
			ret = 1;														\
			goto out;														\
		}} while(0)

#define RRR_STRING_BUILDER_RESERVE_AND_CHECK(string_builder,bytes,err_str)	\
		do {if (rrr_string_builder_reserve((string_builder), bytes) != 0) {	\
			RRR_MSG_0("%s", err_str);										\
			ret = 1;														\
			goto out;														\
		}} while(0)

#define RRR_STRING_BUILDER_UNCHECKED_APPEND(string_builder,str)				\
	rrr_string_builder_unchecked_append(string_builder,str)

void rrr_string_builder_unchecked_append (
		struct rrr_string_builder *string_builder,
		const char *str
);
char *rrr_string_builder_buffer_takeover (
		struct rrr_string_builder *string_builder
);
void rrr_string_builder_clear (
		struct rrr_string_builder *string_builder
);
const char *rrr_string_builder_buf (
		const struct rrr_string_builder *string_builder
);
rrr_biglength rrr_string_builder_length (
		const struct rrr_string_builder *string_builder
);
rrr_biglength rrr_string_builder_size (
		const struct rrr_string_builder *string_builder
);
int rrr_string_builder_new (
		struct rrr_string_builder **result
);
void rrr_string_builder_destroy (
		struct rrr_string_builder *string_builder
);
void rrr_string_builder_destroy_void (
		void *ptr
);
int rrr_string_builder_reserve (
		struct rrr_string_builder *string_builder,
		rrr_biglength bytes
);
int rrr_string_builder_append_from (
		struct rrr_string_builder *target,
		const struct rrr_string_builder *source
);
int rrr_string_builder_append_raw (
		struct rrr_string_builder *target,
		const char *str,
		rrr_biglength length
);
int rrr_string_builder_append (
		struct rrr_string_builder *string_builder,
		const char *str
);
int rrr_string_builder_append_format (
		struct rrr_string_builder *string_builder,
		const char *format,
		...
);

#endif /* RRR_STRING_BUILDER_H */
