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

#include <stdio.h>

struct rrr_string_builder {
	ssize_t size;
	ssize_t wpos;
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

void rrr_string_builder_unchecked_append (struct rrr_string_builder *string_builder, const char *str);
void rrr_string_builder_unchecked_append_raw (struct rrr_string_builder *string_builder, const char *buf, size_t buf_size);
char *rrr_string_builder_buffer_takeover (struct rrr_string_builder *string_builder);
void rrr_string_builder_clear (struct rrr_string_builder *string_builder);
int rrr_string_builder_new (struct rrr_string_builder **result);
void rrr_string_builder_destroy (struct rrr_string_builder *string_builder);
int rrr_string_builder_reserve (struct rrr_string_builder *string_builder, ssize_t bytes);
int rrr_string_builder_append (struct rrr_string_builder *string_builder, const char *str);

#endif /* RRR_STRING_BUILDER_H */
