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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "log.h"
#include "string_builder.h"
#include "macro_utils.h"

void rrr_string_builder_unchecked_append (struct rrr_string_builder *string_builder, const char *str) {
	ssize_t length = strlen(str);
	memcpy(string_builder->buf + string_builder->wpos, str, length + 1);
	string_builder->wpos += length;
	if (string_builder->wpos + 1 > string_builder->size) {
		RRR_BUG("wpos exceeded maximum in rrr_string_builder_unchecked_append\n");
	}
}

void rrr_string_builder_unchecked_append_raw (struct rrr_string_builder *string_builder, const char *buf, size_t buf_size) {
	memcpy(string_builder->buf + string_builder->wpos, buf, buf_size);
}

char *rrr_string_builder_buffer_takeover (struct rrr_string_builder *string_builder) {
	char *ret = string_builder->buf;
	memset(string_builder, '\0', sizeof(*string_builder));
	return ret;
}

void rrr_string_builder_clear (struct rrr_string_builder *string_builder) {
	RRR_FREE_IF_NOT_NULL(string_builder->buf);
	string_builder->size = 0;
	string_builder->wpos = 0;
}

int rrr_string_builder_new (struct rrr_string_builder **result) {
	*result = NULL;

	struct rrr_string_builder *string_builder = malloc(sizeof(*string_builder));

	if (string_builder == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_string_builder_new\n");
		return 1;
	}

	memset(string_builder, '\0', sizeof(*string_builder));

	*result = string_builder;

	return 0;
}

void rrr_string_builder_destroy (struct rrr_string_builder *string_builder) {
	rrr_string_builder_clear (string_builder);
	free(string_builder);
}

int rrr_string_builder_reserve (struct rrr_string_builder *string_builder, ssize_t bytes) {
	if (string_builder->wpos + bytes + 1 > string_builder->size) {
		ssize_t new_size = bytes + 1 + string_builder->size + 1024;
		char *new_buf = realloc(string_builder->buf, new_size);
		if (new_buf == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_string_builder_reserve\n");
			return 1;
		}
		string_builder->size = new_size;
		string_builder->buf = new_buf;
	}

	return 0;
}

int rrr_string_builder_append (struct rrr_string_builder *string_builder, const char *str) {
	ssize_t length = strlen(str);

	if (rrr_string_builder_reserve(string_builder, length) != 0) {
		return 1;
	}

	memcpy(string_builder->buf + string_builder->wpos, str, length + 1);
	string_builder->wpos += length;

	return 0;
}
