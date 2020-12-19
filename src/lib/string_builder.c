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
#include "type.h"
#include "util/gnu.h"
#include "util/macro_utils.h"

void rrr_string_builder_unchecked_append (struct rrr_string_builder *string_builder, const char *str) {
	rrr_biglength length = strlen(str);
	memcpy(string_builder->buf + string_builder->wpos, str, length + 1);
	string_builder->wpos += length;
	if (string_builder->wpos + 1 > string_builder->size) {
		RRR_BUG("wpos exceeded maximum in rrr_string_builder_unchecked_append\n");
	}
}

static void __rrr_string_builder_unchecked_append_raw (struct rrr_string_builder *string_builder, const char *buf, rrr_biglength buf_size) {
	memcpy(string_builder->buf + string_builder->wpos, buf, buf_size);
	string_builder->wpos += buf_size;
	string_builder->buf[string_builder->wpos] = '\0';
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

const char *rrr_string_builder_buf (const struct rrr_string_builder *string_builder) {
	return string_builder->buf;
}

rrr_biglength rrr_string_builder_length (const struct rrr_string_builder *string_builder) {
	return (string_builder->buf == NULL ? 0 : string_builder->wpos);
}

rrr_biglength rrr_string_builder_size (const struct rrr_string_builder *string_builder) {
	return (string_builder->size);
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

void rrr_string_builder_destroy_void (void *ptr) {
	rrr_string_builder_clear (ptr);
	free(ptr);
}

int rrr_string_builder_reserve (struct rrr_string_builder *string_builder, rrr_biglength bytes) {
	if (bytes == 0) {
		return 0;
	}

	if (string_builder->wpos + bytes + 1 > string_builder->size) {
		rrr_biglength new_size = bytes + 1 + string_builder->size + 1024;
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


int rrr_string_builder_append_from (struct rrr_string_builder *target, const struct rrr_string_builder *source) {
	int ret = 0;

	if (source->wpos == 0) {
		goto out;
	}

	if ((ret = rrr_string_builder_reserve(target, source->wpos)) != 0) {
		goto out;
	}

	__rrr_string_builder_unchecked_append_raw (target, source->buf, source->wpos + 1);

	out:
	return ret;
}

int rrr_string_builder_append_raw (struct rrr_string_builder *target, const char *str, rrr_biglength length) {
	if (rrr_string_builder_reserve(target, length) != 0) {
		return 1;
	}

	__rrr_string_builder_unchecked_append_raw(target, str, length);

	return 0;
}

int rrr_string_builder_append (struct rrr_string_builder *string_builder, const char *str) {
	if (*str == '\0') {
		return 0;
	}

	rrr_biglength length = strlen(str);

	if (rrr_string_builder_reserve(string_builder, length) != 0) {
		return 1;
	}

	memcpy(string_builder->buf + string_builder->wpos, str, length + 1);
	string_builder->wpos += length;

	return 0;
}

int rrr_string_builder_append_format (struct rrr_string_builder *string_builder, const char *format, ...) {
	int ret = 0;

	va_list args;
	va_start (args, format);

	char *tmp = NULL;

	if (rrr_vasprintf(&tmp, format, args) <= 0) {
		ret = 1;
		goto out;
	}

	rrr_biglength length = strlen(tmp);
	if (rrr_string_builder_reserve(string_builder, length) != 0) {
		ret = 1;
		goto out;
	}

	memcpy(string_builder->buf + string_builder->wpos, tmp, length + 1);
	string_builder->wpos += length;

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	va_end(args);
	return ret;
}

