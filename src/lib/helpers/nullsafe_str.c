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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../log.h"
#include "nullsafe_str.h"
#include "../util/macro_utils.h"

void rrr_nullsafe_str_destroy_if_not_null (
		struct rrr_nullsafe_str **str
) {
	if (str == NULL) {
		RRR_BUG("BUG: Double pointer to rrr_nullsafe_str_destroy_if_not_null was NULL\n");
	}
	if (*str == NULL) {
		return;
	}
	RRR_FREE_IF_NOT_NULL((*str)->str);
	free(*str);
	*str = NULL;
}

int rrr_nullsafe_str_new_or_replace (
	struct rrr_nullsafe_str **result,
	const void *str,
	rrr_length len
) {
	int ret = 0;

	*result = NULL;

	if (len == 0 && str != NULL) {
		RRR_BUG("BUG: len was 0 but str was not NULL in rrr_nullsafe_str_new\n");
	}
	else if (len != 0 && str == NULL) {
		RRR_BUG("BUG: len was not 0 but str was NULL in rrr_nullsafe_str_new\n");
	}

	struct rrr_nullsafe_str *new_str = *result;
	if (new_str == NULL) {
		if ((new_str = malloc(sizeof(*new_str))) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http_nullsafe_str_new\n");
			ret = 1;
			goto out;
		}
	}
	else {
		RRR_FREE_IF_NOT_NULL(new_str->str);
	}

	memset(new_str, '\0', sizeof(*new_str));

	if (len != 0) {
		if ((new_str->str = malloc(len)) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http_nullsafe_str_new\n");
			ret = 1;
			goto out_free;
		}
		memcpy(new_str->str, str, len);
	}

	new_str->len = len;
	*result = new_str;

	goto out;
	out_free:
		free(new_str);
	out:
		return ret;
}

int rrr_nullsafe_str_append (
		struct rrr_nullsafe_str *nullsafe,
		const void *str,
		rrr_length len
) {
	void *new_str = realloc(nullsafe->str, nullsafe->len + len);
	if (new_str == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_nullsafe_str_append\n");
		return 1;
	}
	nullsafe->str = new_str;

	memcpy(nullsafe->str + nullsafe->len, str, len);
	nullsafe->len += len;

	return 0;
}

void rrr_nullsafe_str_set_allocated (
	struct rrr_nullsafe_str *nullsafe,
	void **ptr,
	rrr_length len
) {
	if (nullsafe == NULL) {
		RRR_BUG("BUG: Target was NULL in rrr_nullsafe_str_set_allocated");
	}
	RRR_FREE_IF_NOT_NULL(nullsafe->str);
	nullsafe->str = *ptr;
	nullsafe->len = len;
	*ptr = NULL;
}

int rrr_nullsafe_str_set (
	struct rrr_nullsafe_str *nullsafe,
	const void *src,
	rrr_length len
) {
	if (nullsafe == NULL) {
		RRR_BUG("BUG: Target was NULL in rrr_nullsafe_str_set_allocated");
	}

	RRR_FREE_IF_NOT_NULL(nullsafe->str);
	nullsafe->len = len;

	if (len > 0) {
		if ((nullsafe->str = malloc(len)) == NULL) {
			return 1;
		}
		memcpy(nullsafe->str, src, len);
	}

	return 0;
}

const char *rrr_nullsafe_str_chr (
	const struct rrr_nullsafe_str *nullsafe,
	char c
) {
	if (nullsafe == NULL) {
		return NULL;
	}
	for (rrr_length i = 0; i < nullsafe->len; i++) {
		const char *pos = nullsafe->str + i;
		if (*pos == c) {
			return pos;
		}
	}

	return NULL;
}

int rrr_nullsafe_str_dup (
	struct rrr_nullsafe_str **target,
	const struct rrr_nullsafe_str *source
) {
	if (source == NULL) {
		return 1;
	}
	if ((rrr_nullsafe_str_new_or_replace(target, source->str, source->len)) != 0) {
		return 1;
	}
	return 0;
}

rrr_length rrr_nullsafe_str_len (
	const struct rrr_nullsafe_str *nullsafe
) {
	return (nullsafe == NULL ? 0 : nullsafe->len);
}

void rrr_nullsafe_str_tolower (
	struct rrr_nullsafe_str *nullsafe
) {
	if (nullsafe == NULL) {
		return;
	}
	for (rrr_length i = 0; i < nullsafe->len; i++) {
		char *pos = nullsafe->str + i;
		*pos = tolower(*pos);
	}
}

int rrr_nullsafe_str_isset (
	const struct rrr_nullsafe_str *nullsafe
) {
	return (nullsafe != NULL && nullsafe->len != 0);
}

int rrr_nullsafe_str_cmpto_case (
	const struct rrr_nullsafe_str *nullsafe,
	const char *str
) {
	if (nullsafe == NULL) {
		return 1;
	}

	const rrr_length str_len = strlen(str);
	if (nullsafe->len == 0 && str_len == 0) {
		return 0;
	}
	else if (nullsafe->len != str_len) {
		return 1;
	}
	for (rrr_length i = 0; i < str_len; i++) {
		char a = tolower(*((const char *) nullsafe->str + i));
		char b = tolower(*(str + i));
		if (a != b) {
			return 1;
		}
	}
	return 0;
}

int rrr_nullsafe_str_cmpto (
		const struct rrr_nullsafe_str *nullsafe,
		const char *str
) {
	if (nullsafe == NULL) {
		return 1;
	}
	rrr_length str_len = strlen(str);
	if (nullsafe->len == 0 && str_len == 0) {
		return 0;
	}
	else if (nullsafe->len != str_len) {
		return 1;
	}
	for (rrr_length i = 0; i < str_len; i++) {
		char a = *((const char *) nullsafe->str + i);
		char b = *(str + i);
		if (a != b) {
			return 1;
		}
	}
	return 0;
}

void rrr_nullsafe_str_output_strip_null_append_null_trim (
	const struct rrr_nullsafe_str *nullsafe,
	char *buf,
	rrr_length buf_size
) {
	if (nullsafe == NULL || nullsafe->len == 0) {
		*buf = '\0';
		return;
	}

	rrr_length get_size = nullsafe->len;
	if (get_size > buf_size - 1) {
		get_size = buf_size - 1;
	}
	buf[get_size] = '\0';
	if (nullsafe->str) {
		memcpy(buf, nullsafe->str, get_size);
	}
	for (rrr_length i = 0; i < get_size; i++) {
		buf[i] = (buf[i] == '\0' ? 'N' : buf[i]);
	}
}

void rrr_nullsafe_str_copyto (
	rrr_length *written_size,
	void *target,
	rrr_length target_size,
	const struct rrr_nullsafe_str *nullsafe
) {
	*written_size = 0;
	if (target_size == 0 || nullsafe == NULL || nullsafe->len == 0) {
		return;
	}

	rrr_length to_write = nullsafe->len;
	if (to_write > target_size) {
		to_write = target_size;
	}
	memcpy(target, nullsafe->str, to_write);
	*written_size = to_write;
}
