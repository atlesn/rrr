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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#include "../log.h"
#include "nullsafe_str.h"
#include "../util/macro_utils.h"
#include "../util/gnu.h"

struct rrr_nullsafe_str {
	void *str;
	rrr_nullsafe_len len;
};

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

void rrr_nullsafe_str_destroy_if_not_null_void (
		void *str_dbl_ptr
) {
	struct rrr_nullsafe_str **str = str_dbl_ptr;
	rrr_nullsafe_str_destroy_if_not_null(str);
}

void rrr_nullsafe_str_move (
		struct rrr_nullsafe_str **target,
		struct rrr_nullsafe_str **source
) {
	rrr_nullsafe_str_destroy_if_not_null(target);
	*target = *source;
	*source = NULL;
}

int rrr_nullsafe_str_new_or_replace_raw (
		struct rrr_nullsafe_str **result,
		const void *str,
		rrr_nullsafe_len len
) {
	int ret = 0;

	*result = NULL;

	if (len != 0 && str == NULL) {
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

int rrr_nullsafe_str_new_or_replace_raw_allocated (
		struct rrr_nullsafe_str **result,
		void **str,
		rrr_nullsafe_len len
) {
	if (rrr_nullsafe_str_new_or_replace_raw(result, NULL, 0) != 0) {
		return 1;
	}

	(*result)->str = *str;
	(*result)->len = len;
	*str = NULL;

	return 0;
}

int rrr_nullsafe_str_new_or_replace (
		struct rrr_nullsafe_str **result,
		const struct rrr_nullsafe_str *source
) {
	return rrr_nullsafe_str_new_or_replace_raw(result, source->str, source->len);
}

int rrr_nullsafe_str_new_or_replace_empty (
		struct rrr_nullsafe_str **result
) {
	return rrr_nullsafe_str_new_or_replace_raw(result, NULL, 0);
}

#define VERIFY_NEW_LENGTH(verb)																	\
	do {if (nullsafe->len + len < nullsafe->len) {												\
		RRR_MSG_0("Overflow while " verb " to nullsafe string, total data length too long\n");	\
		return 1;																				\
	}} while (0)

int rrr_nullsafe_str_append_raw (
		struct rrr_nullsafe_str *nullsafe,
		const void *str,
		rrr_nullsafe_len len
) {
	VERIFY_NEW_LENGTH("appending");

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

int rrr_nullsafe_str_append_asprintf (
		struct rrr_nullsafe_str *nullsafe,
		const void *format,
		...
) {
	int ret = 0;

	char *new_str = NULL;

	va_list args;
	va_start (args, format);

	if ((ret = rrr_vasprintf(&new_str, format, args)) < 0) {
		RRR_MSG_0("Could not allocate memory in rrr_nullsafe_str_append_asprintf\n");
		goto out;
	}
	ret = rrr_nullsafe_str_append_raw(nullsafe, new_str, ret);

	out:
	RRR_FREE_IF_NOT_NULL(new_str);
	va_end (args);
	return ret;
}

int rrr_nullsafe_str_append (
		struct rrr_nullsafe_str *target,
		const struct rrr_nullsafe_str *str
) {
	return rrr_nullsafe_str_append_raw(target, str->str, str->len);
}

int rrr_nullsafe_str_append_with_converter (
		struct rrr_nullsafe_str *target,
		const struct rrr_nullsafe_str *str,
		int (*converter_callback)(struct rrr_nullsafe_str **result, const struct rrr_nullsafe_str *str)
) {
	int ret = 0;

	struct rrr_nullsafe_str *result = NULL;

	if ((ret = converter_callback(&result, str)) != 0) {
		goto out;
	}

	ret = rrr_nullsafe_str_append(target, result);

	out:
	rrr_nullsafe_str_destroy_if_not_null(&result);
	return ret;
}

int rrr_nullsafe_str_append_with_creator (
		struct rrr_nullsafe_str *target,
		int (*creator)(struct rrr_nullsafe_str **result, void *arg),
		void *creator_arg
) {
	int ret = 0;

	struct rrr_nullsafe_str *result = NULL;

	if ((ret = creator(&result, creator_arg)) != 0) {
		goto out;
	}

	ret = rrr_nullsafe_str_append(target, result);

	out:
	rrr_nullsafe_str_destroy_if_not_null(&result);
	return ret;
}

int rrr_nullsafe_str_prepend_raw (
		struct rrr_nullsafe_str *nullsafe,
		const void *str,
		rrr_nullsafe_len len
) {
	VERIFY_NEW_LENGTH("prepending");

	void *new_str = malloc(nullsafe->len + len);
	if (new_str == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_nullsafe_str_prepend\n");
		return 1;
	}

	memcpy(new_str, str, len);

	if (nullsafe->str != NULL) {
		memcpy(new_str + len, nullsafe->str, nullsafe->len);
		free(nullsafe->str);
	}

	nullsafe->str = new_str;
	nullsafe->len += len;

	return 0;
}

int rrr_nullsafe_str_prepend_asprintf (
		struct rrr_nullsafe_str *nullsafe,
		const void *format,
		...
) {
	int ret = 0;

	char *new_str = NULL;

	va_list args;
	va_start (args, format);

	if ((ret = rrr_vasprintf(&new_str, format, args)) < 0) {
		RRR_MSG_0("Could not allocate memory in rrr_nullsafe_str_prepend_asprintf\n");
		goto out;
	}

	ret = rrr_nullsafe_str_prepend_raw(nullsafe, new_str, ret);

	out:
	RRR_FREE_IF_NOT_NULL(new_str);
	va_end (args);
	return ret;
}

void rrr_nullsafe_str_set_allocated (
		struct rrr_nullsafe_str *nullsafe,
		void **ptr,
		rrr_nullsafe_len len
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
		rrr_nullsafe_len len
) {
	if (nullsafe == NULL) {
		RRR_BUG("BUG: Target was NULL in rrr_nullsafe_str_set\n");
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

int rrr_nullsafe_str_chr (
		const struct rrr_nullsafe_str *nullsafe,
		char c,
		int (*callback)(const void *start, size_t len_remaining, void *arg),
		void *callback_arg
) {
	if (nullsafe == NULL) {
		return 0;
	}

	for (rrr_nullsafe_len i = 0; i < nullsafe->len; i++) {
		const char *pos = nullsafe->str + i;
		if (*pos == c) {
			return callback(pos, nullsafe->len - i, callback_arg);
		}
	}

	return 0;
}

int rrr_nullsafe_str_split_raw (
		const struct rrr_nullsafe_str *nullsafe,
		char c,
		int (*callback)(const void *start, size_t chunk_size, int is_last, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if (nullsafe == NULL) {
		return 0;
	}

	rrr_nullsafe_len start_pos = 0;
	for (rrr_nullsafe_len i = 0; i < nullsafe->len; i++) {
		if (*((const char *)(nullsafe->str + i)) == c) {
			if ((ret = callback(nullsafe->str + start_pos, i - start_pos, 0, callback_arg)) != 0) {
				goto out;
			}
			start_pos = i + 1;
		}
		if (nullsafe->len - 1 == i) {
			if ((ret = callback(nullsafe->str + start_pos, i - start_pos + 1, 1, callback_arg)) != 0) {
				goto out;
			}
		}
	}

	out:
	return ret;
}

struct rrr_nullsafe_str_split_callback_data {
	int (*callback)(const struct rrr_nullsafe_str *str, int is_last, void *arg);
	void *callback_arg;
};

static int __rrr_nullsafe_str_split_callback (
	const void *data,
	size_t len,
	int is_last,
	void *arg
) {
	struct rrr_nullsafe_str_split_callback_data *callback_data = arg;

	struct rrr_nullsafe_str tmp = {
		(void *) data, // Cast away const OK
		len
	};

	return callback_data->callback(&tmp, is_last, callback_data->callback_arg);
}

int rrr_nullsafe_str_split (
		const struct rrr_nullsafe_str *nullsafe,
		char c,
		int (*callback)(const struct rrr_nullsafe_str *str, int is_last, void *arg),
		void *callback_arg
) {
	struct rrr_nullsafe_str_split_callback_data callback_data = {
		callback,
		callback_arg
	};

	return rrr_nullsafe_str_split_raw (
		nullsafe,
		c,
		__rrr_nullsafe_str_split_callback,
		&callback_data
	);
}

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
) {
	int ret = 0;

	if (needle->len > haystack->len) {
		goto out;
	}

	const void *start = haystack->str;
	const void *end = haystack->str + haystack->len;
	
	while (start + needle->len <= end) {
		if (memcmp(start, needle->str, needle->len) == 0) {
			const struct rrr_nullsafe_str tmp_at_needle = {
					(void *) start, // Cast away const OK
					end - start
			};
			const struct rrr_nullsafe_str tmp_after_needle = {
					(void *) start + needle->len, // Cast away const OK
					end - start - needle->len
			};
			if ((ret = callback(haystack, needle, &tmp_at_needle, &tmp_after_needle, callback_arg)) != 0) {
				goto out;
			}
		}
		start++;
	}

	out:
	return ret;
}

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
) {
	const struct rrr_nullsafe_str haystack_tmp = {
			(void *) haystack_str, // Cast away const OK
			haystack_len
	};
	return rrr_nullsafe_str_str (&haystack_tmp, needle, callback, callback_arg);
}

int rrr_nullsafe_str_begins_with (
		const struct rrr_nullsafe_str *str,
		const struct rrr_nullsafe_str *substr
) {
	if (str->len < substr->len) {
		return 0;
	}
	return (memcmp (str->str, substr->str, substr->len) == 0);
}

int rrr_nullsafe_str_dup (
		struct rrr_nullsafe_str **target,
		const struct rrr_nullsafe_str *source
) {
	if (source == NULL) {
		return 1;
	}
	if ((rrr_nullsafe_str_new_or_replace_raw(target, source->str, source->len)) != 0) {
		return 1;
	}
	return 0;
}

rrr_nullsafe_len rrr_nullsafe_str_len (
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
	for (rrr_nullsafe_len i = 0; i < nullsafe->len; i++) {
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

	const rrr_nullsafe_len str_len = strlen(str);
	if (nullsafe->len == 0 && str_len == 0) {
		return 0;
	}
	else if (nullsafe->len != str_len) {
		return 1;
	}
	for (rrr_nullsafe_len i = 0; i < str_len; i++) {
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
	rrr_nullsafe_len str_len = strlen(str);
	if (nullsafe->len == 0 && str_len == 0) {
		return 0;
	}
	else if (nullsafe->len != str_len) {
		return 1;
	}
	for (rrr_nullsafe_len i = 0; i < str_len; i++) {
		char a = *((const char *) nullsafe->str + i);
		char b = *(str + i);
		if (a != b) {
			return 1;
		}
	}
	return 0;
}

void rrr_nullsafe_str_util_output_strip_null_append_null_trim_raw_null_ok (
		char *buf,
		rrr_nullsafe_len buf_size,
		const char *str,
		rrr_nullsafe_len len
) {
	if (len == 0) {
		*buf = '\0';
		return;
	}

	rrr_nullsafe_len get_size = len;
	if (get_size > buf_size - 1) {
		get_size = buf_size - 1;
	}
	buf[get_size] = '\0';
	if (str) {
		memcpy(buf, str, get_size);
	}
	for (rrr_nullsafe_len i = 0; i < get_size; i++) {
		buf[i] = (buf[i] == '\0' ? 'N' : buf[i]);
	}
}

void rrr_nullsafe_str_output_strip_null_append_null_trim (
		const struct rrr_nullsafe_str *nullsafe,
		char *buf,
		rrr_nullsafe_len buf_size
) {
	if (nullsafe == NULL) {
		*buf = '\0';
		return;
	}

	rrr_nullsafe_str_util_output_strip_null_append_null_trim_raw_null_ok (buf, buf_size, nullsafe->str, nullsafe->len);
}

void rrr_nullsafe_str_copyto (
		rrr_nullsafe_len *written_size,
		void *target,
		rrr_nullsafe_len target_size,
		const struct rrr_nullsafe_str *nullsafe
) {
	*written_size = 0;
	if (target_size == 0 || nullsafe == NULL || nullsafe->len == 0) {
		return;
	}

	rrr_nullsafe_len to_write = nullsafe->len;
	if (to_write > target_size) {
		to_write = target_size;
	}
	memcpy(target, nullsafe->str, to_write);
	*written_size = to_write;
}

int rrr_nullsafe_str_with_str_do (
		const struct rrr_nullsafe_str *str,
		int (*callback)(const struct rrr_nullsafe_str *str, void *arg),
		void *callback_arg
) {
	return callback(str, callback_arg);
}

int rrr_nullsafe_str_with_tmp_str_do (
		const void *str,
		rrr_nullsafe_len len,
		int (*callback)(const struct rrr_nullsafe_str *str, void *arg),
		void *callback_arg
) {
	const struct rrr_nullsafe_str tmp = {
			(void *) str, // Cast away const OK
			len
	};
	return callback(&tmp, callback_arg);
}

int rrr_nullsafe_str_with_raw_do (
		struct rrr_nullsafe_str *nullsafe,
		int (*callback)(rrr_nullsafe_len *len, void *str, void *arg),
		void *callback_arg
) {
	char str_dummy[] = "";
	void *str_to_use = str_dummy;
	rrr_nullsafe_len len = 0;

	if (nullsafe->len > 0) {
		str_to_use = nullsafe->str;
		len = nullsafe->len;
	}

	int ret = callback(&len, str_to_use, callback_arg);
	if (ret != 0) {
		return ret;
	}

	if (len > nullsafe->len) {
		RRR_BUG("BUG: Callback returned len > allocated len %" PRIrrr_nullsafe_len ">%" PRIrrr_nullsafe_len "\n", len, nullsafe->len);
	}

	return ret;
}

int rrr_nullsafe_str_with_raw_null_terminated_do (
		const struct rrr_nullsafe_str *nullsafe,
		int (*callback)(const char *str, void *arg),
		void *callback_arg
) {
	int ret = 0;

	char *tmp = NULL;

	if (nullsafe->len == 0) {
		ret = callback("", callback_arg);
		goto out;
	}

	if ((tmp = malloc(nullsafe->len + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_nullsafe_str_with_null_terminated_do\n");
		ret = 1;
		goto out;
	}

	memcpy(tmp, nullsafe->str, nullsafe->len);

	tmp[nullsafe->len] = '\0';

	ret = callback(tmp, callback_arg);

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	return ret;
}

#define RRR_NULLSAFE_STR_WITH_STR_DO_STR_AND_LEN_TO_USE_SET(letter)						\
	const void *RRR_PASTE_3(str_to_use, _, letter) = str_static;						\
	rrr_nullsafe_len RRR_PASTE_3(len_to_use, _, letter) = 0;									\
	do {if (RRR_PASTE_3(nullsafe, _, letter)->len > 0) {								\
		RRR_PASTE_3(str_to_use, _, letter) = RRR_PASTE_3(nullsafe, _, letter)->str;		\
		RRR_PASTE_3(len_to_use, _, letter) = RRR_PASTE_3(nullsafe, _, letter)->len;		\
	}} while (0)

int rrr_nullsafe_str_with_raw_do_const (
		const struct rrr_nullsafe_str *nullsafe_a,
		int (*callback)(const void *str, rrr_nullsafe_len len, void *arg),
		void *callback_arg
) {
	static const char *str_static = "";

	RRR_NULLSAFE_STR_WITH_STR_DO_STR_AND_LEN_TO_USE_SET(a);

	return callback(str_to_use_a, len_to_use_a, callback_arg);
}

int rrr_nullsafe_str_with_raw_do_double_const (
		const struct rrr_nullsafe_str *nullsafe_a,
		const struct rrr_nullsafe_str *nullsafe_b,
		int (*callback)(const void *str_a, rrr_nullsafe_len len_a, const void *str_b, rrr_nullsafe_len len_b, void *arg),
		void *callback_arg
) {
	static const char *str_static = "";

	RRR_NULLSAFE_STR_WITH_STR_DO_STR_AND_LEN_TO_USE_SET(a);
	RRR_NULLSAFE_STR_WITH_STR_DO_STR_AND_LEN_TO_USE_SET(b);

	return callback(str_to_use_a, len_to_use_a, str_to_use_b, len_to_use_b, callback_arg);
}

char *rrr_nullsafe_str_with_raw_do_const_return_str (
		const struct rrr_nullsafe_str *nullsafe,
		char *(*callback)(const void *str, rrr_nullsafe_len len, void *arg),
		void *callback_arg
) {
	static const char *str_static = "";
	const void *str_to_use = str_static;
	rrr_nullsafe_len len_to_use = 0;

	if (nullsafe->len > 0) {
		str_to_use = nullsafe->str;
		len_to_use = nullsafe->len;
	}

	return callback(str_to_use, len_to_use, callback_arg);
}

int rrr_nullsafe_str_with_raw_truncated_do (
		const struct rrr_nullsafe_str *nullsafe,
		rrr_nullsafe_len pos,
		rrr_nullsafe_len len,
		int (*callback)(const void *str, rrr_nullsafe_len len, void *arg),
		void *callback_arg
) {
	if (pos + len > nullsafe->len) {
		RRR_BUG("BUG: pos+len exceeds available length in rrr_nullsafe_str_with_raw_truncated_do\n");
	}

	return callback(nullsafe->str + pos, len, callback_arg);
}

int rrr_nullsafe_str_foreach_byte_do (
		const struct rrr_nullsafe_str *nullsafe,
		int (*callback)(char byte, void *arg),
		void *callback_arg
) {
	int ret = 0;

	for (rrr_nullsafe_len i = 0; i < nullsafe->len; i++) {
		if ((ret = callback(*((char *) (nullsafe->str + i)), callback_arg)) != 0) {
			break;
		}
	}

	return ret;
}
