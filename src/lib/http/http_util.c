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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>

#include "../log.h"
#include "../allocator.h"

#include "http_util.h"
#include "http_common.h"

#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../helpers/nullsafe_str.h"
#include "../helpers/string_builder.h"

#if defined(RRR_WITH_NGHTTP2)
#include "http_application_http2.h"
#endif

#if defined(RRR_WITH_HTTP3)
#include "http_application_http3.h"
#endif

#ifdef RRR_WITH_ZLIB
#include "../zlib/rrr_zlib.h"
#endif

#ifdef RRR_WITH_JSONC
#include "../json/json.h"
#endif

#define RRR_HTTP_UTIL_JSON_TO_ARRAYS_MAX_LEVELS 5

static int __rrr_http_util_is_alphanumeric (unsigned char c) {
	if (	(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9')
	) {
		return 1;
	}
	return 0;
}

static int __rrr_http_util_is_lwsp (unsigned char c) {
	return (c == ' ' || c == '\t');
}

static int __rrr_http_util_is_uri_unreserved_rfc2396 (unsigned char c) {
	// RFC2396 §2.3.
	switch (c) {
		case '-':
			return 1;
		case '_':
			return 1;
		case '.':
			return 1;
		case '!':
			return 1;
		case '~':
			return 1;
		case '*':
			return 1;
		case '\'':
			return 1;
		case '(':
			return 1;
		case ')':
			return 1;
		default:
			return 0;
	};
	return 0;
}

static int __rrr_http_util_is_uri_reserved(unsigned char c) {
	switch (c) {
		case ';':
			return 1;
		case '/':
			return 1;
		case '?':
			return 1;
		case ':':
			return 1;
		case '@':
			return 1;
		case '&':
			return 1;
		case '=':
			return 1;
		case '+':
			return 1;
		case '$':
			return 1;
		case ',':
			return 1;
		default:
			return 0;
	};
	return 0;
}

static int __rrr_http_util_is_header_special_rfc822 (unsigned char c) {
	// RFC822 §3.3.
	switch (c) {
		case '(':
			return 1;
		case ')':
			return 1;
		case '<':
			return 1;
		case '>':
			return 1;
		case '@':
			return 1;
		case ',':
			return 1;
		case ';':
			return 1;
		case ':':
			return 1;
		case '\\':
			return 1;
		case '"':
			return 1;
		case '.':
			return 1;
		case '[':
			return 1;
		case ']':
			return 1;
		default:
			return 0;
	};
	return 0;
}

static int __rrr_http_util_is_header_nonspecial_rfc7230 (unsigned char c) {
	// RFC7230 §3.2.6.
	switch (c) {
		case '!':
			return 1;
		case '#':
			return 1;
		case '$':
			return 1;
		case '%':
			return 1;
		case '&':
			return 1;
		case '\'':
			return 1;
		case '*':
			return 1;
		case '+':
			return 1;
		case '-':
			return 1;
		case '.':
			return 1;
		case '^':
			return 1;
		case '_':
			return 1;
		case '`':
			return 1;
		case '|':
			return 1;
		case '~':
			return 1;
		default:
			return 0;
	};
	return 0;
}

static int __rrr_http_util_is_ascii_non_ctl (unsigned char c) {
	return (c > 31 && c < 127);
}

void rrr_http_util_print_where_message (
		const char *start,
		const char *end
) {
	const rrr_length max = 20;

	if (end < start) {
		RRR_BUG("BUG: end was smaller than start in rrr_http_util_print_where_message\n");
	}

	char buf[max+1];

	rrr_length bytes_to_copy = max;
	if (start + bytes_to_copy >= end) {
		bytes_to_copy = rrr_length_from_ptr_sub_bug_const(end, start);
	}

	if (bytes_to_copy > max) {
		RRR_BUG("BUG: Overflow in rrr_http_util_print_where_message, bytes to copy was %u\n", bytes_to_copy);
	}

	strncpy(buf, start, bytes_to_copy);
	buf[bytes_to_copy] = '\0';

	// Stop message at newline

	for (rrr_length i = 0; i < bytes_to_copy; i++) {
		if (buf[i] == '\0') {
			break;
		}
		else if (buf[i] == '\r' || buf[i] == '\n') {
			buf[i] = '\0';
			break;
		}
	}

	RRR_MSG_0("Where: %s\n", buf);
	RRR_MSG_0("       /\\ <-- HERE\n");
}

static int __rrr_http_util_decode_urlencoded_string_callback (
		rrr_nullsafe_len *len,
		void *str,
		void *arg
) {
	(void)(arg);

	int ret = 0;

	const unsigned char *start = str;
	const unsigned char *end = str + *len;

	unsigned char *target = str;

	rrr_nullsafe_len wpos = 0;

	while (start < end) {
		unsigned char c = *start;

		if (c == '%') {
			if (start + 3 > end) {
				RRR_MSG_0("Not enough characters after %% in urlencoded string\n");
				ret = 1;
				goto out;
			}

			unsigned long long int result = 0;

			rrr_length result_len = 0;
			if (rrr_http_util_strtoull_raw (&result, &result_len, (const char *) start + 1, (const char *) start + 3, 16) != 0) {
				RRR_MSG_0("Invalid %%-sequence in urlencoded string\n");
				rrr_http_util_print_where_message((const char *) start, (const char *) end);
				ret = 1;
				goto out;
			}

			if (result > 0xff) {
				RRR_BUG("Result after converting %%-sequence too big in __rrr_http_util_decode_urlencoded_string_callback\n");
			}

			c = (unsigned char) result;
			start += 2; // One more ++ at the end of the loop
		}

		target[wpos++] = c;

		start++;
	}

	*len = wpos;

	out:
	return ret;
}

int rrr_http_util_urlencoded_string_decode (
		struct rrr_nullsafe_str *str
) {
	return rrr_nullsafe_str_with_raw_do(str, __rrr_http_util_decode_urlencoded_string_callback, NULL);
}

struct rrr_http_util_uri_encode_foreach_byte_callback_data {
	char *wpos;
};

static int __rrr_http_util_uri_encode_foreach_byte_callback (char byte, void *arg) {
	struct rrr_http_util_uri_encode_foreach_byte_callback_data *callback_data = arg;

	if (__rrr_http_util_is_alphanumeric((unsigned char) byte) || __rrr_http_util_is_uri_unreserved_rfc2396((unsigned char) byte)) {
		*(callback_data->wpos) = byte;
		callback_data->wpos++;
	}
	else {
		sprintf(callback_data->wpos, "%s%02X", "%", (unsigned char) byte);
		callback_data->wpos += 3;
	}

	return 0;
}

// We allow non-ASCII here
int rrr_http_util_uri_encode (
		struct rrr_nullsafe_str **target,
		const struct rrr_nullsafe_str *str
) {
	int ret = 0;

	char *result = NULL;

	rrr_biglength result_max_length = (str != NULL ? rrr_nullsafe_str_len(str) * 3 : 0);
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(result_max_length,"rrr_http_util_encode_uri");

	const rrr_biglength allocate_size = result_max_length + 1; // Allocate extra byte for 0 from sprintf
	RRR_SIZE_CHECK(allocate_size,"While encoding HTTP URI", ret = 1; goto out);
	if ((result = rrr_allocate(allocate_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_util_encode_uri\n");
		ret = 1;
		goto out;
	}

	rrr_memset(result, '\0', allocate_size);

	if (*target == NULL) {
		if ((ret = rrr_nullsafe_str_new_or_replace_empty(target)) != 0) {
			goto out;
		}
	}

	if (result_max_length > 0) {
		struct rrr_http_util_uri_encode_foreach_byte_callback_data callback_data = {
			result
		};

		if ((ret = rrr_nullsafe_str_foreach_byte_do(str, __rrr_http_util_uri_encode_foreach_byte_callback, &callback_data)) != 0) {
			goto out;
		}

		rrr_nullsafe_str_set_allocated (
				*target,
				(void **) &result,
				rrr_length_from_ptr_sub_bug_const(callback_data.wpos, result)
		);
	}

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

static int __rrr_http_util_unquote_string_callback (
		rrr_nullsafe_len *len,
		void *str,
		void *arg
) {
	(void)(arg);

	unsigned char *start = str;
	unsigned char *end = str + *len;

	unsigned char *target = str;

	rrr_nullsafe_len wpos = 0;

	while (start < end) {
		if (*start == '"' || *start == '(') {
			unsigned char endquote = (*start == '"' ? '"' : ')');

			// Skip past begin quote
			start++;

			if (start >= end) {
				break;
			}

			for (; start < end; start++) {
				if (*start == '\\') {
					if (start + 1 < end) {
						unsigned char next = *(start + 1);
						if (next == endquote) {
							// Write only the quote character
							start++;
						}
						else {
							// Write only the escape character
						}
					}
				}
				else if (*start == endquote) {
					break;
				}

				target[wpos++] = *start;
			}
		}
		else {
			target[wpos++] = *start;
		}

		start++;
	}

	*len = wpos;

	return 0;
}

int rrr_http_util_unquote_string (
		struct rrr_nullsafe_str *str
) {
	return rrr_nullsafe_str_with_raw_do(str, __rrr_http_util_unquote_string_callback, NULL);
}

// TODO : Support RFC8187. This function is less forgiving than the standard.
char *rrr_http_util_header_value_quote (
		const char *input,
		rrr_length length,
		char delimeter_start,
		char delimeter_end
) {
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(length, "rrr_http_util_quote_header_value A");

	if (length == 0) {
		return NULL;
	}

	int err = 0;

	char *result = NULL;

	rrr_biglength result_size = length * 2 + 2 + 1;
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(length, "rrr_http_util_quote_header_value B");

	const rrr_biglength allocate_size = result_size + 1;
	RRR_SIZE_CHECK(allocate_size,"While quoting HTTP header value", err = 1; goto out);
	if ((result = rrr_allocate(allocate_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_util_quote_header_value\n");
		err = 1;
		goto out;
	}
	rrr_memset (result, '\0', result_size);

	char *wpos = result;
	char *wpos_max = result + result_size;

	int needs_quote = 0;
	for (rrr_length i = 0; i < length; i++) {
		unsigned char c = *((unsigned char *) input + i);

		if (__rrr_http_util_is_alphanumeric(c) || __rrr_http_util_is_header_nonspecial_rfc7230(c)) {
			// OK
		}
		else if (__rrr_http_util_is_header_special_rfc822(c) || __rrr_http_util_is_lwsp(c) || c == '\r' || c == '\\') {
			needs_quote = 1;
			// Don't break, check all chars for validity
		}
		else if (__rrr_http_util_is_ascii_non_ctl(c)) {
			// OK
		}
		else {
			RRR_MSG_0("Invalid octet %02x in rrr_http_util_quote_header_value\n", c);
			err = 1;
			goto out;
		}
	}

	if (needs_quote == 0) {
		memcpy(result, input, length);
	}
	else {
		*wpos = delimeter_start;
		wpos++;

		for (rrr_length i = 0; i < length; i++) {
			char c = *(input + i);

			if (c == delimeter_start || c == delimeter_end || c == '\r' || c == '\\') {
				*wpos = '\\';
				wpos++;
			}

			*wpos = c;
			wpos++;
		}

		*wpos = delimeter_end;
		wpos++;

		if (wpos > wpos_max) {
			RRR_BUG("Result string was too long in rrr_http_util_quote_ascii\n");
		}
	}

	out:
	if (err != 0) {
		RRR_FREE_IF_NOT_NULL(result);
		result = NULL;
	}

	return result;
}

struct rrr_http_util_quote_header_value_nullsafe_callback_data {
	char delimeter_start;
	char delimeter_end;
};

static char *__rrr_http_util_quote_header_value_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_http_util_quote_header_value_nullsafe_callback_data *callback_data = arg;

	if (len > RRR_LENGTH_MAX) {
		RRR_MSG_0("HTTP header value too long while quoting (%" PRIrrr_nullsafe_len ">%llu)\n",
			len, (unsigned long long) RRR_LENGTH_MAX);
		return NULL;
	}

	return rrr_http_util_header_value_quote (
			str,
			(rrr_length) len,
			callback_data->delimeter_start,
			callback_data->delimeter_end
	);
}

char *rrr_http_util_header_value_quote_nullsafe (
		const struct rrr_nullsafe_str *str,
		char delimeter_start,
		char delimeter_end
) {
	if (!rrr_nullsafe_str_isset(str)) {
		return NULL;
	}

	struct rrr_http_util_quote_header_value_nullsafe_callback_data callback_data = {
		delimeter_start,
		delimeter_end
	};

	return rrr_nullsafe_str_with_raw_do_const_return_str (
			str,
			__rrr_http_util_quote_header_value_nullsafe_callback,
			&callback_data
	);
}

const char *rrr_http_util_find_crlf (
		const char *start,
		const char *end
) {
	// Remember end minus 1
	for (const char *pos = start; pos < end - 1; pos++) {
		if (*pos == '\r' && *(pos + 1) == '\n') {
			return pos;
		}
	}
	return NULL;
}

const char *rrr_http_util_find_whsp (
		const char *start,
		const char *end
) {
	// Remember end minus 1
	for (const char *pos = start; pos < end - 1; pos++) {
		if (*pos == ' ' || *pos == '\t') {
			return pos;
		}
	}
	return NULL;
}

int rrr_http_util_strtoull_raw (
		unsigned long long int *result,
		rrr_length *result_len,
		const char *start,
		const char *end,
		int base
) {
	char buf[64];
	const char *numbers_end = NULL;

	*result = 0;
	*result_len = 0;

	const char *pos = NULL;
	for (pos = start; pos < end; pos++) {
		if (base == 10) {
			if (*pos < '0' || *pos > '9') {
				numbers_end = pos;
				break;
			}
		}
		else if (base == 16) {
			if ((*pos >= '0' && *pos <= '9') || (*pos >= 'a' && *pos <= 'f') || (*pos >= 'A' && *pos <= 'F')) {
				// OK
			}
			else {
				numbers_end = pos;
				break;
			}
		}
		else {
			RRR_BUG("Unknown base %i in %s\n", base, __func__);
		}
	}

	if (pos == end) {
		numbers_end = end;
	}

	if (numbers_end == start) {
		return 1;
	}

	if (numbers_end - start > 63) {
		RRR_MSG_0("Number was too long in %s\n", __func__);
		return 1;
	}

	memcpy(buf, start, rrr_length_from_ptr_sub_bug_const(numbers_end, start));
	buf[numbers_end - start] = '\0';

	char *endptr;
	unsigned long long int number = strtoull(buf, &endptr, base);

	if (endptr == NULL) {
		RRR_BUG("Endpointer was NULL in %s\n", __func__);
	}

	rrr_biglength result_tmp = rrr_length_from_ptr_sub_bug_const(endptr, buf);
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(result_tmp, "rrr_http_util_strtoull_raw");

	*result = number;
	*result_len = rrr_length_from_biglength_bug_const(result_tmp);

	return 0;
}

struct rrr_http_util_strtoull_callback_data {
	unsigned long long int *result;
	int base;
};

static int __rrr_http_util_strtoull_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_http_util_strtoull_callback_data *callback_data = arg;

	rrr_length result_len = 0;
	return rrr_http_util_strtoull_raw(callback_data->result, &result_len, str, str + len, callback_data->base);
}

int rrr_http_util_strtoull (
		unsigned long long int *result,
		const struct rrr_nullsafe_str *nullsafe,
		int base
) {
	struct rrr_http_util_strtoull_callback_data callback_data = {
			result,
			base
	};

	return rrr_nullsafe_str_with_raw_do_const (nullsafe, __rrr_http_util_strtoull_callback, &callback_data);
}

int rrr_http_util_strcasestr (
		const char **result_start,
		rrr_length *result_len,
		const char *start,
		const char *end,
		const char *needle
) {
	rrr_biglength needle_len = strlen(needle);
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(needle_len, "rrr_http_util_strcasestr");

	const char *needle_end = needle + needle_len;
	if (needle_end < needle) {
		RRR_BUG("BUG: Pointer overflow in rrr_http_util_strcasestr\n");
	}

	*result_start = NULL;
	*result_len = 0;

	const char *result = NULL;
	rrr_length len = 0;

	if (end - start < (rrr_slength) needle_len) {
		return 1;
	}

	const char *revert_position = NULL;

	const char *needle_pos = needle;
	for (const char *pos = start; pos < end; pos++) {
		char a = (char) tolower(*pos);
		char b = (char) tolower(*needle_pos);

		if (a == b) {
			needle_pos++;
			len++;
			if (revert_position == NULL) {
				revert_position = pos + 1;
			}
			if (result == NULL) {
				result = pos;
			}
			if (needle_pos == needle_end) {
				break;
			}
		}
		else {
			if (revert_position != NULL) {
				pos = revert_position;
				revert_position = NULL;
			}
			needle_pos = needle;
			result = NULL;
			len = 0;
		}
	}

	*result_start = result;
	*result_len = len;

	return (result == NULL);
}

const char *rrr_http_util_strchr (
		const char *start,
		const char *end,
		char chr
) {
	for (const char *pos = start; pos < end; pos++) {
		if (*pos == chr) {
			return pos;
		}
	}

	return NULL;
}

rrr_length rrr_http_util_count_whsp (
		const char *start,
		const char *end
) {
	rrr_length ret = 0;

	for (const char *pos = start; pos < end; pos++) {
		if (*pos != ' ' && *pos != '\t') {
			break;
		}
		ret++;
	}

	return ret;
}

void rrr_http_util_uri_clear (
		struct rrr_http_uri *uri
) {
	RRR_FREE_IF_NOT_NULL(uri->endpoint);
	RRR_FREE_IF_NOT_NULL(uri->host);
	RRR_FREE_IF_NOT_NULL(uri->protocol);
}

void rrr_http_util_uri_destroy (
		struct rrr_http_uri *uri
) {
	rrr_http_util_uri_clear(uri);
	rrr_free(uri);
}

static int __rrr_http_util_uri_validate_characters_foreach_byte_callback (
		char byte,
		void *arg
) {
	char *invalid = arg;

	if (	(byte >= 'A' && byte <= 'Z') ||
			(byte >= 'a' && byte <= 'z') ||
			(byte >= '0' && byte <= '9') ||
			(byte >= '!' && byte <= '/' && byte != '"') ||
			(byte == '_' || byte == '~' || byte == ':' || byte == '?' || byte == '[' || byte == ']' || byte == '@' || byte == ';' || byte == '=')
	) {
		// OK
	}
	else {
		*invalid = byte;
		return 1;
	}

	return 0;
}

static int __rrr_http_util_uri_validate_characters (
		unsigned char *invalid,
		const struct rrr_nullsafe_str *str
) {
	*invalid = '\0';
	return rrr_nullsafe_str_foreach_byte_do(str, __rrr_http_util_uri_validate_characters_foreach_byte_callback, invalid);
}

void rrr_http_util_uri_flags_get (
		struct rrr_http_uri_flags *target,
		const struct rrr_http_uri *uri
) {
	memset (target, '\0', sizeof(*target));

	if (uri->protocol == NULL) {
		 // OK, do nothing
	}
	else if (strcmp(uri->protocol, "http") == 0) {
		target->is_http = 1;
	}
	else if (strcmp(uri->protocol, "https") == 0) {
		target->is_http = 1;
		target->is_tls = 1;
	}
	else if (strcmp(uri->protocol, "ws") == 0) {
		target->is_websocket = 1;
	}
	else if (strcmp(uri->protocol, "wss") == 0) {
		target->is_websocket = 1;
		target->is_tls = 1;
	}
	else {
		RRR_BUG("BUG: Unknown protocol '%s' in rrr_http_util_uri_get_protocol, only values made by rrr_http_util_uri_parse are valid\n", uri->protocol);
	}
}

int rrr_http_util_uri_endpoint_prepend (
		struct rrr_http_uri *uri,
		const char *prefix
) {
	int ret = 0;

	char *endpoint_new = NULL;

	if (uri->endpoint == NULL) {
		if ((endpoint_new = rrr_strdup(prefix)) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http_util_uri_endpoint_prepend A\n");
			ret = 1;
			goto out;
		}
	}
	else {
		// Allocate for extra / and the usual \0
		if ((endpoint_new = rrr_allocate(strlen(prefix) + strlen(uri->endpoint) + 1 + 1)) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http_util_uri_endpoint_prepend B\n");
			ret = 1;
			goto out;
		}

		strcpy(endpoint_new, prefix);

		if (*(endpoint_new + strlen(endpoint_new) - 1) == '/') {
			if (*(uri->endpoint) == '/') {
				// Prefix ends with / and original begins with /, remove one
				*(endpoint_new + strlen(endpoint_new) - 1) = '\0';
			}
		}
		else if (*(uri->endpoint) != '/') {
			// No / at end of prefix nor at beginning of original, add one
			sprintf(endpoint_new + strlen(endpoint_new), "/");
		}

		sprintf(endpoint_new + strlen(endpoint_new), "%s", uri->endpoint);
	}

	RRR_FREE_IF_NOT_NULL(uri->endpoint);
	uri->endpoint = endpoint_new;

	out:
	// Enable if more goto out are added after allocation failure gotos
	// RRR_FREE_IF_NOT_NULL(endpoint_new);
	return ret;
}

static int __rrr_http_util_uri_parse_hostname_and_port (
		struct rrr_http_uri *uri_new,
		const char **pos,
		const char *end,
		int allow_slash,
		int force_port
) {
	int ret = 0;

	const char *str = *pos;
	rrr_slength len = end - *pos;
	rrr_length result_len_tmp = 0;

	assert(len >= 0);

	if (len == 0) {
		RRR_MSG_0("Empty value for host:port URI\n");
		ret = 1;
		goto out;
	}

	while (*pos < end) {
		if (__rrr_http_util_is_alphanumeric((unsigned char) **pos) || **pos == '.') {
			// OK, increment result
		}
		else if (**pos == '-') {
			if (result_len_tmp == 0) {
				RRR_MSG_0("Invalid hostname in host:port URI, cannot begin with '-'\n");
				ret = 1;
				goto out;
			}
			// OK, increment result
		}
		else if ((allow_slash && **pos == '/') || **pos == ':') {
			break;
		}
		else {
			RRR_MSG_0("Invalid character x%02x in host:port URI\n", **pos);
			ret = 1;
			goto out;
		}

		if (++result_len_tmp == 0) {
			RRR_MSG_0("Length overflow while parsing HTTP URI\n");
			ret = 1;
			goto out;
		}

		(*pos)++;
	}

	if (result_len_tmp > 0) {
		if (result_len_tmp + 1 == 0) {
			RRR_MSG_0("Allocation overflow while parsing HTTP URI\n");
			ret = 1;
			goto out;
		}
		if ((uri_new->host = rrr_allocate(result_len_tmp + 1)) == NULL) {
			RRR_MSG_0("Could not allocate memory for hostname in %s\n", __func__);
			ret = 1;
			goto out;
		}
		memcpy(uri_new->host, str, result_len_tmp);
		uri_new->host[result_len_tmp] = '\0';
	}

	if (**pos == ':') {
		(*pos)++;
		unsigned long long port = 0;
		if (rrr_http_util_strtoull_raw(&port, &result_len_tmp, *pos, end, 10) != 0 || port < 1 || port > 65535) {
			RRR_MSG_0("Invalid port in host:name URI\n");
			ret = 1;
			goto out;
		}

		uri_new->port = (uint16_t) port;

		*pos += result_len_tmp;
	}
	else if (force_port) {
		RRR_MSG_0("Invalid character x%02x after hostname in host:port URI\n", **pos);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

#define VERIFY_LENGTH()                                                  \
  do {if (len > RRR_LENGTH_MAX) {                                        \
    RRR_MSG_0("HTTP URI too long to be parsed (%" PRIrrrbl ">%llu)\n",   \
      len, (unsigned long long) RRR_LENGTH_MAX);                         \
    ret = 1;                                                             \
    goto out;                                                            \
  }}while(0) 

static int __rrr_http_util_uri_parse_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_http_uri *uri_new = arg;

	int ret = 0;

	VERIFY_LENGTH();

	const char *pos = str;
	const char *end = str + len;

	const char *new_pos = NULL;

	{
		rrr_length result_len_tmp = 0;

		// Parse protocol if present
		if (rrr_http_util_strcasestr(&new_pos, &result_len_tmp, pos, end, "//") == 0 && new_pos == pos) {
			// OK, empty protocol
		}
		else if (rrr_http_util_strcasestr(&new_pos, &result_len_tmp, pos, end, "://") == 0) {
			ssize_t protocol_name_length = new_pos - pos;
			if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "https", 5) == 0) {
				uri_new->protocol = rrr_strdup("https");
			}
			else if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "http", 4) == 0) {
				uri_new->protocol = rrr_strdup("http");
			}
			else if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "ws", 4) == 0) {
				uri_new->protocol = rrr_strdup("ws");
			}
			else if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "wss", 4) == 0) {
				uri_new->protocol = rrr_strdup("wss");
			}
			else {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
				RRR_MSG_0("Unsupported or missing protocol name in URI '%s'\n", name);
				ret = 1;
				goto out;
			}
			if (uri_new->protocol == NULL) {
				RRR_MSG_0("Could not allocate memory for protocol in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
		else {
			new_pos = pos;
			result_len_tmp = 0;
		}

		pos = new_pos + result_len_tmp;
	}

	// Parse hostname if protocol is present
	if (uri_new->protocol != NULL) {
		if ((ret = __rrr_http_util_uri_parse_hostname_and_port (
				uri_new,
				&pos,
				end,
				1, /* Allow slash */
				0  /* Don't force port */
		)) != 0) {
			goto out;
		}
	}

	// Parse the endpoint and query string
	{
		rrr_length result_len_tmp = 0;
		const char *endpoint_begin = pos;
		while (pos < end) {
			if (__rrr_http_util_is_alphanumeric((unsigned char) *pos)) {
				result_len_tmp++;
			}
			else if (__rrr_http_util_is_header_nonspecial_rfc7230((unsigned char) *pos)) {
				result_len_tmp++;
			}
			else if (__rrr_http_util_is_uri_reserved((unsigned char) *pos)) {
				result_len_tmp++;
			}
			else {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
				RRR_MSG_0("Invalid character %c in URI endpoint '%s'\n", *pos, name);
				ret = 1;
				goto out;
			}
			pos++;
		}

		if (pos != end) {
			RRR_BUG("BUG: pos was != end after parsing in %s\n", __func__);
		}

		if (result_len_tmp == 0) {
			if ((uri_new->endpoint = rrr_strdup("")) == 0) {
				RRR_MSG_0("Could not allocate memory for endpoint in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
		else {
			if ((uri_new->endpoint = rrr_allocate(result_len_tmp + 1)) == 0) {
				RRR_MSG_0("Could not allocate memory for endpoint in %s\n", __func__);
				ret = 1;
				goto out;
			}
			memcpy(uri_new->endpoint, endpoint_begin, result_len_tmp);
			uri_new->endpoint[result_len_tmp] = '\0';
		}
	}

	out:
	return ret;
}

static int __rrr_http_util_uri_host_parse_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_http_uri *uri_new = arg;

	int ret = 0;

	VERIFY_LENGTH();

	const char *pos = str;
	const char *end = str + len;
	const char *new_pos = NULL;
	rrr_length result_len_tmp = 0;

	// Protocol is not allowed
	if (rrr_http_util_strcasestr(&new_pos, &result_len_tmp, pos, end, "://") == 0) {
		RRR_MSG_0("Separator :// not allowed in host:port URI\n");
		ret = 1;
		goto out;
	}
	else if (rrr_http_util_strcasestr(&new_pos, &result_len_tmp, pos, end, "//") == 0) {
		RRR_MSG_0("Separator // not allowed in host:port URI\n");
		ret = 1;
		goto out;
	}

	// Parse hostname and port
	if ((ret = __rrr_http_util_uri_parse_hostname_and_port (
			uri_new,
			&pos,
			end,
			0, /* Don't allow slash */
			1  /* Force port */
	)) != 0) {
		goto out;
	}

	// Port is required by RFC7838, and hostname is not required
	if (uri_new->port == 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
		RRR_MSG_0("Port number was zero in host:port URI '%s'\n", name);
		ret = 1;
		goto out;
	}

	if (end != pos) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
		RRR_MSG_0("Invalid characters at end of host:port URI '%s'\n", name);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_util_uri_parse_final (
		struct rrr_http_uri *uri_result,
		const struct rrr_nullsafe_str *str,
		int (*parse_method)(const void *str, rrr_nullsafe_len len, void *arg)
) {
	int ret = 0;

	unsigned char invalid;

	if (!rrr_nullsafe_str_isset(str)) {
		RRR_BUG("BUG: str was NULL in %s\n", __func__);
	}

	if (__rrr_http_util_uri_validate_characters(&invalid, str) != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,str);
		RRR_MSG_0("Invalid characters in URI '%s' (first invalid character is 0x%02x)\n",
			name, invalid);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_nullsafe_str_with_raw_do_const(str, parse_method, uri_result)) != 0) {
		goto out;
	}

	if (uri_result->port == 0 && uri_result->protocol != NULL) {
		if (rrr_posix_strcasecmp(uri_result->protocol, "https") == 0 || rrr_posix_strcasecmp(uri_result->protocol, "wss") == 0) {
			uri_result->port = 443;
		}
		else if (rrr_posix_strcasecmp(uri_result->protocol, "http") == 0 || rrr_posix_strcasecmp(uri_result->protocol, "ws") == 0) {
			uri_result->port = 80;
		}
	}

	out:
	return ret;
}

static int __rrr_http_util_uri_parse_allocate (
		struct rrr_http_uri **uri_result,
		const struct rrr_nullsafe_str *str,
		int (*parse_method)(const void *str, rrr_nullsafe_len len, void *arg)
) {
	int ret = 0;

	struct rrr_http_uri *uri_new = NULL;

	if ((uri_new = rrr_allocate_zero(sizeof(*uri_new))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_http_util_uri_parse_final (
			uri_new,
			str,
			parse_method
	)) != 0) {
			goto out_destroy;
	}

	*uri_result = uri_new;

	goto out;
	out_destroy:
		rrr_http_util_uri_destroy(uri_new);
	out:
		return ret;
}

int rrr_http_util_uri_parse (
		struct rrr_http_uri **uri_result,
		const struct rrr_nullsafe_str *str
) {
	return __rrr_http_util_uri_parse_allocate(uri_result, str, __rrr_http_util_uri_parse_callback);
}

int rrr_http_util_uri_host_parse (
		struct rrr_http_uri *uri_result,
		const struct rrr_nullsafe_str *str
) {
	return __rrr_http_util_uri_parse_final(uri_result, str, __rrr_http_util_uri_host_parse_callback);
}

static int __rrr_http_util_uri_validate_characters_nullsafe_callback (
		const struct rrr_nullsafe_str *str,
		void *arg
) {
	unsigned char *invalid = arg;
	return __rrr_http_util_uri_validate_characters (
			invalid,
			str
	);
}

int rrr_http_util_uri_validate_characters (
		unsigned char *invalid,
		const char *str
) {
	return rrr_nullsafe_str_with_tmp_str_do (
			str,
			strlen(str),
			__rrr_http_util_uri_validate_characters_nullsafe_callback,
			invalid
	);
}

void rrr_http_util_nprintf (
		rrr_length length,
		const char *format,
		...
) {
	va_list args;
	va_start (args, format);

	char *tmp = NULL;
	int res_i = 0;

	if ((res_i = rrr_vasprintf(&tmp, format, args)) <= 0) {
		RRR_MSG_0("Warning: Could not allocate memory in rrr_http_util_nprintf\n");
	}
	else {
		rrr_slength res = res_i;
		if (res > (rrr_slength) length) {
			tmp[length] = '\0';
		}
		printf("%s", tmp);
	}

	va_end(args);

	RRR_FREE_IF_NOT_NULL(tmp);
}

void rrr_http_util_dbl_ptr_free (void *ptr) {
	void *to_free = *((void **) ptr);
	RRR_FREE_IF_NOT_NULL(to_free);
}

enum rrr_http_method rrr_http_util_method_str_to_enum (
		const char *method_str
) {
	enum rrr_http_method method = RRR_HTTP_METHOD_GET;

	/*
	 * DO NOT REMOVE THIS COMMENT
	 * Default method when user only specifies POST is RRR_HTTP_METHOD_POST_URLENCODED
	 */

	if (method_str == NULL || *(method_str) == '\0') {
		// Default to GET
	}
	else if ( strcasecmp(method_str, "get") == 0) {
		method = RRR_HTTP_METHOD_GET;
	}
	else if ( strcasecmp(method_str, "head") == 0) {
		method = RRR_HTTP_METHOD_HEAD;
	}
	else if ( strcasecmp(method_str, "options") == 0) {
		method = RRR_HTTP_METHOD_OPTIONS;
	}
	else if ( strcasecmp(method_str, "delete") == 0) {
		method = RRR_HTTP_METHOD_DELETE;
	}
	else if ( strcasecmp(method_str, "put") == 0) {
		method = RRR_HTTP_METHOD_PUT;
	}
	else if ( strcasecmp(method_str, "patch") == 0) {
		method = RRR_HTTP_METHOD_PATCH;
	}
	else if ( strcasecmp(method_str, "post") == 0) {
		method = RRR_HTTP_METHOD_POST;
	}
	else {
		RRR_MSG_0("Warning: Unknown value '%s' for HTTP method in rrr_http_util_method_str_to_enum, defaulting to GET\n", method_str);
	}

	return method;
}

enum rrr_http_body_format rrr_http_util_format_str_to_enum (
		const char *format_str
) {
	enum rrr_http_body_format format = RRR_HTTP_BODY_FORMAT_URLENCODED;

	if (format_str == NULL || *(format_str) == '\0') {
		// Default to URLENCODED
	}
	else if (strcasecmp(format_str, "urlencoded") == 0) {
		format = RRR_HTTP_BODY_FORMAT_URLENCODED;
	}
	else if (strcasecmp(format_str, "multipart") == 0) {
		format = RRR_HTTP_BODY_FORMAT_MULTIPART_FORM_DATA;
	}
	else if (strcasecmp(format_str, "json") == 0) {
#ifdef RRR_WITH_JSONC
		format = RRR_HTTP_BODY_FORMAT_JSON;
#else
		RRR_MSG_0("Warning: Value 'json' set for HTTP format in rrr_http_util_format_str_to_enum, but RRR is not compiled with JSON support. Defaulting to URLENCODED\n", format_str);
#endif
	}
	else if (strcasecmp(format_str, "raw") == 0) {
		format = RRR_HTTP_BODY_FORMAT_RAW;
	}
	else {
		RRR_MSG_0("Warning: Unknown value '%s' for HTTP format in rrr_http_util_format_str_to_enum, defaulting to URLENCODED\n", format_str);
	}

	return format;
}

struct rrr_http_util_iana_response_code {
	unsigned int code;	
	const char *phrase;
};

static const struct rrr_http_util_iana_response_code rrr_http_util_iana_response_codes[] = {
	// Common IANA codes
	{200, "OK"},
	{204, "No Content"},
	{400, "Bad Request"},
	{403, "Forbidden"},
	{404, "Not Found"},
	{500, "Internal Server Error"},

	// Non-iana codes
	{418, "I'm a teapot"}, // RFC2324/RFC7168

	// Other IANA codes
	{100, "Continue"},
	{101, "Switching Protocols"},
	{102, "Processing"},
	{103, "Early Hints"},
	{201, "Created"},
	{202, "Accepted"},
	{203, "Non-Authoritative Information"},
	{205, "Reset Content"},
	{206, "Partial Content"},
	{207, "Multi-Status"},
	{208, "Already Reported"},
	{226, "IM Used"},
	{300, "Multiple Choices"},
	{301, "Moved Permanently"},
	{302, "Found"},
	{303, "See Other"},
	{304, "Not Modified"},
	{305, "Use Proxy"},
	{307, "Temporary Redirect"},
	{308, "Permanent Redirect"},
	{401, "Unauthorized"},
	{402, "Payment Required"},
	{405, "Method Not Allowed"},
	{406, "Not Acceptable"},
	{407, "Proxy Authentication Required"},
	{408, "Request Timeout"},
	{409, "Conflict"},
	{410, "Gone"},
	{411, "Length Required"},
	{412, "Precondition Failed"},
	{413, "Payload Too Large"},
	{414, "URI Too Long"},
	{415, "Unsupported Media Type"},
	{416, "Range Not Satisfiable"},
	{417, "Expectation Failed"},
	{421, "Misdirected Request"},
	{422, "Unprocessable Entity"},
	{423, "Locked"},
	{424, "Failed Dependency"},
	{425, "Too Early"},
	{426, "Upgrade Required"},
	{428, "Precondition Required"},
	{429, "Too Many Requests"},
	{431, "Request Header Fields Too Large"},
	{451, "Unavailable For Legal Reasons"},
	{501, "Not Implemented"},
	{502, "Bad Gateway"},
	{503, "Service Unavailable"},
	{504, "Gateway Timeout"},
	{505, "HTTP Version Not Supported"},
	{506, "Variant Also Negotiates"},
	{507, "Insufficient Storage"},
	{508, "Loop Detected"},
	{510, "Not Extended"},
	{511, "Network Authentication Required"}
};

const char *rrr_http_util_iana_response_phrase_from_status_code (
		unsigned int status_code
) {
	if (status_code < 100 || status_code > 599) {
		goto out_unknown;
	}

	int retries = 1;
	while (--retries >= 0) {
		for (size_t i = 0; i < sizeof(rrr_http_util_iana_response_codes) / sizeof(rrr_http_util_iana_response_codes[0]); i++) {
			const struct rrr_http_util_iana_response_code *code = &rrr_http_util_iana_response_codes[i];
			if (code->code == status_code) {
				return code->phrase;
			}
		}

		status_code -= status_code % 100;
	}

	out_unknown:
	return "Unknown status";
}
#ifdef RRR_WITH_JSONC
int rrr_http_util_json_to_arrays (
		const char *data,
		rrr_length data_size,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
) {
	return rrr_json_to_arrays (data, data_size, RRR_HTTP_UTIL_JSON_TO_ARRAYS_MAX_LEVELS, callback, callback_arg);
}
#endif
#ifdef RRR_HTTP_UTIL_WITH_ENCODING
int rrr_http_util_encode (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input,
		const char *encoding
) {
	int ret = 0;

	/* Only one single gzip encoding is supported, and parsing 
	 * of multiple encodings is not performed. */

#ifdef RRR_WITH_ZLIB
	if (strcmp(encoding, "gzip") == 0) {
		if ((ret = rrr_zlib_gzip_compress_nullsafe (
				output,
				input
		)) != 0) {
			RRR_MSG_0("Compression failed in %s\n", __func__);
		}
		goto out;
	}
#endif

	RRR_MSG_0("Unsupported HTTP encoding '%s'\n", encoding);

	out:
	return ret;
}

int rrr_http_util_decode (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input,
		const struct rrr_nullsafe_str *encoding
) {
	int ret = 0;

	/* Only one single gzip encoding is supported, and parsing 
	 * of multiple encodings is not performed. */

	if (!(rrr_nullsafe_str_len(input) > 0)) {
		RRR_BUG("Input had zero length in %s\n", __func__);
	}

#ifdef RRR_WITH_ZLIB
	if (rrr_nullsafe_str_cmpto_case(encoding, "gzip") == 0) {
		if ((ret = rrr_zlib_gzip_decompress_nullsafe (
				output,
				input
		)) != 0) {
			RRR_MSG_0("Decompression failed in %s\n", __func__);
		}
		goto out;
	}
#endif

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(encoding_str,encoding);
	RRR_MSG_0("Unsupported HTTP encoding '%s'\n", encoding_str);

	out:
	return ret;
}

const char *rrr_http_util_encodings_get (void) {
	return "gzip";
}
#endif

int rrr_http_util_alpn_iterate (
		const char * const alpn,
		unsigned int length,
		int (*callback)(unsigned int i, const char *alpn, unsigned char alpn_length, void *arg),
		void *callback_arg
) {
	int ret = 0;

	unsigned int i = 0;

	const char *pos = alpn;
	const char * const end = alpn + length;

	while (pos < end) {
		unsigned char length = (unsigned char) *pos;
		pos++;
		assert(pos + length <= end);

		if ((ret = callback(i, pos, length, callback_arg)) != 0) {
			goto out;
		}

		pos += length;
		i++;
	}

	assert(pos == end);

	out:
	return ret;
}

struct rrr_http_util_make_alt_svc_header_callback_data {
	struct rrr_string_builder *target;
	uint16_t port;
};

static int __rrr_http_util_make_alt_svc_header_callback (
		unsigned int i,
		const char *alpn,
		unsigned char length,
		void *arg
) {
	struct rrr_http_util_make_alt_svc_header_callback_data *callback_data = arg;

	(void)(i);

	int ret = 0;

	// Only add h2, h3, h3-29 etc. and not http/2 or http/1.1
	if (memchr(alpn, '/', length) != NULL) {
		goto out;
	}

	if (rrr_string_builder_length(callback_data->target) > 0) {
		if ((ret = rrr_string_builder_append_raw(callback_data->target, ",", 1)) != 0) {
			goto out;
		}
	}
	if ((ret = rrr_string_builder_append_raw(callback_data->target, alpn, length)) != 0) {
		goto out;
	}
	if ((ret = rrr_string_builder_append_format(callback_data->target, "=\":%u\"; ma=3600", callback_data->port)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_util_make_alt_svc_header (
		struct rrr_string_builder *target,
		uint16_t tls_port,
		uint16_t quic_port
) {
	(void)(tls_port);
	(void)(quic_port);

	int ret = 0;

	assert(tls_port > 0 || quic_port > 0);
	assert(rrr_string_builder_length(target) == 0);
	
#if defined(RRR_WITH_NGHTTP2)
	if (tls_port > 0) {
		const char *alpn = NULL;
		unsigned int length = 0;

		struct rrr_http_util_make_alt_svc_header_callback_data callback_data = {
			target,
			tls_port
		};

		rrr_http_application_http2_alpn_protos_get (&alpn, &length);

		if ((ret = rrr_http_util_alpn_iterate (
				alpn,
				length,
				__rrr_http_util_make_alt_svc_header_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}
#endif

#if defined(RRR_WITH_HTTP3)
	if (quic_port > 0) {
		const char *alpn = NULL;
		unsigned int length = 0;

		struct rrr_http_util_make_alt_svc_header_callback_data callback_data = {
			target,
			quic_port
		};

		rrr_http_application_http3_alpn_protos_get (&alpn, &length);

		if ((ret = rrr_http_util_alpn_iterate (
				alpn,
				length,
				__rrr_http_util_make_alt_svc_header_callback,
				&callback_data
		)) != 0 ) {
			goto out;
		}
	}
#endif

	goto out;
	out:
	return ret;
}
