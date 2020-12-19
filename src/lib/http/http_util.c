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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#include "../log.h"

#include "http_util.h"

#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../helpers/nullsafe_str.h"

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
		bytes_to_copy = end - start;
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
		rrr_length *len,
		void *str,
		void *arg
) {
	(void)(arg);

	int ret = 0;

	const unsigned char *start = str;
	const unsigned char *end = str + *len;

	unsigned char *target = str;

	rrr_length wpos = 0;

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

			c = result;
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

int __rrr_http_util_uri_encode_foreach_byte_callback (char byte, void *arg) {
	char **wpos = arg;

	if (__rrr_http_util_is_alphanumeric(byte) || __rrr_http_util_is_uri_unreserved_rfc2396(byte)) {
		**wpos = byte;
		(*wpos)++;
	}
	else {
		sprintf((*wpos), "%s%02x", "%", byte);
		(*wpos) += 3;
	}

	return 0;
}

// We allow non-ASCII here
int rrr_http_util_uri_encode (
		struct rrr_nullsafe_str **target,
		const struct rrr_nullsafe_str *str
) {
	rrr_biglength result_max_length = (str != NULL ? rrr_nullsafe_str_len(str) * 3 : 0);
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(result_max_length,"rrr_http_util_encode_uri");

	*target = NULL;

	int ret = 0;

	char *result = malloc(result_max_length + 1); // Allocate extra byte for 0 from sprintf
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_util_encode_uri\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', result_max_length + 1);

	if (result_max_length == 0) {
		goto out;
	}

	char *wpos = result;
	char *wpos_max = result + result_max_length;

	// NOTE : Pass double pointer to wpos
	if ((ret = rrr_nullsafe_str_foreach_byte_do(str, __rrr_http_util_uri_encode_foreach_byte_callback, &wpos)) != 0) {
		goto out;
	}

	if (wpos > wpos_max) {
		RRR_BUG("Result string was too long in rrr_http_util_encode_uri\n");
	}

	if (*target == NULL) {
		if ((ret = rrr_nullsafe_str_new_or_replace_empty(target)) != 0) {
			goto out;
		}
	}

	rrr_nullsafe_str_set_allocated(*target, (void **) &result, wpos - result);

	out:
	rrr_nullsafe_str_destroy_if_not_null(target);
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

static int __rrr_http_util_unquote_string_callback (
		rrr_length *len,
		void *str,
		void *arg
) {
	(void)(arg);

	unsigned char *start = str;
	unsigned char *end = str + *len;

	unsigned char *target = str;

	rrr_length wpos = 0;

	while (start < end) {
		if (*start == '"' || *start == '(') {
			char endquote = (*start == '"' ? '"' : ')');

			// Skip past begin quote
			start++;

			if (start >= end) {
				break;
			}

			for (; start < end; start++) {
				if (*start == '\\') {
					if (start + 1 < end) {
						char next = *(start + 1);
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

	rrr_biglength result_size = length * 2 + 2 + 1;
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(length, "rrr_http_util_quote_header_value B");

	char *result = malloc(result_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_util_quote_header_value\n");
		err = 1;
		goto out;
	}
	memset (result, '\0', result_size);

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
		rrr_length len,
		void *arg
) {
	struct rrr_http_util_quote_header_value_nullsafe_callback_data *callback_data = arg;

	return rrr_http_util_header_value_quote (
				str,
				len,
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

	return rrr_nullsafe_str_with_raw_do_const_return_str(str, __rrr_http_util_quote_header_value_nullsafe_callback, &callback_data);
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
			RRR_BUG("Unkonwn base %i in rrr_http_util_strtoull\n", base);
		}
	}

	if (pos == end) {
		numbers_end = end;
	}

	if (numbers_end == start) {
		return 1;
	}

	if (numbers_end - start > 63) {
		RRR_MSG_0("Number was too long in __rrr_http_part_strtoull\n");
		return 1;
	}

	memcpy(buf, start, numbers_end - start);
	buf[numbers_end - start] = '\0';

	char *endptr;
	unsigned long long int number = strtoull(buf, &endptr, base);

	if (endptr == NULL) {
		RRR_BUG("Endpointer was NULL in __rrr_http_part_strtoull\n");
	}

	rrr_biglength result_tmp = endptr - buf;
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(result_tmp, "__rrr_http_part_strtoull");

	*result = number;
	*result_len = result_tmp;

	return 0;
}

struct rrr_http_util_strtoull_callback_data {
	unsigned long long int *result;
	int base;
};

static int __rrr_http_util_strtoull_callback (
		const void *str,
		rrr_length len,
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
		char a = tolower(*pos);
		char b = tolower(*needle_pos);

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

void rrr_http_util_uri_destroy (
		struct rrr_http_uri *uri
) {
	RRR_FREE_IF_NOT_NULL(uri->endpoint);
	RRR_FREE_IF_NOT_NULL(uri->host);
	RRR_FREE_IF_NOT_NULL(uri->protocol);
	free(uri);
}

static int __rrr_http_util_uri_validate_characters_foreach_byte_callback (
		char byte,
		void *arg
) {
	unsigned char *invalid = arg;

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
		if ((endpoint_new = strdup(prefix)) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http_util_uri_endpoint_prepend A\n");
			ret = 1;
			goto out;
		}
	}
	else {
		// Allocate for extra / and the usual \0
		if ((endpoint_new = malloc(strlen(prefix) + strlen(uri->endpoint) + 1 + 1)) == NULL) {
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

static int __rrr_http_util_uri_parse_callback (
		const void *str,
		rrr_length len,
		void *arg
) {
	struct rrr_http_uri *uri_new = arg;

	int ret = 0;

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
				uri_new->protocol = strdup("https");
			}
			else if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "http", 4) == 0) {
				uri_new->protocol = strdup("http");
			}
			else if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "ws", 4) == 0) {
				uri_new->protocol = strdup("ws");
			}
			else if (protocol_name_length > 0 && rrr_posix_strncasecmp(pos, "wss", 4) == 0) {
				uri_new->protocol = strdup("wss");
			}
			else {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
				RRR_MSG_0("Unsupported or missing protocol name in URI '%s'\n", name);
				ret = 1;
				goto out;
			}
			if (uri_new->protocol == NULL) {
				RRR_MSG_0("Could not allocate memory for protocol in __rrr_http_util_uri_parse_callback\n");
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
	const char *hostname_begin = pos;
	if (uri_new->protocol != NULL) {
		rrr_length result_len_tmp = 0;
		while (pos < end) {
			if (__rrr_http_util_is_alphanumeric(*pos)) {
				result_len_tmp++;
			}
			else if (*pos == '-') {
				if (result_len_tmp == 0) {
					RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
					RRR_MSG_0("Invalid hostname in URI '%s', cannot begin with '-'\n", name);
					ret = 1;
					goto out;
				}
				result_len_tmp++;
			}
			else if (*pos == '.') {
				result_len_tmp++;
			}
			else if (*pos == '/' || *pos == ':') {
				break;
			}
			else {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
				RRR_MSG_0("Invalid character %c in URI '%s' hostname\n", *pos, name);
				ret = 1;
				goto out;
			}

			pos++;
		}

		if (result_len_tmp > 0) {
			if ((uri_new->host = malloc(result_len_tmp + 1)) == NULL) {
				RRR_MSG_0("Could not allocate memory for hostname in __rrr_http_util_uri_parse_callback\n");
				ret = 1;
				goto out;
			}
			memcpy(uri_new->host, hostname_begin, result_len_tmp);
			uri_new->host[result_len_tmp] = '\0';
		}

		if (*pos == ':') {
			pos++;
			unsigned long long port = 0;
			if (rrr_http_util_strtoull_raw(&port, &result_len_tmp, pos, end, 10) != 0 || port < 1 || port > 65535) {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len);
				RRR_MSG_0("Invalid port in URL '%s'\n", name);
				ret = 1;
				goto out;
			}

			uri_new->port = port;

			pos += result_len_tmp;
		}
	}

	// Parse the endpoint and query string
	{
		rrr_length result_len_tmp = 0;
		const char *endpoint_begin = pos;
		while (pos < end) {
			if (__rrr_http_util_is_alphanumeric(*pos)) {
				result_len_tmp++;
			}
			else if (__rrr_http_util_is_header_nonspecial_rfc7230(*pos)) {
				result_len_tmp++;
			}
			else if (__rrr_http_util_is_uri_reserved(*pos)) {
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
			RRR_BUG("BUG: pos was != end after parsing in __rrr_http_util_uri_parse_callback\n");
		}

		if (result_len_tmp == 0) {
			if ((uri_new->endpoint = strdup("")) == 0) {
				RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_util_uri_parse_callback\n");
				ret = 1;
				goto out;
			}
		}
		else {
			if ((uri_new->endpoint = malloc(result_len_tmp + 1)) == 0) {
				RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_util_uri_parse_callback\n");
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

int rrr_http_util_uri_parse (
		struct rrr_http_uri **uri_result,
		const struct rrr_nullsafe_str *str
) {
	int ret = 0;
	struct rrr_http_uri *uri_new = NULL;

	*uri_result = NULL;

	if (!rrr_nullsafe_str_isset(str)) {
		RRR_BUG("BUG: str was NULL in rrr_http_uri_parse\n");
	}

	unsigned char invalid;
	if (__rrr_http_util_uri_validate_characters(&invalid, str) != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,str);
		RRR_MSG_0("Invalid characters in URI '%s' (first invalid character is 0x%02x)\n",
				name, invalid);
		ret = 1;
		goto out;
	}

	if ((uri_new = malloc(sizeof(*uri_new))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_uri_parse\n");
		ret = 1;
		goto out;
	}

	memset(uri_new, '\0', sizeof(*uri_new));

	if ((ret = rrr_nullsafe_str_with_raw_do_const(str, __rrr_http_util_uri_parse_callback, uri_new)) != 0) {
		goto out_destroy;
	}

	if (uri_new->port == 0 && uri_new->protocol != NULL) {
		if (rrr_posix_strcasecmp(uri_new->protocol, "https") == 0 || rrr_posix_strcasecmp(uri_new->protocol, "wss")) {
			uri_new->port = 443;
		}
		else if (rrr_posix_strcasecmp(uri_new->protocol, "http") == 0 || rrr_posix_strcasecmp(uri_new->protocol, "ws")) {
			uri_new->port = 80;
		}
	}

	*uri_result = uri_new;

	goto out;
	out_destroy:
		rrr_http_util_uri_destroy(uri_new);
	out:
		return ret;
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
