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

#include "../global.h"
#include "http_util.h"
#include "gnu.h"

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

// We allow non-ASCII here
char *rrr_http_util_encode_uri (
		const char *input
) {
	ssize_t input_length = strlen(input);
	ssize_t result_max_length = input_length * 3 + 1;

	int err = 0;

	char *result = malloc(result_max_length);
	if (result == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_util_encode_uri\n");
		err = 1;
		goto out;
	}
	memset(result, '\0', result_max_length);

	char *wpos = result;
	char *wpos_max = result + result_max_length;

	for (int i = 0; i < input_length; i++) {
		unsigned char c = *((unsigned char *) input + i);

		if (__rrr_http_util_is_alphanumeric(c) || __rrr_http_util_is_uri_unreserved_rfc2396(c)) {
			*wpos = c;
			wpos++;
		}
		else {
			sprintf(wpos, "%s%02x", "%", c);
			wpos += 3;
		}
	}

	if (wpos > wpos_max) {
		RRR_BUG("Result string was too long in rrr_http_util_encode_uri\n");
	}

	out:
	if (err != 0) {
		RRR_FREE_IF_NOT_NULL(result);
		result = NULL;
	}
	return result;
}

// TODO : Support RFC8187. This function is less forgiving than the standard.
char *rrr_http_util_quote_header_value (
		const char *input,
		char delimeter_start,
		char delimeter_end
) {
	ssize_t length = strlen(input);

	if (length == 0) {
		return NULL;
	}

	int err = 0;

	ssize_t result_length = length * 2 + 2 + 1;
	char *result = malloc(result_length);
	if (result == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_util_quote_header_value\n");
		err = 1;
		goto out;
	}
	memset (result, '\0', result_length);

	char *wpos = result;
	char *wpos_max = result + result_length;

	int needs_quote = 0;
	for (int i = 0; i < length; i++) {
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
			RRR_MSG_ERR("Invalid octet %02x in rrr_http_util_quote_ascii\n", c);
			err = 1;
			goto out;
		}
	}

	if (needs_quote == 0) {
		strcpy(result, input);
	}
	else {
		*wpos = delimeter_start;
		wpos++;

		for (int i = 0; i < length; i++) {
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

int rrr_http_util_strtoull (
		unsigned long long int *result,
		ssize_t *result_len,
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
		RRR_MSG_ERR("Number was too long in __rrr_http_part_strtoull\n");
		return 1;
	}

	memcpy(buf, start, numbers_end - start);
	buf[numbers_end - start] = '\0';

	char *endptr;
	unsigned long long int number = strtoull(buf, &endptr, base);

	if (endptr == NULL) {
		RRR_BUG("Endpointer was NULL in __rrr_http_part_strtoull\n");
	}

	*result = number;
	*result_len = endptr - buf;

	return 0;
}

int rrr_http_util_strcasestr (
		const char **result_start,
		ssize_t *result_len,
		const char *start,
		const char *end,
		const char *needle
) {
	ssize_t needle_len = strlen(needle);
	const char *needle_end = needle + needle_len;

	*result_start = NULL;
	*result_len = 0;

	const char *result = NULL;
	ssize_t len = 0;

	if (end - start < needle_len) {
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

ssize_t rrr_http_util_count_whsp (const char *start, const char *end) {
	ssize_t ret = 0;

	for (const char *pos = start; pos < end; pos++) {
		if (*pos != ' ' && *pos != '\t') {
			break;
		}
		ret++;
	}

	return ret;
}

void rrr_http_util_strtolower (char *str) {
	ssize_t len = strlen(str);
	for (int i = 0; i < len; i++) {
		str[i] = tolower(str[i]);
	}
}

void rrr_http_util_strtoupper (char *str) {
	ssize_t len = strlen(str);
	for (int i = 0; i < len; i++) {
		str[i] = toupper(str[i]);
	}
}

void rrr_http_util_uri_destroy (struct rrr_http_uri *uri) {
	RRR_FREE_IF_NOT_NULL(uri->endpoint);
	RRR_FREE_IF_NOT_NULL(uri->host);
	RRR_FREE_IF_NOT_NULL(uri->protocol);
	free(uri);
}

int rrr_http_util_uri_parse (struct rrr_http_uri **uri_result, const char *uri) {
	int ret = 0;
	struct rrr_http_uri *uri_new = NULL;

	*uri_result = NULL;

	if (uri == NULL) {
		RRR_BUG("uri was NULL in rrr_http_uri_parse\n");
	}

	if ((uri_new = malloc(sizeof(*uri_new))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_uri_parse\n");
		ret = 1;
		goto out;
	}

	memset(uri_new, '\0', sizeof(*uri_new));

	size_t len = strlen(uri);

	const char *pos = uri;
	const char *end = uri + len;

	const char *new_pos;
	ssize_t result_len;

	// Parse protocol if present
	if (rrr_http_util_strcasestr(&new_pos, &result_len, pos, end, "//") && new_pos == pos) {
		if ((uri_new->protocol = strdup("")) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for protocol in rrr_http_uri_parse\n");
			ret = 1;
			goto out_destroy;
		}
	}
	else if (rrr_http_util_strcasestr(&new_pos, &result_len, pos, end, "://") == 0) {
		ssize_t protocol_name_length = new_pos - pos;
		if (protocol_name_length > 0 && strncasecmp(pos, "https", 5) == 0) {
			uri_new->protocol = strdup("https");
		}
		else if (protocol_name_length > 0 && strncasecmp(pos, "http", 4) == 0) {
			uri_new->protocol = strdup("http");
		}
		else {
			RRR_MSG_ERR("Unsupported or missing protocol name in URI '%s'\n", uri);
			ret = 1;
			goto out_destroy;
		}
		if (uri_new->protocol == NULL) {
			RRR_MSG_ERR("Could not allocate memory for protocol in rrr_http_uri_parse\n");
			ret = 1;
			goto out_destroy;
		}
	}

	pos = new_pos + result_len;

	// Parse hostname if protocol is present
	const char *hostname_begin = pos;
	if (uri_new->protocol != NULL) {
		result_len = 0;
		while (pos < end) {
			if (__rrr_http_util_is_alphanumeric(*pos)) {
				result_len++;
			}
			else if (*pos == '-') {
				if (result_len == 0) {
					RRR_MSG_ERR("Invalid hostname in URI '%s', cannot begin with '-'\n", uri);
					ret = 1;
					goto out_destroy;
				}
				result_len++;
			}
			else if (*pos == '.') {
				result_len++;
			}
			else if (*pos == '/' || *pos == ':') {
				break;
			}
			else {
				RRR_MSG_ERR("Invalid character %c in URI '%s' hostname\n", *pos, uri);
				ret = 1;
				goto out_destroy;
			}

			pos++;
		}

		if (result_len > 0) {
			if ((uri_new->host = malloc(result_len + 1)) == NULL) {
				RRR_MSG_ERR("Could not allocate memory for hostname in rrr_http_uri_parse\n");
				ret = 1;
				goto out_destroy;
			}
			memcpy(uri_new->host, hostname_begin, result_len);
			uri_new->host[result_len] = '\0';
		}

		if (*pos == ':') {
			pos++;
			unsigned long long port = 0;
			if (rrr_http_util_strtoull(&port, &result_len, pos, end, 10) != 0 || port < 1 || port > 65535) {
				RRR_MSG_ERR("Invalid port in URL '%s'\n", uri);
				ret = 1;
				goto out_destroy;
			}

			uri_new->port = port;

			pos += result_len;
		}
	}

	// Parse the rest
	result_len = 0;
	const char *endpoint_begin = pos;
	while (pos < end) {
		if (__rrr_http_util_is_alphanumeric(*pos)) {
			result_len++;
		}
		else if (__rrr_http_util_is_header_nonspecial_rfc7230(*pos)) {
			result_len++;
		}
		else if (__rrr_http_util_is_uri_reserved(*pos)) {
			result_len++;
		}
		else {
			RRR_MSG_ERR("Invalid character %c in URI endpoint '%s'\n", *pos, uri);
			ret = 1;
			goto out_destroy;
		}
		pos++;
	}

	if (pos != end) {
		RRR_BUG("BUG: pos was != end after parsing in rrr_http_uri_parse\n");
	}

	if (result_len == 0) {
		if ((uri_new->endpoint = strdup("")) == 0) {
			RRR_MSG_ERR("Could not allocate memory for endpoint in rrr_http_uri_parse\n");
			ret = 1;
			goto out_destroy;
		}
	}
	else {
		if ((uri_new->endpoint = malloc(result_len + 1)) == 0) {
			RRR_MSG_ERR("Could not allocate memory for endpoint in rrr_http_uri_parse\n");
			ret = 1;
			goto out_destroy;
		}
		memcpy(uri_new->endpoint, endpoint_begin, result_len);
		uri_new->endpoint[result_len] = '\0';
	}

	if (uri_new->port == 0 && uri_new->protocol != NULL) {
		if (strcasecmp(uri_new->protocol, "https") == 0) {
			uri_new->port = 443;
		}
		else if (strcasecmp(uri_new->protocol, "http") == 0) {
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

void rrr_http_util_nprintf (size_t length, const char *format, ...) {
	va_list args;
	va_start (args, format);

	char *tmp = NULL;
	int res = 0;

	if ((res = rrr_vasprintf(&tmp, format, args)) <= 0) {
		RRR_MSG_ERR("Warning: Could not allocate memory in rrr_http_util_nprintf\n");
	}
	else {
		if (res > (int) length) {
			tmp[length] = '\0';
		}
		printf("%s", tmp);
	}

	va_end(args);

	RRR_FREE_IF_NOT_NULL(tmp);
}
