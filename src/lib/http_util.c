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

#include "../global.h"
#include "http_util.h"

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
/*
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
*/
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
		VL_MSG_ERR("Could not allocate memory in rrr_http_util_encode_uri\n");
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
		VL_BUG("Result string was too long in rrr_http_util_encode_uri\n");
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
		VL_MSG_ERR("Could not allocate memory in rrr_http_util_quote_header_value\n");
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
			VL_MSG_ERR("Invalid octet %02x in rrr_http_util_quote_ascii\n", c);
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
			VL_BUG("Result string was too long in rrr_http_util_quote_ascii\n");
		}
	}

	out:
	if (err != 0) {
		RRR_FREE_IF_NOT_NULL(result);
		result = NULL;
	}

	return result;
}
