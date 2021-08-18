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

#include "utf8.h"

#include <stdint.h>
#include <ctype.h>
#include <string.h>

static int __rrr_utf8_get_character_continue (uint32_t *result, uint32_t c, const uint8_t **pos, const uint8_t *end) {
	if (*pos >= end) {
		return 1;
	}

	uint32_t d = **pos;
	(*pos)++;

	if (c >= 0xC2 && c <= 0xDF && d >= 0x80 && d <= 0xBF) {
		c = c & 0x1F; // 5 bits
		d = d & 0x3F; // 6 bits

		*result = (c << 6) | d;
		return 0;
	}

	if (*pos >= end) {
		return 1;
	}

	uint32_t e = **pos;
	(*pos)++;

	if (	(c == 0xE0              && d >= 0xA0 && d <= 0xBF && e >= 0x80 && e <= 0xBF) ||
			(c >= 0xE1 && c <= 0xEC && d >= 0x80 && d <= 0xBF && e >= 0x80 && e <= 0xBF) ||
			(c == 0xED              && d >= 0x80 && d <= 0x9F && e >= 0x80 && e <= 0xBF) ||
			(c >= 0xEE && c <= 0xEF && d >= 0x80 && d <= 0xBF && e >= 0x80 && e <= 0xBF)
	) {
		c = c & 0x0F; // 4 bits
		d = d & 0x3F; // 6 bits
		e = e & 0x3F; // 6 bits

		*result = (c << 12) | (d << 6) | e;
		return 0;
	}

	if (*pos >= end) {
		return 1;
	}

	uint32_t f = **pos;
	(*pos)++;

	if (	(c == 0xF0              && d >= 0x90 && d <= 0xBF && e >= 0x80 && e <= 0xBF && f >= 0x80 && f <= 0xBF) ||
			(c >= 0xF1 && c <= 0xF3 && d >= 0x80 && d <= 0xBF && e >= 0x80 && e <= 0xBF && f >= 0x80 && f <= 0xBF) ||
			(c == 0xF4              && d >= 0x80 && d <= 0x8F && e >= 0x80 && e <= 0xBF && f >= 0x80 && f <= 0xBF)
	) {
		c = c & 0x07; // 3 bits
		d = d & 0x3F; // 6 bits
		e = e & 0x3F; // 6 bits
		f = f & 0x3F; // 6 bits

		*result = (c << 18) | (d << 12) | (e << 6) | f;
		return 0;
	}

	return 1;
}

int rrr_utf8_get_character (uint32_t *result, const char **pos, const char *end) {
	*result = 0;

	if (*pos >= end) {
		return 0;
	}

	uint8_t c = **((uint8_t**) pos);
	(*pos)++;

	if (c <= 0x7F) {
		*result = c;
		return 0;
	}

	return __rrr_utf8_get_character_continue (result, c, (const uint8_t **) pos, (const uint8_t *) end);
}

int rrr_utf8_validate (const char *buf, rrr_length len) {
	int ret = 0;

	const char *pos = buf;
	const char *end = buf + len;

	uint32_t result = 0;
	do {
		ret = rrr_utf8_get_character (&result, &pos, end);
	} while (ret == 0 && !(ret == 0 && result == 0));

	return ret;
}

int rrr_utf8_validate_and_iterate (
		const char *buf,
		rrr_length len,
		int (*callback)(uint32_t character, void *arg),
		void *callback_arg
) {
	int ret = 0;

	const char *pos = buf;
	const char *end = buf + len;

	uint32_t result = 0;
	do {
		ret = rrr_utf8_get_character (&result, &pos, end);
		if (ret != 0 || (ret == 0 && result == 0)) {
			return ret;
		}
		if ((ret = callback(result, callback_arg)) != 0) {
			return ret;
		}
	} while (ret == 0);

	return ret;
}

// TODO : Currently only converts ASCII
void rrr_utf8_strtoupper (char *buf) {
	for (size_t i = 0; i < strlen(buf); i++) {
		buf[i] = (char) toupper(buf[i]);
	}
}
