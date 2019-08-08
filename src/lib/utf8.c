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

#include <stdint.h>

#include "utf8.h"

static int __rrr_utf8_get_character (uint32_t *result, const char **pos, const char *end) {
	if (*pos >= end) {
		return 0;
	}

	uint8_t c = **pos;
	uint8_t d = 0;
	uint8_t e = 0;
	uint8_t f = 0;
	(*pos)++;

	if (c <= 0x7F) {
		*result = c;
		return 0;
	}

	if (*pos >= end) {
		return 1;
	}

	d = **pos;
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

	e = **pos;
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

	f = **pos;
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

int rrr_utf8_validate (const char *buf, int len) {
	int ret = 0;

	const char *pos = buf;
	const char *end = buf + len;

	do {
		uint32_t result;
		ret = __rrr_utf8_get_character (&result, &pos, end);
	} while (ret == 0);

	return ret;
}

int rrr_utf8_validate_and_iterate (
		const char *buf,
		int len,
		int (*callback)(uint32_t character, void *arg),
		void *callback_arg
) {
	int ret = 0;

	const char *pos = buf;
	const char *end = buf + len;

	do {
		uint32_t result = 0;
		ret = __rrr_utf8_get_character (&result, &pos, end);
		if (ret != 0) {
			return ret;
		}
		if ((ret = callback(result, callback_arg)) != 0) {
			return ret;
		}
	} while (ret == 0);

	return ret;
}
