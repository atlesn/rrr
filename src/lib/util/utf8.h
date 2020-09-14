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

#ifndef RRR_UTF8_H
#define RRR_UTF8_H

#include <inttypes.h>

int rrr_utf8_get_character (uint32_t *result, const char **pos, const char *end);
int rrr_utf8_validate (const char *buf, int len);
int rrr_utf8_validate_and_iterate (
		const char *buf,
		int len,
		int (*callback)(uint32_t character, void *arg),
		void *callback_arg
);
void rrr_utf8_strtoupper (char *buf);

#endif /* RRR_UTF8_H */
