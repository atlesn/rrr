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

#ifndef RRR_HTTP_UTIL_H
#define RRR_HTTP_UTIL_H

#include <stdio.h>

char *rrr_http_util_encode_uri (
		const char *input
);
char *rrr_http_util_quote_header_value (
		const char *input,
		char delimeter_start,
		char delimeter_end
);
const char *rrr_http_util_find_crlf (
		const char *start,
		const char *end
);
int rrr_http_util_strtoull (
		unsigned long long int *result,
		ssize_t *result_len,
		const char *start,
		const char *end
);
int rrr_http_util_strcasestr (
		const char **result_start,
		ssize_t *result_len,
		const char *start,
		const char *end,
		const char *needle
);
const char *rrr_http_util_strchr (
		const char *start,
		const char *end,
		char chr
);
ssize_t rrr_http_util_count_whsp (
		const char *start,
		const char *end
);
void rrr_http_util_strtolower (char *str);

#endif /* RRR_HTTP_UTIL_H */
