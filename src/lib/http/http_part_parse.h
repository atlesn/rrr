/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_PART_PARSE_H
#define RRR_HTTP_PART_PARSE_H

#include <stdlib.h>

#include "http_common.h"

struct rrr_http_part;
struct rrr_nullsafe_str;

int rrr_http_part_parse (
		struct rrr_http_part *result,
		size_t *target_size,
		size_t *parsed_bytes,
		const char *data_ptr,
		size_t start_pos,
		const char *end,
		enum rrr_http_parse_type parse_type
);
int rrr_http_part_parse_request_data_set (
		struct rrr_http_part *part,
		size_t data_length,
		enum rrr_http_application_type protocol_version,
		const struct rrr_nullsafe_str *request_method,
		const struct rrr_nullsafe_str *uri
);
int rrr_http_part_parse_response_data_set (
		struct rrr_http_part *part,
		size_t data_length
);

#endif /* RRR_HTTP_PART_PARSE_H */
