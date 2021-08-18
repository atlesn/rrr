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

#include "http_common.h"
#include "../rrr_types.h"

struct rrr_http_part;
struct rrr_nullsafe_str;

int rrr_http_part_parse (
		struct rrr_http_part *result,
		rrr_biglength *target_size,
		rrr_biglength *parsed_bytes,
		const char *data_ptr,
		rrr_biglength start_pos,
		const char *end,
		enum rrr_http_parse_type parse_type
);
int rrr_http_part_parse_request_data_set (
		struct rrr_http_part *part,
		rrr_biglength data_length,
		enum rrr_http_application_type application_type,
		enum rrr_http_version version,
		const struct rrr_nullsafe_str *request_method,
		const struct rrr_nullsafe_str *uri
);
int rrr_http_part_parse_response_data_set (
		struct rrr_http_part *part,
		rrr_biglength data_length
);

#endif /* RRR_HTTP_PART_PARSE_H */
