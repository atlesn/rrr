/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_PART_MULTIPART_H
#define RRR_HTTP_PART_MULTIPART_H

struct rrr_http_part;

int rrr_http_part_multipart_process (
		struct rrr_http_part *part,
		const char *data_ptr
);
int rrr_http_part_multipart_form_data_make (
		struct rrr_http_part *request_part,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
);

#endif /* HTTP_PART_MULTIPART_H */
