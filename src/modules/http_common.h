/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

struct http_common_request_fields {
	union {
		struct {
			const char *http_method;
			const char *http_protocol;
			const char *http_endpoint;
			const char *http_query_string;
			const char *http_authority;
			const char *http_body;
			const char *http_content_transfer_encoding;
			const char *http_content_type;
			const char *http_content_type_boundary;
			const char *http_request_partials;
		};
		const char *index[10];
	};
};

static const struct http_common_request_fields http_common_request_fields = {
	.http_method = "http_method",
	.http_protocol = "http_protocol",
	.http_endpoint = "http_endpoint",
	.http_query_string = "http_query_string",
	.http_authority = "http_authority",
	.http_body = "http_body",
	.http_content_transfer_encoding = "http_content_transfer_encoding",
	.http_content_type = "http_content_type",
	.http_content_type_boundary = "http_content_type_boundary",
	.http_request_partials = "http_request_partials"
};

#define HTTP_COMMON_REQUEST_FIELDS_FOREACH(field)                            \
  const char *field;                                                         \
  for (size_t i = 0;                                                         \
    i < sizeof(http_common_request_fields.index)/sizeof(http_common_request_fields.index[0]) && \
    (field = http_common_request_fields.index[i]); i++)

struct http_common_response_fields {
	const char *http_response_code;
	const char *http_content_type;
	const char *http_body;
};

static const struct http_common_response_fields http_common_response_fields = {
	"http_response_code",
	"http_content_type",
	"http_body"
};

#endif /* HTTP_COMMON_H */
