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

#ifndef RRR_HTTP_PART_H
#define RRR_HTTP_PART_H

#include <stdio.h>

#include "linked_list.h"
#include "http_fields.h"
#include "read_constants.h"

#define RRR_HTTP_PARSE_OK			RRR_READ_OK
#define RRR_HTTP_PARSE_HARD_ERR 	RRR_READ_HARD_ERROR
#define RRR_HTTP_PARSE_SOFT_ERR		RRR_READ_SOFT_ERROR
#define RRR_HTTP_PARSE_INCOMPLETE	RRR_READ_INCOMPLETE
//#define RRR_HTTP_PARSE_UNTIL_CLOSE	RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE
//#define RRR_HTTP_PARSE_CHUNKED		RRR_SOCKET_READ_COMPLETE_METHOD_CHUNKED

#define RRR_HTTP_PART_PROTOCOL_VERSION_1_1 1

enum rrr_http_parse_type {
	RRR_HTTP_PARSE_REQUEST,
	RRR_HTTP_PARSE_RESPONSE
};

struct rrr_http_header_field_definition;

struct rrr_http_header_field {
	RRR_LL_NODE(struct rrr_http_header_field);
	struct rrr_http_field_collection fields;
	const struct rrr_http_header_field_definition *definition;
	long long int value_signed;
	long long unsigned int value_unsigned;
	char *name;
	char *value;
};

struct rrr_http_header_field_collection {
	RRR_LL_HEAD(struct rrr_http_header_field);
};

#define RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION \
		struct rrr_http_header_field *field

struct rrr_http_header_field_definition {
	const char *name_lowercase;
	int (*parse)(RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION);
};

struct rrr_http_chunk {
	RRR_LL_NODE(struct rrr_http_chunk);
	ssize_t start;
	ssize_t length;
};

struct rrr_http_chunks {
	RRR_LL_HEAD(struct rrr_http_chunk);
};

struct rrr_http_part {
	RRR_LL_NODE(struct rrr_http_part);
	RRR_LL_HEAD(struct rrr_http_part);
	struct rrr_http_header_field_collection headers;
	struct rrr_http_field_collection fields;
	struct rrr_http_chunks chunks;
	int response_code;
	char *response_str;
	char *request_method;
	char *request_uri;
	int parse_complete;
	int header_complete;
	int is_chunked;
	int parsed_protocol_version;
	const void *data_ptr;
	ssize_t request_length;
	ssize_t header_length;
	ssize_t data_length;
};

void rrr_http_part_destroy (struct rrr_http_part *part);
int rrr_http_part_new (struct rrr_http_part **result);
const struct rrr_http_header_field *rrr_http_part_get_header_field (
		struct rrr_http_part *part,
		const char *name_lowercase
);
int rrr_http_part_parse (
		struct rrr_http_part *result,
		ssize_t *target_size,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t start_pos,
		const char *end,
		enum rrr_http_parse_type parse_type
);
#endif /* RRR_HTTP_PART_H */
