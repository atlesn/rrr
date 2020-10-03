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

#ifndef RRR_HTTP_PART_H
#define RRR_HTTP_PART_H

#include <stdio.h>

#include "http_fields.h"
#include "http_common.h"

#include "../read_constants.h"
#include "../util/linked_list.h"
#include "../helpers/nullsafe_str.h"

#define RRR_HTTP_PARSE_OK			RRR_READ_OK
#define RRR_HTTP_PARSE_HARD_ERR 	RRR_READ_HARD_ERROR
#define RRR_HTTP_PARSE_SOFT_ERR		RRR_READ_SOFT_ERROR
#define RRR_HTTP_PARSE_INCOMPLETE	RRR_READ_INCOMPLETE
//#define RRR_HTTP_PARSE_UNTIL_CLOSE	RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE
//#define RRR_HTTP_PARSE_CHUNKED		RRR_SOCKET_READ_COMPLETE_METHOD_CHUNKED

#define RRR_HTTP_PART_PROTOCOL_VERSION_1_1 1

enum rrr_http_parse_type {
	RRR_HTTP_PARSE_REQUEST,
	RRR_HTTP_PARSE_RESPONSE,
	RRR_HTTP_PARSE_MULTIPART
};

#define RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE	(1<<0)
#define RRR_HTTP_HEADER_FIELD_NO_PAIRS			(1<<1)

#define RRR_HTTP_PART_ITERATE_CALLBACK_ARGS			\
		int chunk_idx,								\
		int chunk_total,							\
		const char *data_start,						\
		rrr_biglength chunk_data_size,				\
		rrr_biglength part_data_size,				\
		void *arg

#define RRR_HTTP_PART_DATA_LENGTH(part) \
	((part)->data_length)

#define RRR_HTTP_PART_TOP_LENGTH(part) \
	((part)->headroom_length + (part)->header_length)

#define RRR_HTTP_PART_BODY_LENGTH(part) \
	(RRR_HTTP_PART_DATA_LENGTH(part))

#define RRR_HTTP_PART_BODY_PTR(data_ptr,part) \
	((data_ptr) + RRR_HTTP_PART_TOP_LENGTH(part))

struct rrr_http_header_field_definition;

struct rrr_http_header_field {
	RRR_LL_NODE(struct rrr_http_header_field);

	// This list is filled while parsing the header field
	struct rrr_http_field_collection fields;

	const struct rrr_http_header_field_definition *definition;

	struct rrr_nullsafe_str *name;

	// This is filled by known header field parsers. Pointer
	// must always be checked for NULL before usage, they are
	// only set for certain header field types.
	long long int value_signed;
	long long unsigned int value_unsigned;
	struct rrr_nullsafe_str *binary_value_nullsafe;
	struct rrr_nullsafe_str *value;
};

struct rrr_http_header_field_collection {
	RRR_LL_HEAD(struct rrr_http_header_field);
};

#define RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION \
		struct rrr_http_header_field *field

struct rrr_http_header_field_definition {
	const char *name_lowercase;
	int flags;
	int (*parse)(RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION);
};

struct rrr_http_chunk {
	RRR_LL_NODE(struct rrr_http_chunk);
	size_t start;
	size_t length;
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

	// Setting this causes everything else in a response
	// struct to be ignored when sending
	struct rrr_nullsafe_str *response_raw_data_nullsafe;

	struct rrr_nullsafe_str *request_method_str_nullsafe;
	enum rrr_http_method request_method;

	struct rrr_nullsafe_str *request_uri_nullsafe;

	// Setting this causes raw data to be sent as opposed to
	// generating headers and body
	const char *request_raw_data;
	size_t request_raw_data_size;

	int parse_complete;
	int header_complete;
	int is_chunked;
	int parsed_protocol_version;

//	const void *data_ptr;

	size_t headroom_length;
	size_t header_length;
	size_t data_length;
	int data_length_unknown;
};

void rrr_http_part_destroy (struct rrr_http_part *part);
void rrr_http_part_destroy_void (void *part);
void rrr_http_part_destroy_void_double_ptr (void *arg);
int rrr_http_part_new (struct rrr_http_part **result);
int rrr_http_part_set_allocated_raw_response (
		struct rrr_http_part *part,
		char **raw_data_source,
		size_t raw_data_size
);
void rrr_http_part_set_raw_request_ptr (
		struct rrr_http_part *part,
		const char *raw_data,
		size_t raw_data_size
);
const struct rrr_http_header_field *rrr_http_part_header_field_get (
		const struct rrr_http_part *part,
		const char *name
);
const struct rrr_http_header_field *rrr_http_part_header_field_get_with_value (
		const struct rrr_http_part *part,
		const char *name_lowercase,
		const char *value_anycase
);
int rrr_http_part_update_data_ptr (
		struct rrr_http_part *part
);
int rrr_http_part_header_field_push (
		struct rrr_http_part *part,
		const char *name,
		const char *value
);
int rrr_http_part_fields_iterate_const (
		const struct rrr_http_part *part,
		int (*callback)(const struct rrr_http_field *field, void *callback_arg),
		void *callback_arg
);
int rrr_http_part_header_fields_iterate (
		struct rrr_http_part *part,
		int (*callback)(struct rrr_http_header_field *field, void *arg),
		void *callback_arg
);
void rrr_http_part_header_field_remove (
		struct rrr_http_part *part,
		const char *field
);
int rrr_http_part_chunks_iterate (
		struct rrr_http_part *part,
		const char *data_ptr,
		int (*callback)(RRR_HTTP_PART_ITERATE_CALLBACK_ARGS),
		void *callback_arg
);
int rrr_http_part_process_multipart (
		struct rrr_http_part *part,
		const char *data_ptr
);
int rrr_http_part_parse (
		struct rrr_http_part *result,
		size_t *target_size,
		size_t *parsed_bytes,
		const char *data_ptr,
		size_t start_pos,
		const char *end,
		enum rrr_http_parse_type parse_type
);
int rrr_http_part_extract_post_and_query_fields (
		struct rrr_http_part *target,
		const char *data_ptr
);
int rrr_http_part_merge_chunks (
		char **result_data,
		struct rrr_http_part *part,
		const char *data_ptr
);
void rrr_http_part_dump_header (
		struct rrr_http_part *part
);

#endif /* RRR_HTTP_PART_H */
