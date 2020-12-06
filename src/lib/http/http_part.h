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
#include "http_header_fields.h"

#include "../read_constants.h"
#include "../util/linked_list.h"
#include "../helpers/nullsafe_str.h"

//#define RRR_HTTP_PARSE_UNTIL_CLOSE	RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE
//#define RRR_HTTP_PARSE_CHUNKED		RRR_SOCKET_READ_COMPLETE_METHOD_CHUNKED

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

#define RRR_HTTP_PART_DECLARE_DATA_START_AND_END(part,data_ptr)	\
		const char *data_start =								\
				data_ptr +										\
				part->headroom_length +							\
				part->header_length								\
		;														\
		const char *data_end =									\
				data_start +									\
				part->data_length

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
	enum rrr_http_application_type parsed_protocol_version;

//	const void *data_ptr;

	size_t headroom_length;
	size_t header_length;
	size_t data_length;
	int data_length_unknown;
};
int __rrr_http_part_content_type_equals (
		struct rrr_http_part *part,
		const char *content_type_test
);
const struct rrr_http_field *__rrr_http_part_header_field_subvalue_get (
		const struct rrr_http_part *part,
		const char *field_name,
		const char *subvalue_name
);
void rrr_http_part_destroy (struct rrr_http_part *part);
void rrr_http_part_destroy_void (void *part);
void rrr_http_part_destroy_void_double_ptr (void *arg);
int rrr_http_part_new (struct rrr_http_part **result);
int rrr_http_part_prepare (struct rrr_http_part **part);
int rrr_http_part_raw_response_set_allocated (
		struct rrr_http_part *part,
		char **raw_data_source,
		size_t raw_data_size
);
const struct rrr_http_header_field *rrr_http_part_header_field_get (
		const struct rrr_http_part *part,
		const char *name
);
const struct rrr_http_header_field *rrr_http_part_header_field_get_raw (
		const struct rrr_http_part *part,
		const char *name
);
const struct rrr_http_header_field *rrr_http_part_header_field_get_with_value_case (
		const struct rrr_http_part *part,
		const char *name_lowercase,
		const char *value_anycase
);
struct rrr_http_chunk *rrr_http_part_chunk_new (
		rrr_length chunk_start,
		rrr_length chunk_length
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
int rrr_http_part_post_and_query_fields_extract (
		struct rrr_http_part *target,
		const char *data_ptr
);
int rrr_http_part_chunks_merge (
		char **result_data,
		struct rrr_http_part *part,
		const char *data_ptr
);
int rrr_http_part_post_x_www_form_body_make (
		struct rrr_http_part *part,
		int no_urlencoding,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
);
void rrr_http_part_header_dump (
		struct rrr_http_part *part
);

#endif /* RRR_HTTP_PART_H */
