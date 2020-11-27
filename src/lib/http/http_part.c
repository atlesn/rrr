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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include "../log.h"
#include "http_part.h"
#include "http_fields.h"
#include "http_util.h"
#include "http_header_fields.h"
#include "../helpers/nullsafe_str.h"
#include "../util/macro_utils.h"
#include "../util/base64.h"
#include "../util/gnu.h"

int __rrr_http_part_content_type_equals (
		struct rrr_http_part *part,
		const char *content_type_test
) {
	const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(part, "content-type");
	if (content_type == NULL) {
		return 0;
	}

	if (rrr_nullsafe_str_cmpto_case(content_type->value, content_type_test) == 0) {
		return 1;
	}

	return 0;
}

const struct rrr_http_field *__rrr_http_part_header_field_subvalue_get (
		const struct rrr_http_part *part,
		const char *field_name,
		const char *subvalue_name
) {
	const struct rrr_http_header_field *field = rrr_http_part_header_field_get(part, field_name);
	if (field == NULL) {
		return NULL;
	}

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		if (	rrr_nullsafe_str_isset(node->name) &&
				rrr_nullsafe_str_isset(node->value) &&
				rrr_nullsafe_str_cmpto_case(node->name, subvalue_name) == 0
		) {
			return node;
		}
	RRR_LL_ITERATE_END();

	return NULL;
}

void rrr_http_part_destroy (struct rrr_http_part *part) {
	RRR_LL_DESTROY(part, struct rrr_http_part, rrr_http_part_destroy(node));
	rrr_http_header_field_collection_clear(&part->headers);
	RRR_LL_DESTROY(&part->chunks, struct rrr_http_chunk, free(node));
	rrr_http_field_collection_clear(&part->fields);
	RRR_FREE_IF_NOT_NULL(part->response_str);
	rrr_nullsafe_str_destroy_if_not_null(&part->response_raw_data_nullsafe);
	rrr_nullsafe_str_destroy_if_not_null(&part->request_uri_nullsafe);
	rrr_nullsafe_str_destroy_if_not_null(&part->request_method_str_nullsafe);
	free (part);
}

void rrr_http_part_destroy_void (void *part) {
	rrr_http_part_destroy(part);
}

int rrr_http_part_new (struct rrr_http_part **result) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_part *part = malloc (sizeof(*part));
	if (part == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_part_new\n");
		ret = 1;
		goto out;
	}

	memset (part, '\0', sizeof(*part));

	*result = part;

	out:
	return ret;
}

int rrr_http_part_prepare (struct rrr_http_part **part) {
	int ret = 0;

	if (*part != NULL) {
		rrr_http_part_destroy(*part);
		*part = NULL;
	}
	if ((ret = rrr_http_part_new(part)) != 0) {
		RRR_MSG_0("Could not create HTTP part in rrr_http_part_prepare\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_http_part_raw_response_set_allocated (
		struct rrr_http_part *part,
		char **raw_data_source,
		size_t raw_data_size
) {
	int ret = 0;

	if (part->response_raw_data_nullsafe != NULL) {
		RRR_BUG("BUG: rrr_http_part_set_allocated_raw_response called while raw data was already set\n");
	}
	if ((ret = rrr_nullsafe_str_new_or_replace(&part->response_raw_data_nullsafe, NULL, 0)) != 0) {
		goto out;
	}
	rrr_nullsafe_str_set_allocated(part->response_raw_data_nullsafe, (void **) raw_data_source, raw_data_size);

	out:
	return ret;
}
/*
void rrr_http_part_raw_request_set_ptr (
		struct rrr_http_part *part,
		const char *raw_data,
		size_t raw_data_size
) {
	part->request_raw_data = raw_data;
	part->request_raw_data_size = raw_data_size;
}
*/
const struct rrr_http_header_field *rrr_http_part_header_field_get (
		const struct rrr_http_part *part,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if (rrr_nullsafe_str_cmpto_case(node->name, name) == 0) {
			if (node->definition == NULL || node->definition->parse == NULL) {
				RRR_BUG("Attempted to retrieve field %s which was not parsed in rrr_http_part_header_field_get, definition must be added\n",
						name);
			}
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

const struct rrr_http_header_field *rrr_http_part_header_field_get_raw (
		const struct rrr_http_part *part,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if (rrr_nullsafe_str_cmpto_case(node->name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

const struct rrr_http_header_field *rrr_http_part_header_field_get_with_value_case (
		const struct rrr_http_part *part,
		const char *name_lowercase,
		const char *value_anycase
) {
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if (rrr_nullsafe_str_cmpto(node->name, name_lowercase) == 0) {
			if (node->definition == NULL || node->definition->parse == NULL) {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,node->name);
				RRR_BUG("BUG: Attempted to retrieve field %s which was not parsed in rrr_http_part_header_field_get_with_value_case, definition must be added\n",
						name);
			}
			if (rrr_nullsafe_str_cmpto_case(node->value, value_anycase) == 0) {
				return node;
			}
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

struct rrr_http_chunk *rrr_http_part_chunk_new (
		rrr_length chunk_start,
		rrr_length chunk_length
) {
	struct rrr_http_chunk *new_chunk = malloc(sizeof(*new_chunk));
	if (new_chunk == NULL) {
		RRR_MSG_0("Could not allocate memory for chunk in rrr_http_part_chunk_new\n");
		return NULL;
	}

	memset(new_chunk, '\0', sizeof(*new_chunk));

	new_chunk->start = chunk_start;
	new_chunk->length = chunk_length;

	return new_chunk;
}

int rrr_http_part_header_field_push (
		struct rrr_http_part *part,
		const char *name,
		const char *value
) {
	int ret = 0;

	struct rrr_http_header_field *field = NULL;

	if ((ret = rrr_http_header_field_new_with_value(&field, name, value)) != 0) {
		goto out;
	}

	RRR_LL_APPEND(&part->headers, field);

	out:
	return ret;
}

int rrr_http_part_fields_iterate_const (
		const struct rrr_http_part *part,
		int (*callback)(const struct rrr_http_field *field, void *callback_arg),
		void *callback_arg
) {
	return rrr_http_field_collection_iterate_const(&part->fields, callback, callback_arg);
}

int rrr_http_part_header_fields_iterate (
		struct rrr_http_part *part,
		int (*callback)(struct rrr_http_header_field *field, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if ((ret = callback(node, callback_arg)) != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

void rrr_http_part_header_field_remove (
		struct rrr_http_part *part,
		const char *field
) {
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if (rrr_nullsafe_str_cmpto_case(node->name, field) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&part->headers, 0; rrr_http_header_field_destroy(node));
}

int rrr_http_part_chunks_iterate (
		struct rrr_http_part *part,
		const char *data_ptr,
		int (*callback)(RRR_HTTP_PART_ITERATE_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	RRR_HTTP_PART_DECLARE_DATA_START_AND_END(part, data_ptr);

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_header_dump(part);
	}

	if (RRR_LL_COUNT(&part->chunks) == 0) {
		ret = callback(0, 1, data_start, data_end - data_start, part->data_length, callback_arg);
		goto out;
	}

	int i = 0;
	int chunks_total = RRR_LL_COUNT(&part->chunks);

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		const char *data_start = data_ptr + node->start;

		if (data_start + node->length > data_end) {
			RRR_BUG("Chunk end overrun in rrr_http_part_chunks_iterate\n");
		}

		// NOTE : Length might be 0
		if ((ret = callback(i, chunks_total, data_start, node->length, part->data_length, callback_arg)) != 0) {
			goto out;
		}

		i++;
	RRR_LL_ITERATE_END();

	out:
	return ret;
}


static int __rrr_http_part_query_string_parse (
		struct rrr_http_field_collection *target,
		const char *start,
		const char *end
) {
	int ret = 0;

	char *buf = NULL;
	size_t buf_pos = 0;
	struct rrr_http_field *field_tmp = NULL;
	struct rrr_http_field *value_target = NULL;

	// Skip initial spaces
	while (start < end) {
		if (*start != ' ' && *start != '\t' && *start != '\r' && *start != '\n') {
			break;
		}
		start++;
	}

	if ((buf = malloc((end - start) + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory for buffer in __rrr_http_part_query_string_parse\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	while (start < end) {
		int push_no_value = 0;
		int end_is_near = 0;

		unsigned char c = *start;

		if (start + 1 >= end || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			end_is_near = 1;
		}

		if (c == '+') {
			c = ' ';
		}
		else if (c == '%') {
			if (start + 3 > end) {
				RRR_MSG_0("Not enough characters after %% in query string\n");
				ret = RRR_HTTP_PARSE_SOFT_ERR;
				goto out;
			}

			unsigned long long int result = 0;

			rrr_length result_len = 0;
			if (rrr_http_util_strtoull (&result, &result_len, start + 1, start + 3, 16) != 0) {
				RRR_MSG_0("Invalid %%-sequence in HTTP query string\n");
				rrr_http_util_print_where_message(start, end);
				ret = RRR_HTTP_PARSE_SOFT_ERR;
				goto out;
			}

			if (result > 0xff) {
				RRR_BUG("Result after converting %%-sequence too big in __rrr_http_part_query_string_parse\n");
			}

			c = result;
			start += 2; // One more ++ at the end of the loop

			if (start + 1 >= end || *(start+1) == ' ' || *(start+1) == '\t' || *(start+1) == '\r' || *(start+1) == '\n') {
				end_is_near = 1;
			}
		}
		else if (c == '=') {
			if (c == '=' && value_target != NULL) {
				RRR_MSG_0("Unexpected = in query string\n");
				rrr_http_util_print_where_message(start, end);
				ret = RRR_HTTP_PARSE_SOFT_ERR;
				goto out;
			}

			goto push_new_field;
		}
		else if (c == '&') {
			if (value_target == NULL) {
				goto push_new_field_no_value;
			}
			else {
				goto store_value;
			}
		}

		if (end_is_near) {
			buf[buf_pos++] = c;
			buf[buf_pos] = '\0';

			if (value_target == NULL) {
				goto push_new_field_no_value;
			}
			else {
				goto store_value;
			}
		}

		buf[buf_pos++] = c;
		buf[buf_pos] = '\0';

		goto increment;

		store_value:
			if (rrr_http_field_set_value(value_target, buf, buf_pos) != 0) {
				RRR_MSG_0("Could not set value in __rrr_http_part_query_string_parse\n");
				ret = RRR_HTTP_PARSE_HARD_ERR;
				goto out;
			}
			value_target = NULL;
			goto reset_buf;

		push_new_field_no_value:
			push_no_value = 1;

		push_new_field:
			if (buf_pos > 0) {
				if (rrr_http_field_new_no_value(&field_tmp, buf, buf_pos) != 0) {
					RRR_MSG_0("Could not allocate new field in __rrr_http_part_query_string_parse\n");
					ret = RRR_HTTP_PARSE_HARD_ERR;
					goto out;
				}
				RRR_LL_APPEND(target, field_tmp);
				if (!push_no_value) {
					value_target = field_tmp;
				}
				field_tmp = NULL;
			}
			goto reset_buf;

		reset_buf:
			buf[0] = '\0';
			buf_pos = 0;

		increment:
			start++;

		if (end_is_near) {
			break;
		}
	}

	out:
	if (field_tmp != NULL) {
		rrr_http_field_destroy(field_tmp);
	}
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

static int __rrr_http_part_query_fields_from_uri_extract (
		struct rrr_http_part *target
) {
	int ret = 0;

	const char *query_end = target->request_uri_nullsafe->str + target->request_uri_nullsafe->len;
	const char *query_start = rrr_nullsafe_str_chr(target->request_uri_nullsafe, '?');

	if (query_start == NULL) {
		ret = 0;
		goto out;
	}

	// Skip ?
	query_start++;

	if (query_start == query_end) {
		goto out;
	}

	if ((ret = __rrr_http_part_query_string_parse (&target->fields, query_start, query_end)) != 0) {
		RRR_MSG_0("Error while parsing query string in __rrr_http_part_query_fields_from_uri_extract\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_http_part_post_and_query_fields_extract (
		struct rrr_http_part *target,
		const char *data_ptr
) {
	int ret = 0;

	struct rrr_http_field *field_tmp = NULL;

	if (__rrr_http_part_content_type_equals(target, "application/x-www-form-urlencoded")) {
		RRR_HTTP_PART_DECLARE_DATA_START_AND_END(target, data_ptr);

		if ((ret = __rrr_http_part_query_string_parse (&target->fields, data_start, data_end)) != 0) {
			RRR_MSG_0("Error while parsing query string in rrr_http_part_post_and_query_fields_extract\n");
			goto out;
		}
	}
	else if (__rrr_http_part_content_type_equals(target, "multipart/form-data")) {
		RRR_LL_ITERATE_BEGIN(target, struct rrr_http_part);
			RRR_HTTP_PART_DECLARE_DATA_START_AND_END(node, data_ptr);

			const struct rrr_http_field *field_name = __rrr_http_part_header_field_subvalue_get(node, "content-disposition", "name");
			if (field_name == NULL || !rrr_nullsafe_str_isset(field_name->value)) {
				RRR_DBG_1("Warning: Unknown field or invalid content-disposition of multipart part\n");
				RRR_LL_ITERATE_NEXT();
			}

			if ((ret = rrr_http_field_new_no_value(&field_tmp, field_name->value->str, field_name->value->len)) != 0) {
				RRR_MSG_0("Could not create new field in rrr_http_part_post_and_query_fields_extract\n");
				goto out;
			}

			if (data_end - data_start > 0) {
				if ((ret = rrr_http_field_set_value(field_tmp, data_start, data_end - data_start)) != 0) {
					RRR_MSG_0("Could not set value of field in rrr_http_part_post_and_query_fields_extract\n");
					goto out;
				}
			}

			const struct rrr_http_header_field *field_content_type = rrr_http_part_header_field_get(node, "content-type");
			if (field_content_type != NULL && rrr_nullsafe_str_isset(field_content_type->value)) {
				if ((ret = rrr_http_field_set_content_type (
						field_tmp,
						field_content_type->value->str,
						field_content_type->value->len
				)) != 0) {
					RRR_MSG_0("Could not set content type of field in rrr_http_part_post_and_query_fields_extract\n");
					goto out;
				}
			}

			RRR_LL_APPEND(&target->fields, field_tmp);
			field_tmp = NULL;
		RRR_LL_ITERATE_END();
	}

	if ((ret =  __rrr_http_part_query_fields_from_uri_extract(target)) != 0) {
		goto out;
	}

	out:
	if (field_tmp != NULL) {
		rrr_http_field_destroy(field_tmp);
	}
	return ret;
}

int rrr_http_part_chunks_merge (
		char **result_data,
		struct rrr_http_part *part,
		const char *data_ptr
) {
	int ret = RRR_HTTP_OK;

	if (part->is_chunked == 0) {
		goto out;
	}

	*result_data = NULL;

	char *data_new = NULL;
	const size_t top_length = RRR_HTTP_PART_TOP_LENGTH(part);
	size_t new_buf_size = 0;

	new_buf_size += top_length;

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		new_buf_size += node->length;
	RRR_LL_ITERATE_END();

	if ((data_new = malloc(new_buf_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_part_chunks_merge\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	size_t wpos = 0;

	memcpy(data_new, data_ptr, top_length);
	wpos += top_length;

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		memcpy(data_new + wpos, data_ptr + node->start, node->length);
		wpos += node->length;
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&part->chunks, 0; free(node));

	part->is_chunked = 0;
	part->data_length = wpos;

	*result_data = data_new;

	// goto out; out_free:
	// RRR_FREE_IF_NOT_NULL(data_new); -- Enable if needed
	out:
	return ret;
}

int rrr_http_part_post_x_www_form_body_make (
		struct rrr_http_part *part,
		int no_urlencoding,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
) {
	int ret = 0;
	char *body_buf = NULL;
	char *header_buf = NULL;

	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &body_buf);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &header_buf);

	rrr_length body_size = 0;
	if (no_urlencoding == 0) {
		body_buf = rrr_http_field_collection_to_urlencoded_form_data(&body_size, &part->fields);
	}
	else {
		body_buf = rrr_http_field_collection_to_raw_form_data(&body_size, &part->fields);
	}

	if (body_buf == NULL) {
		RRR_MSG_0("Could not create body in rrr_http_part_post_x_www_form_body_make \n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf (
			&header_buf,
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: %" PRIrrrl "\r\n\r\n",
			body_size
	)) < 0) {
		RRR_MSG_0("Could not create content type string in rrr_http_part_post_x_www_form_body_make  return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = chunk_callback(header_buf, strlen(header_buf), chunk_callback_arg)) != 0) {
		goto out;
	}

	if ((ret = chunk_callback(body_buf, body_size, chunk_callback_arg)) != 0) {
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

static void __rrr_http_part_header_field_dump (
		struct rrr_http_header_field *field
) {
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(parent_name,field->name);

	RRR_MSG_3("%s: unsigned %llu - signed %lli - value length '%ld'\n",
			parent_name,
			field->value_unsigned,
			field->value_signed,
			(unsigned long) rrr_nullsafe_str_len(field->value)
	);

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,node->name);
		RRR_MSG_3("\t%s: %ld bytes\n", name, (unsigned long) rrr_nullsafe_str_len(node->value));
	RRR_LL_ITERATE_END();
}

void rrr_http_part_header_dump (
		struct rrr_http_part *part
) {
	printf ("== DUMP HTTP PART HEADER ====================================\n");
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		__rrr_http_part_header_field_dump(node);
	RRR_LL_ITERATE_END();
	printf ("== DUMP HTTP PART HEADER END ================================\n");
}
