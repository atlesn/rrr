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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include "../log.h"
#include "../allocator.h"
#include "http_part.h"
#include "http_part_multipart.h"
#include "http_fields.h"
#include "http_util.h"
#include "http_header_fields.h"
#include "../array.h"
#include "../helpers/string_builder.h"
#include "../helpers/nullsafe_str.h"
#include "../util/macro_utils.h"
#include "../util/base64.h"
#include "../util/gnu.h"
#include "../util/posix.h"

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
	rrr_array_collection_clear(&part->arrays);
	RRR_LL_DESTROY(&part->chunks, struct rrr_http_chunk, rrr_free(node));
	rrr_http_field_collection_clear(&part->fields);
	rrr_nullsafe_str_destroy_if_not_null(&part->request_uri_nullsafe);
	rrr_nullsafe_str_destroy_if_not_null(&part->request_method_str_nullsafe);
	rrr_free (part);
}

void rrr_http_part_destroy_void (void *part) {
	rrr_http_part_destroy(part);
}

int rrr_http_part_new (struct rrr_http_part **result) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_part *part = rrr_allocate (sizeof(*part));
	if (part == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
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
		RRR_MSG_0("Could not create HTTP part in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

const struct rrr_http_header_field *rrr_http_part_header_field_get (
		const struct rrr_http_part *part,
		const char *name
) {
	return rrr_http_header_field_collection_get(&part->headers, name);
}

const struct rrr_http_header_field *rrr_http_part_header_field_get_raw (
		const struct rrr_http_part *part,
		const char *name
) {
	return rrr_http_header_field_collection_get_raw(&part->headers, name);
}

const struct rrr_http_header_field *rrr_http_part_header_field_get_with_value_case (
		const struct rrr_http_part *part,
		const char *name_lowercase,
		const char *value_anycase
) {
	return rrr_http_header_field_collection_get_with_value_case(&part->headers, name_lowercase, value_anycase);
}

struct rrr_http_header_field *__rrr_http_part_header_field_get (
		struct rrr_http_part *part,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if (rrr_nullsafe_str_cmpto(node->name, name) == 0)
			return node;
	RRR_LL_ITERATE_END();

	return NULL;
}

struct rrr_http_chunk *rrr_http_part_chunk_new (
		rrr_biglength chunk_start,
		rrr_biglength chunk_length
) {
	struct rrr_http_chunk *new_chunk = rrr_allocate(sizeof(*new_chunk));
	if (new_chunk == NULL) {
		RRR_MSG_0("Could not allocate memory for chunk in %s\n", __func__);
		return NULL;
	}

	memset(new_chunk, '\0', sizeof(*new_chunk));

	new_chunk->start = chunk_start;
	new_chunk->length = chunk_length;

	return new_chunk;
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

int rrr_http_part_header_field_push_nullsafe (
		struct rrr_http_part *part,
		const char *name,
		const struct rrr_nullsafe_str *value
) {
	int ret = 0;

	struct rrr_http_header_field *field = NULL;

	if ((ret = rrr_http_header_field_new_with_value_nullsafe(&field, name, value)) != 0) {
		goto out;
	}

	RRR_LL_APPEND(&part->headers, field);

	out:
	return ret;
}

int rrr_http_part_header_field_push_if_not_exists (
		struct rrr_http_part *part,
		const char *name,
		const char *value
) {
	if (rrr_http_part_header_field_get_raw (part, name) != NULL) {
		return 0;
	}

	return rrr_http_part_header_field_push(part, name, value);
}

int rrr_http_part_header_field_push_and_replace (
		struct rrr_http_part *part,
		const char *name,
		const char *value
) {
	rrr_http_part_header_field_remove (part, name);
	return rrr_http_part_header_field_push(part, name, value);
}

int rrr_http_part_header_field_push_subvalue (
		struct rrr_http_part *part,
		const char *field,
		const char *name,
		const char *value
) {
	int ret = 0;

	struct rrr_http_header_field *content_type = __rrr_http_part_header_field_get (part, "content-type");
	if (content_type == NULL) {
		RRR_BUG("BUG: Field %s was not present in %s\n", field, __func__);
	}

	if ((ret = rrr_http_field_collection_add(
			&content_type->fields,
			name,
			rrr_length_from_size_t_bug_const(strlen(name)),
			value,
			rrr_length_from_size_t_bug_const(strlen(value)),
			NULL,
			0,
			NULL
	)) != 0) {
		RRR_MSG_0("Failed to add value to field collection in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

int rrr_http_part_header_field_parse_value_raw (
		struct rrr_http_part *part,
		const char *name,
		rrr_length name_length,
		const char *value,
		rrr_length value_length
) {
	int ret = 0;

	rrr_length parsed_bytes;
	if ((ret = rrr_http_header_field_parse_value_raw(&part->headers, &parsed_bytes, name, name_length, value, value_length)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_part_fields_iterate_const (
		const struct rrr_http_part *part,
		int (*callback)(const RRR_HTTP_COMMON_FIELD_CALLBACK_ARGS),
		void *callback_arg
) {
	return rrr_http_field_collection_iterate_const(&part->fields, callback, callback_arg);
}

int rrr_http_part_header_fields_iterate (
		struct rrr_http_part *part,
		int (*callback)(RRR_HTTP_COMMON_HEADER_FIELD_CALLBACK_ARGS),
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
		ret = callback (
				0,
				1,
				data_start,
				rrr_biglength_from_ptr_sub_bug_const(data_end, data_start),
				part->data_length,
				callback_arg
		);
		goto out;
	}

	int i = 0;
	int chunks_total = RRR_LL_COUNT(&part->chunks);

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		const char *data_start = data_ptr + node->start;

		if (data_start + node->length > data_end) {
			RRR_BUG("Chunk end overrun in %s\n", __func__);
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
	rrr_length buf_pos = 0;
	struct rrr_http_field *field_tmp = NULL;
	struct rrr_http_field *value_target = NULL;

	// Skip initial spaces
	while (start < end) {
		if (*start != ' ' && *start != '\t' && *start != '\r' && *start != '\n') {
			break;
		}
		start++;
	}

	rrr_length to_allocate = 0;
	// +1 to accomodate zero termination
	if (rrr_length_from_ptr_sub_err(&to_allocate, end + 1, start) != 0) {
		RRR_MSG_0("Data too long while parsing HTTP query string\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if ((buf = rrr_allocate(to_allocate)) == NULL) {
		RRR_MSG_0("Could not allocate memory for buffer in %s\n", __func__);
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	while (start < end) {
		int push_no_value = 0;
		int end_is_near = 0;

		unsigned char c = (unsigned char) *start;

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
			if (rrr_http_util_strtoull_raw (&result, &result_len, start + 1, start + 3, 16) != 0) {
				RRR_MSG_0("Invalid %%-sequence in HTTP query string\n");
				rrr_http_util_print_where_message(start, end);
				ret = RRR_HTTP_PARSE_SOFT_ERR;
				goto out;
			}

			if (result > 0xff) {
				RRR_BUG("Result after converting %%-sequence too big in %s\n", __func__);
			}

			c = (unsigned char) result;
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

		buf[rrr_length_inc_bug_old_value(&buf_pos)] = (char) c;
		buf[buf_pos] = '\0';

		if (end_is_near) {
			if (value_target == NULL) {
				goto push_new_field_no_value;
			}
			goto store_value;
		}

		goto increment;

		store_value:
			if (rrr_http_field_value_set(value_target, buf, buf_pos) != 0) {
				RRR_MSG_0("Could not set value in %s\n", __func__);
				ret = RRR_HTTP_PARSE_HARD_ERR;
				goto out;
			}
			value_target = NULL;
			goto reset_buf;

		push_new_field_no_value:
			push_no_value = 1;

		push_new_field:
			if (buf_pos > 0) {
				if (rrr_http_field_new_no_value_raw(&field_tmp, buf, buf_pos) != 0) {
					RRR_MSG_0("Could not allocate new field in %s\n", __func__);
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

static int __rrr_http_part_query_fields_from_uri_extract_callback (
		const void *start,
		rrr_nullsafe_len len_remaining,
		void *arg
) {
	const char *query_start = start;
	const char *query_end = start + len_remaining;
	struct rrr_http_part *target = arg;

	int ret = 0;

	// Skip ?
	query_start++;

	if (query_start == query_end) {
		goto out;
	}

	if ((ret = __rrr_http_part_query_string_parse (&target->fields, query_start, query_end)) != 0) {
		RRR_MSG_0("Error while parsing query string in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_part_fields_from_uri_extract (
		struct rrr_http_part *target
) {
	return rrr_nullsafe_str_chr(target->request_uri_nullsafe, '?', __rrr_http_part_query_fields_from_uri_extract_callback, target);
}

struct rrr_http_part_fields_from_post_data_extract_json_callback_data {
	struct rrr_http_part *target;
};

#ifdef RRR_WITH_JSONC
static int __rrr_http_part_fields_from_post_extract_json_callback (
		const struct rrr_array *array,
		void *arg
) {
	struct rrr_http_part_fields_from_post_data_extract_json_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_array *new_array = NULL;

	if ((ret = rrr_array_clone (&new_array, array)) != 0) {
		RRR_MSG_0("Failed to clone array in %s\n", __func__);
		goto out;
	}

	RRR_LL_APPEND(&callback_data->target->arrays, new_array);

	out:
	return ret;
}
#endif

static int __rrr_http_part_fields_from_post_extract (
		struct rrr_http_part *target,
		const char *data_ptr
) {
	int ret = 0;

	struct rrr_http_field *field_tmp = NULL;

	if (__rrr_http_part_content_type_equals(target, "application/x-www-form-urlencoded")) {
		RRR_HTTP_PART_DECLARE_DATA_START_AND_END(target, data_ptr);
		if ((ret = __rrr_http_part_query_string_parse (&target->fields, data_start, data_end)) != 0) {
			RRR_MSG_0("Error while parsing query string in %s\n", __func__);
			goto out;
		}
	}
	else if (__rrr_http_part_content_type_equals(target, "multipart/form-data")) {
		RRR_LL_ITERATE_BEGIN(target, struct rrr_http_part);
			RRR_HTTP_PART_DECLARE_DATA_START_AND_END(node, data_ptr);

			if (data_length > RRR_LENGTH_MAX) {
				RRR_MSG_0("Multipart form value too big, cannot be stored (%" PRIrrrbl ">%llu)\n",
					data_length, (unsigned long long) RRR_LENGTH_MAX);
				ret = RRR_HTTP_PARSE_SOFT_ERR;
				goto out;
			}

			const struct rrr_http_field *field_name = __rrr_http_part_header_field_subvalue_get(node, "content-disposition", "name");
			if (field_name == NULL || !rrr_nullsafe_str_isset(field_name->value)) {
				RRR_DBG_1("Warning: Unknown field or invalid content-disposition of multipart part\n");
				RRR_LL_ITERATE_NEXT();
			}

			if ((ret = rrr_http_field_new_no_value(&field_tmp, field_name->value)) != 0) {
				RRR_MSG_0("Could not create new field in %s\n", __func__);
				goto out;
			}

			if (data_length > 0) {
				if ((ret = rrr_http_field_value_set (
						field_tmp,
						data_start,
						rrr_length_from_biglength_bug_const(data_length)
				)) != 0) {
					RRR_MSG_0("Could not set value of field in %s\n", __func__);
					goto out;
				}
			}

			const struct rrr_http_header_field *field_content_type = rrr_http_part_header_field_get(node, "content-type");
			if (field_content_type != NULL && rrr_nullsafe_str_isset(field_content_type->value)) {
				if ((ret = rrr_http_field_content_type_set (
						field_tmp,
						field_content_type->value
				)) != 0) {
					RRR_MSG_0("Could not set content type of field in %s\n", __func__);
					goto out;
				}
			}

			RRR_LL_APPEND(&target->fields, field_tmp);
			field_tmp = NULL;
		RRR_LL_ITERATE_END();
	}
#ifdef RRR_WITH_JSONC
	else if (__rrr_http_part_content_type_equals(target, "application/json")) {
		RRR_HTTP_PART_DECLARE_DATA_START_AND_END(target, data_ptr);

		rrr_length json_length;
		if (rrr_length_from_biglength_err(&json_length, data_length) != 0) {
			RRR_MSG_0("JSON data in HTTP body too big, cannot be stored (%" PRIrrrbl ">%llu)\n",
					data_length, (unsigned long long) RRR_LENGTH_MAX);
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}

		struct rrr_http_part_fields_from_post_data_extract_json_callback_data callback_data = {
			target
		};

		if ((ret = rrr_http_util_json_to_arrays (
				data_start,
				json_length,
				__rrr_http_part_fields_from_post_extract_json_callback,
				&callback_data
		)) != 0) {
			RRR_MSG_0("Failed to parse JSON in HTTP request body, return was %i\n", ret);
			// Mask hard errors (allocation failures)
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}
	}
#endif

	out:
	if (field_tmp != NULL) {
		rrr_http_field_destroy(field_tmp);
	}
	return ret;
}

int rrr_http_part_multipart_and_fields_process (
		struct rrr_http_part *part,
		const char *data_or_null,
		short no_body_parse
) {
	int ret = 0;

	if ((ret = __rrr_http_part_fields_from_uri_extract(part)) != 0) {
		goto out;
	}

	if (!no_body_parse && data_or_null != NULL) {
		if ((ret = rrr_http_part_multipart_process(part, data_or_null)) != 0) {
			goto out;
		}

		if ((ret = __rrr_http_part_fields_from_post_extract(part, data_or_null)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_http_part_chunks_merge (
		char **result_data,
		struct rrr_http_part *part,
		const char *data_ptr
) {
	int ret = RRR_HTTP_OK;

	char *data_new = NULL;

	if (part->is_chunked == 0) {
		goto out;
	}

	*result_data = NULL;

	const rrr_biglength top_length = RRR_HTTP_PART_TOP_LENGTH(part);
	rrr_biglength new_buf_size = top_length;

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		new_buf_size += node->length;
		if (new_buf_size < node->length) {
			RRR_MSG_0("Overflow while merging HTTP chunks\n");
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	if ((data_new = rrr_allocate(new_buf_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	rrr_biglength wpos = 0;

	RRR_SIZE_CHECK(top_length,"Merge HTTP chunks",ret = 1; goto out);

	rrr_memcpy(data_new, data_ptr, top_length);
	wpos += top_length;

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		RRR_SIZE_CHECK(node->length,"Merge HTTP chunk node",ret = 1; goto out);
		rrr_memcpy(data_new + wpos, data_ptr + node->start, node->length);
		wpos += node->length;
		if (wpos < node->length) {
			// Should discover this during allocation loop
			RRR_BUG("Overflow while merging HTTP chunk\n");
		}
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&part->chunks, 0; rrr_free(node));

	part->is_chunked = 0;
	part->data_length = wpos;

	*result_data = data_new;
	data_new = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(data_new);
	return ret;
}

int rrr_http_part_post_x_www_form_body_make (
		struct rrr_http_part *part,
		int no_urlencoding,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
) {
	int ret = 0;

	struct rrr_nullsafe_str *body_buf_nullsafe = NULL;

	pthread_cleanup_push(rrr_nullsafe_str_destroy_if_not_null_void, &body_buf_nullsafe);

	if (no_urlencoding == 0) {
		if ((ret = rrr_http_field_collection_to_urlencoded_form_data(&body_buf_nullsafe, &part->fields)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = rrr_http_field_collection_to_raw_form_data(&body_buf_nullsafe, &part->fields)) != 0) {
			goto out;
		}
	}

	if ((ret = rrr_http_part_header_field_push(part, "content-type", "application/x-www-form-urlencoded")) != 0) {
		goto out;
	}

	if ((ret = chunk_callback(body_buf_nullsafe, chunk_callback_arg)) != 0) {
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

#ifdef RRR_WITH_JSONC
int rrr_http_part_json_make (
		struct rrr_http_part *part,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
) {
	int ret = 0;

	struct rrr_nullsafe_str *body_buf_nullsafe = NULL;

	pthread_cleanup_push(rrr_nullsafe_str_destroy_if_not_null_void, &body_buf_nullsafe);

	if ((ret = rrr_http_field_collection_to_json(&body_buf_nullsafe, &part->fields)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(part, "content-type", "application/json")) != 0) {
		goto out;
	}

	if ((ret = chunk_callback(body_buf_nullsafe, chunk_callback_arg)) != 0) {
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}
#endif

static void __rrr_http_part_header_field_dump (
		struct rrr_http_header_field *field
) {
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(parent_name,field->name);

	RRR_DBG("%s: unsigned %llu - signed %lli - value length '%ld'\n",
			parent_name,
			field->value_unsigned,
			field->value_signed,
			(unsigned long) rrr_nullsafe_str_len(field->value)
	);

	if (rrr_nullsafe_str_len(field->value) > 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,field->value);
		RRR_DBG("\t = %s\n", value);
	}

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,node->name);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,node->value);
		RRR_DBG("\t |_ %s: %ld bytes\n", name, (unsigned long) rrr_nullsafe_str_len(node->value));
		if (rrr_nullsafe_str_len(node->value) > 0) {
			RRR_DBG("\t      = %s\n", value);
		}
	RRR_LL_ITERATE_END();
}

void rrr_http_part_header_dump (
		struct rrr_http_part *part
) {
	RRR_DBG("== DUMP HTTP PART HEADER ====================================\n");
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		__rrr_http_part_header_field_dump(node);
	
	RRR_LL_ITERATE_END();
	RRR_DBG("== DUMP HTTP PART HEADER END ================================\n");
}
