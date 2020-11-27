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
#include <pthread.h>

#include "../log.h"
#include "http_part_parse.h"
#include "http_part_multipart.h"
#include "http_part.h"
#include "http_common.h"
#include "http_util.h"
#include "../random.h"
#include "../util/gnu.h"

static int __rrr_http_part_boundary_locate (
		const char **result,
		const char *start,
		const char *end,
		const struct rrr_nullsafe_str *boundary
) {
	int ret = 1;

//	printf("Looking for boundary '%s' length %li\n", boundary, boundary_length);

	const char *boundary_pos = NULL;

	while (start + 1 + boundary->len < end) {
		if (*start == '-' && *(start + 1) == '-') {
			start += 2;
			if (strncmp(start, boundary->str, boundary->len) == 0) {
				boundary_pos = start;
				ret = 0;
				// Don't add to start, is done below
				break;
			}
		}
		start++;
	}

	*result = boundary_pos;

	return ret;
}

static int __rrr_http_part_multipart_process_part (
		struct rrr_http_part *parent,
		const char *data_ptr,
		size_t *parsed_bytes,
		int *end_found,
		const char *start_orig,
		const char *end,
		const struct rrr_nullsafe_str *boundary
) {
	int ret = RRR_HTTP_PARSE_OK;

	*parsed_bytes = 0;
	*end_found = 0;

	struct rrr_http_part *new_part = NULL;

	const char *start = start_orig;
	const char *crlf = NULL;
	const char *boundary_pos = NULL;

	if (__rrr_http_part_boundary_locate(&boundary_pos, start, end, boundary) != 0) {
		RRR_MSG_0("Could not find boundary while looking for part begin in HTTP multipart request\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// 4 bytes are OK, thats the previous -- and CRLF
	if (boundary_pos - start > 4) {
		RRR_DBG_1("Warning: HTTP multipart request contains some data before boundary, %li bytes\n", boundary_pos - start);
	}

	start = boundary_pos + boundary->len;

//	printf("Process multipart start offset after boundary: %li\n", start_orig - data_ptr);

	if (start + 2 >= end) {
		RRR_MSG_0("Not enough data after boundary while parsing HTTP multipart request\n");
//		printf("start: %s end: %s\n", start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	int is_boundary_end = 0;

	// Check for last boundary, has -- after it
	if (*start == '-' && *(start + 1) == '-') {
		is_boundary_end = 1;
		start += 2;
	}

	crlf = rrr_http_util_find_crlf(start, end);
	if (crlf != start) {
		RRR_DBG_1("Warning: No CRLF found directly after boundary in HTTP multipart request\n");
	}

	start = crlf + 2;

	if (is_boundary_end) {
		*end_found = 1;
		*parsed_bytes = start - start_orig;

		if (end - start > 0) {
			RRR_DBG_1("Warning: %li bytes found after HTTP multipart end\n", end - start);
		}

		goto out;
	}

	// Check for end of part. We don't increment start past this, it is needed again to parse
	// the next part.
	if (__rrr_http_part_boundary_locate(&boundary_pos, start, end, boundary) != 0) {
		RRR_MSG_0("Could not find boundary while looking for part end in HTTP multipart request\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// Skip the two -- at the end
	boundary_pos -= 2;

	const char *presumably_crlf = boundary_pos - 2;
	if (*presumably_crlf == '\r' && *(presumably_crlf + 1) == '\n') {
		boundary_pos -= 2;
	}

	if (rrr_http_part_new(&new_part) != 0) {
		RRR_MSG_0("Could not allocate new part in __rrr_http_part_process_multipart_part\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	size_t target_size = 0;
	size_t parsed_bytes_tmp = 0;

	if ((ret = rrr_http_part_parse (
			new_part,
			&target_size,
			&parsed_bytes_tmp,
			data_ptr,
			(start - data_ptr),
			boundary_pos,
			RRR_HTTP_PARSE_MULTIPART
	)) != 0) {
		// Incomplete return is normal, the parser does not know about boundaries
		ret &= ~(RRR_HTTP_PARSE_INCOMPLETE);
		if (ret != 0) {
			RRR_MSG_0("Failed to parse part from HTTP multipart request return was %i\n", ret);
			goto out;
		}
	}

	if (new_part->headroom_length != 0) {
		RRR_BUG("BUG: Request or response not 0 in __rrr_http_part_process_multipart_part\n");
	}

	if (new_part->header_complete != 1) {
		RRR_DBG("Warning: Invalid header specification in HTTP multipart request part header\n");
	}
/* Commented out after data_length was changed to unsigned
	if (new_part->data_length != -1) {
		RRR_DBG("Warning: Invalid length specification in HTTP multipart request part header\n");
	}
*/

	new_part->headroom_length = start - data_ptr;
	new_part->data_length = (boundary_pos - start) - new_part->header_length;

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_header_dump(new_part);
	}

	if ((ret = rrr_http_part_multipart_process(new_part, data_ptr)) != 0) {
		RRR_MSG_0("Error while processing sub-multipart in HTTP multipart request\n");
		goto out;
	}

	RRR_LL_APPEND(parent, new_part);
	new_part = NULL;

	*parsed_bytes = boundary_pos - start_orig;

	out:
		if (new_part != NULL) {
			rrr_http_part_destroy(new_part);
		}
		return ret;
}

int rrr_http_part_multipart_process (
		struct rrr_http_part *part,
		const char *data_ptr
) {
	int ret = RRR_HTTP_PARSE_OK;

	if (!__rrr_http_part_content_type_equals(part, "multipart/form-data")) {
		goto out;
	}

	if (part->request_method == RRR_HTTP_METHOD_GET) {
		RRR_MSG_0("Received multipart message in GET request which is not a valid combination\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	const struct rrr_http_field *boundary = __rrr_http_part_header_field_subvalue_get(part, "content-type", "boundary");
	if (boundary == NULL || !rrr_nullsafe_str_isset(boundary->value)) {
		RRR_MSG_0("No multipart boundary found in content-type of HTTP header\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	int max_parts = 1000;
	int end_found = 0;

	if (part->is_chunked || RRR_LL_COUNT(&part->chunks) > 0) {
		RRR_BUG("BUG: Attempted to process chunked part as multipart\n");
	}

	RRR_HTTP_PART_DECLARE_DATA_START_AND_END(part, data_ptr);

	while (data_start <= data_end && --max_parts > 0) {
		size_t parsed_bytes_tmp = 0;

		if ((ret = __rrr_http_part_multipart_process_part (
				part,
				data_ptr,
				&parsed_bytes_tmp,
				&end_found,
				data_start,
				data_end,
				boundary->value
		)) != 0) {
			// It's possible that return is INCOMPLETE, SOFT and HARD
			// INCOMPLETE is also invalid since we only process multipart after all
			// data has been read from remote.
			if (ret == RRR_HTTP_PARSE_HARD_ERR) {
				RRR_MSG_0("Hard error while parsing rrr_http_part_process_multipart\n");
			}
			else {
				RRR_MSG_0("HTTP Multipart parsing failed, possible invalid data from client. Return was %i.\n", ret);
			}
			ret = RRR_HTTP_PARSE_SOFT_ERR; // Only return soft error
			goto out;
		}

		data_start += parsed_bytes_tmp;

		if (end_found) {
			break;
		}
	}

	if (--max_parts <= 0 && end_found != 0) {
		RRR_MSG_0("Too many parts or chunks in HTTP multipart body\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_part_multipart_form_data_make_wrap_chunk (
		const void *data,
		ssize_t size,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
) {
	if (size < 0) {
		RRR_BUG("Size was < 0 in __rrr_http_part_multipart_form_data_make_wrap_chunk\n");
	}
	if (size == 0) {
		return RRR_HTTP_OK;
	}

	int ret = 0;

	char buf[128];
	sprintf(buf, "%x\r\n", (unsigned int) size);

	if ((ret = chunk_callback(buf, strlen(buf), chunk_callback_arg)) != 0) {
		goto out;
	}

	if ((ret = chunk_callback(data, size, chunk_callback_arg)) != 0) {
		goto out;
	}

	if ((ret = chunk_callback("\r\n", 2, chunk_callback_arg)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_part_multipart_field_make (
		const char *boundary,
		struct rrr_http_field *node,
		int is_first,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
) {
	int ret = 0;

	char *name_buf = NULL;
	char *name_buf_full = NULL;
	char *content_type_buf = NULL;
	char *body_buf = NULL;

	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &name_buf);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &name_buf_full);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &content_type_buf);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &body_buf);

	if (rrr_nullsafe_str_isset(node->name)) {
		if ((name_buf = rrr_http_util_quote_header_value_nullsafe(node->name, '"', '"')) == NULL) {
			RRR_MSG_0("Could not quote field name_buf in __rrr_http_part_multipart_field_make\n");
			ret = 1;
			goto out;
		}

		if ((ret = rrr_asprintf (&name_buf_full, "; name=%s", name_buf)) <= 0) {
			RRR_MSG_0("Could not create name_buf_full in __rrr_http_part_multipart_field_make return was %i\n", ret);
			ret = 1;
			goto out;
		}
	}

	if (rrr_nullsafe_str_isset(node->content_type)) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,node->content_type);
		if ((ret = rrr_asprintf (&content_type_buf, "Content-Type: %s\r\n", value)) <= 0) {
			RRR_MSG_0("Could not create content_type_buf in __rrr_http_part_multipart_field_make return was %i\n", ret);
			ret = 1;
			goto out;
		}
	}

	RRR_FREE_IF_NOT_NULL(body_buf);
	if ((ret = rrr_asprintf (
			&body_buf,
			"%s--%s\r\n"
			"Content-Disposition: form-data%s\r\n"
			"%s\r\n",
			(is_first ? "" : "\r\n"),
			boundary,
			(name_buf_full != NULL ? name_buf_full : ""),
			(content_type_buf != NULL ? content_type_buf : "")
	)) < 0) {
		RRR_MSG_0("Could not create content type string and body  in __rrr_http_part_multipart_field_make return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_http_part_multipart_form_data_make_wrap_chunk (body_buf, strlen(body_buf), chunk_callback, chunk_callback_arg)) != 0) {
		RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_part_multipart_field_make A\n");
		goto out;
	}

	if (rrr_nullsafe_str_isset(node->value)) {
		if ((ret = __rrr_http_part_multipart_form_data_make_wrap_chunk (node->value->str, node->value->len, chunk_callback, chunk_callback_arg)) != 0) {
			RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_part_multipart_field_make B\n");
			goto out;
		}
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

int rrr_http_part_multipart_form_data_make (
		struct rrr_http_part *part,
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS),
		void *chunk_callback_arg
) {
	int ret = 0;

	char *body_buf = NULL;
	char *boundary_buf = NULL;

	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &body_buf);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &boundary_buf);

	// RFC7578

	if ((ret = rrr_asprintf (&boundary_buf, "RRR%u", (unsigned int) rrr_rand())) < 0) {
		RRR_MSG_0("Could not create boundary_buf string in rrr_http_part_multipart_form_data_make return was %i\n", ret);
		ret = 1;
		goto out;
	}

	{
		RRR_FREE_IF_NOT_NULL(body_buf);
		if ((ret = rrr_asprintf (
				&body_buf,
				"Content-Type: multipart/form-data; boundary=%s\r\n"
				"Transfer-Encoding: chunked\r\n\r\n",
				boundary_buf
		)) < 0) {
			RRR_MSG_0("Could not create content type string in rrr_http_part_multipart_form_data_make return was %i\n", ret);
			ret = 1;
			goto out;
		}

		if ((ret = chunk_callback(body_buf, strlen(body_buf), chunk_callback_arg)) != 0) {
			goto out;
		}
	}

	// All sends below this point must be wrapped inside chunk sender

	int is_first = 1;
	RRR_LL_ITERATE_BEGIN(&part->fields, struct rrr_http_field);
		if ((ret = __rrr_http_part_multipart_field_make(boundary_buf, node, is_first, chunk_callback, chunk_callback_arg)) != 0) {
			goto out;
		}
		is_first = 0;
	RRR_LL_ITERATE_END();

	{
		RRR_FREE_IF_NOT_NULL(body_buf);
		if ((ret = rrr_asprintf (
				&body_buf,
				"\r\n--%s--\r\n",  // <-- ONE CRLF AFTER BODY AND ONE AT THE VERY END
				boundary_buf
		)) < 0) {
			RRR_MSG_0("Could not create last boundary in rrr_http_part_multipart_form_data_make return was %i\n", ret);
			ret = 1;
			goto out;
		}

		if ((ret = __rrr_http_part_multipart_form_data_make_wrap_chunk(body_buf, strlen(body_buf), chunk_callback, chunk_callback_arg)) != 0) {
			goto out;
		}
	}

	if ((ret = chunk_callback("0\r\n\r\n", 5, chunk_callback_arg)) != 0) {
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return ret;
}
