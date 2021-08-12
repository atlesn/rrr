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

#include "../log.h"
#include "../allocator.h"
#include "http_part_parse.h"
#include "http_part_multipart.h"
#include "http_part.h"
#include "http_common.h"
#include "http_util.h"
#include "../random.h"
#include "../util/gnu.h"
#include "../helpers/nullsafe_str.h"

struct rrr_http_part_multipart_process_part_find_end_callback_data {
	rrr_length part_length;
};

static int __rrr_http_part_multipart_process_part_find_end_callback (
		const struct rrr_nullsafe_str *haystack_orig,
		const struct rrr_nullsafe_str *needle_orig,
		const struct rrr_nullsafe_str *pos_at_needle,
		const struct rrr_nullsafe_str *pos_after_needle,
		void *arg
) {
	struct rrr_http_part_multipart_process_part_find_end_callback_data *callback_data = arg;

	(void)(needle_orig);
	(void)(pos_after_needle);

	const rrr_nullsafe_len part_length = rrr_nullsafe_str_len(haystack_orig) - rrr_nullsafe_str_len(pos_at_needle);

	if (part_length > RRR_LENGTH_MAX) {
		RRR_MSG_0("HTTP part too long while processing multipart (%" PRIrrr_nullsafe_len ">%llu)\n",
			part_length, (long long unsigned) RRR_LENGTH_MAX);
		return 1;
	}

	callback_data->part_length = (rrr_length) part_length;

	return RRR_HTTP_PARSE_EOF;
}

struct rrr_http_part_multipart_process_part_callback_data {
	struct rrr_http_part *parent;
	rrr_length max_parts;
	rrr_biglength *parsed_bytes;
	const struct rrr_nullsafe_str *boundary_with_dashes_end;
	const char *data_ptr;
};

static int __rrr_http_part_multipart_process_part_callback (
		const struct rrr_nullsafe_str *haystack_orig,
		const struct rrr_nullsafe_str *needle_orig,
		const struct rrr_nullsafe_str *pos_at_needle,
		const struct rrr_nullsafe_str *pos_after_needle,
		void *arg
) {
	struct rrr_http_part_multipart_process_part_callback_data *callback_data = arg;

	int ret = RRR_HTTP_OK;

	struct rrr_http_part *new_part = NULL;
	int end_boundary_found = 0;

	if ((rrr_biglength) RRR_LL_COUNT(callback_data->parent) >= callback_data->max_parts) {
		RRR_MSG_0("Too many parts in HTTP multipart, max is %i\n", callback_data->max_parts);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (rrr_nullsafe_str_len(pos_after_needle) < 2) {
		RRR_MSG_0("Not enough data after boundary while parsing HTTP multipart request\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// Check for last boundary with --
	if (rrr_nullsafe_str_begins_with(pos_at_needle, callback_data->boundary_with_dashes_end)) {
		goto out;
	}

	struct rrr_http_part_multipart_process_part_find_end_callback_data find_end_callback_data = {
		0
	};

	// Since the needle we use with the boundary has \r\n in it, the last boundary will produce
	// a mismatch here as it has -- after the boundary. If this is the case, look for the end boundary
	// instead.
	if (rrr_nullsafe_str_str (
			pos_after_needle,
			needle_orig,
			__rrr_http_part_multipart_process_part_find_end_callback,
			&find_end_callback_data
	) != RRR_HTTP_PARSE_EOF) {
		if (rrr_nullsafe_str_str (
				pos_after_needle,
				callback_data->boundary_with_dashes_end,
				__rrr_http_part_multipart_process_part_find_end_callback,
				&find_end_callback_data
		) != RRR_HTTP_PARSE_EOF) {
			RRR_MSG_0("Could not find boundary while looking for part end in HTTP multipart request\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}

		*(callback_data->parsed_bytes) =  rrr_nullsafe_str_len(haystack_orig) -
		                                  rrr_nullsafe_str_len(pos_at_needle) +
                                                  find_end_callback_data.part_length;

		end_boundary_found = 1;
	}

	if (rrr_http_part_new(&new_part) != 0) {
		RRR_MSG_0("Could not allocate new part in __rrr_http_part_process_multipart_part\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	{
		size_t target_size = 0;
		size_t parsed_bytes_tmp = 0;

		size_t start_pos = rrr_nullsafe_str_len(haystack_orig) - rrr_nullsafe_str_len(pos_after_needle);

		if ((ret = rrr_http_part_parse (
				new_part,
				&target_size,
				&parsed_bytes_tmp,
				callback_data->data_ptr,
				start_pos,
				callback_data->data_ptr + start_pos + find_end_callback_data.part_length,
				RRR_HTTP_PARSE_MULTIPART
		)) != 0) {
			// Incomplete return is normal, the parser does not know about boundaries
			ret &= ~(RRR_HTTP_PARSE_INCOMPLETE);
			if (ret != 0) {
				RRR_MSG_0("Failed to parse part from HTTP multipart request return was %i\n", ret);
				goto out;
			}
		}
	}

	if (new_part->headroom_length != 0) {
		RRR_BUG("BUG: Request or response not 0 in __rrr_http_part_process_multipart_part\n");
	}

	if (new_part->header_complete != 1) {
		RRR_DBG("Warning: Invalid header specification in HTTP multipart request part header\n");
	}

	new_part->headroom_length = rrr_nullsafe_str_len(haystack_orig) - rrr_nullsafe_str_len(pos_after_needle);
	new_part->data_length = find_end_callback_data.part_length - new_part->header_length - 2; // Subtract one CRLF

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_header_dump(new_part);
	}

	if ((ret = rrr_http_part_multipart_process(new_part, callback_data->data_ptr)) != 0) {
		RRR_MSG_0("Error while processing sub-multipart in HTTP multipart request\n");
		goto out;
	}

	RRR_LL_APPEND(callback_data->parent, new_part);
	new_part = NULL;

	if (end_boundary_found) {
		ret = RRR_HTTP_PARSE_EOF;
	}

	out:
	if (new_part != NULL) {
		rrr_http_part_destroy(new_part);
	}
	return ret;
}

static int __rrr_http_part_multipart_process_parts (
		struct rrr_http_part *parent,
		rrr_length max_parts,
		rrr_biglength *parsed_bytes,
		const char * const start,
		const char * const end,
		const struct rrr_nullsafe_str *boundary
) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

	struct rrr_nullsafe_str *boundary_with_dashes = NULL;
	struct rrr_nullsafe_str *boundary_with_dashes_end = NULL;

	*parsed_bytes = 0;

	if (end - start > RRR_LENGTH_MAX) {
		RRR_MSG_0("Part was too long while parsing HTTP multipart (%llu>%llu)\n",
			(unsigned long long) (end - start),
			(unsigned long long) RRR_LENGTH_MAX
		);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if ((ret = rrr_nullsafe_str_dup (&boundary_with_dashes, boundary)) != 0) {
		goto out;
	}

	// Boundary must have -- directly in front of it
	if ((ret = rrr_nullsafe_str_prepend_raw(boundary_with_dashes, "--", 2)) != 0) {
		goto out;
	}

	{
		// End boundary has -- after it
		if ((ret = rrr_nullsafe_str_dup(&boundary_with_dashes_end, boundary_with_dashes)) != 0) {
			goto out;
		}
		if ((ret = rrr_nullsafe_str_append_raw(boundary_with_dashes_end, "--\r\n", 4)) != 0) {
			goto out;
		}
	}

	// Boundary must have \r\n directly after it
	if ((ret = rrr_nullsafe_str_append_raw(boundary_with_dashes, "\r\n", 2)) != 0) {
		goto out;
	}

	struct rrr_http_part_multipart_process_part_callback_data callback_data = {
			parent,
			max_parts,
			parsed_bytes,
			boundary_with_dashes_end,
			start
	};

	if ((ret = rrr_nullsafe_str_str_raw (
			start,
			rrr_length_from_ptr_sub_bug_const (end, start),
			boundary_with_dashes,
			__rrr_http_part_multipart_process_part_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_HTTP_PARSE_EOF) {
			ret = RRR_HTTP_PARSE_OK;
		}
		goto out;
	}

	out:
		rrr_nullsafe_str_destroy_if_not_null(&boundary_with_dashes);
		rrr_nullsafe_str_destroy_if_not_null(&boundary_with_dashes_end);
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

	if (part->is_chunked || RRR_LL_COUNT(&part->chunks) > 0) {
		RRR_BUG("BUG: Attempted to process chunked part as multipart\n");
	}

	RRR_HTTP_PART_DECLARE_DATA_START_AND_END(part, data_ptr);

	size_t parsed_bytes_tmp = 0;

	if ((ret = (__rrr_http_part_multipart_process_parts (
			part,
			1000, // Max parts
			&parsed_bytes_tmp,
			data_ptr,
			data_end,
			boundary->value
	) & ~(RRR_HTTP_PARSE_EOF))) != 0) {
		// It's possible that return is EOF, INCOMPLETE, SOFT and HARD
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

	out:
	return ret;
}

struct rrr_http_part_multipart_form_data_make_field_callback_data {
		int is_first;
		const char *boundary;
		int (*chunk_callback)(RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS);
		void *chunk_callback_arg;
};

static int __rrr_http_part_multipart_form_data_make_field_callback (
		const struct rrr_nullsafe_str *name,
		const struct rrr_nullsafe_str *value,
		const struct rrr_nullsafe_str *content_type,
		void *arg
) {
	struct rrr_http_part_multipart_form_data_make_field_callback_data *callback_data = arg;

	int ret = 0;

	char *name_buf = NULL;
	char *name_buf_full = NULL;
	char *content_type_buf = NULL;
	char *body_buf = NULL;
	struct rrr_nullsafe_str *body_buf_nullsafe = NULL;

	if (rrr_nullsafe_str_isset(name)) {
		if ((name_buf = rrr_http_util_header_value_quote_nullsafe(name, '"', '"')) == NULL) {
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

	if (rrr_nullsafe_str_isset(content_type)) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,content_type);
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
			(callback_data->is_first ? "" : "\r\n"),
			callback_data->boundary,
			(name_buf_full != NULL ? name_buf_full : ""),
			(content_type_buf != NULL ? content_type_buf : "")
	)) < 0) {
		RRR_MSG_0("Could not create content type string and body  in __rrr_http_part_multipart_field_make return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_nullsafe_str_new_or_replace_raw(&body_buf_nullsafe, NULL, 0)) != 0) {
		goto out;
	}

	rrr_nullsafe_str_set_allocated (
			body_buf_nullsafe,
			(void**) &body_buf,
			rrr_length_from_size_t_bug_const(strlen(body_buf))
	);

	if ((ret = callback_data->chunk_callback (body_buf_nullsafe, callback_data->chunk_callback_arg)) != 0) {
		RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_part_multipart_field_make A\n");
		goto out;
	}

	if (rrr_nullsafe_str_isset(value)) {
		if ((ret = callback_data->chunk_callback (value, callback_data->chunk_callback_arg)) != 0) {
			RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_part_multipart_field_make B\n");
			goto out;
		}
	}

	callback_data->is_first = 0;

	out:
	RRR_FREE_IF_NOT_NULL(name_buf);
	RRR_FREE_IF_NOT_NULL(name_buf_full);
	RRR_FREE_IF_NOT_NULL(content_type_buf);
	RRR_FREE_IF_NOT_NULL(body_buf);
	rrr_nullsafe_str_destroy_if_not_null(&body_buf_nullsafe);
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
	struct rrr_nullsafe_str *body_buf_nullsafe = NULL;

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
				"multipart/form-data; boundary=%s",
				boundary_buf
		)) < 0) {
			RRR_MSG_0("Could not create content type string in rrr_http_part_multipart_form_data_make return was %i\n", ret);
			ret = 1;
			goto out;
		}

		if ((ret = rrr_http_part_header_field_push(part, "content-type", body_buf)) != 0) {
			goto out;
		}
	}

	struct rrr_http_part_multipart_form_data_make_field_callback_data callback_data = {
		1,
		boundary_buf,
		chunk_callback,
		chunk_callback_arg
	};


	if ((ret = rrr_http_field_collection_iterate_as_strings (
		&part->fields,
		__rrr_http_part_multipart_form_data_make_field_callback,
		&callback_data
	)) != 0) {
		goto out;
	}

	{
		if ((ret = rrr_nullsafe_str_new_or_replace_raw(&body_buf_nullsafe, NULL, 0)) != 0) {
			goto out;
		}

		// ONE CRLF AFTER BODY AND ONE AT THE VERY END
		if ((ret = rrr_nullsafe_str_append_asprintf(body_buf_nullsafe, "\r\n--%s--\r\n", boundary_buf)) != 0) {
			RRR_MSG_0("Could not create last boundary in rrr_http_part_multipart_form_data_make return was %i\n", ret);
			goto out;
		}

		if ((ret = chunk_callback (body_buf_nullsafe, chunk_callback_arg)) != 0) {
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(body_buf);
	RRR_FREE_IF_NOT_NULL(boundary_buf);
	rrr_nullsafe_str_destroy_if_not_null(&body_buf_nullsafe);

	return ret;
}
