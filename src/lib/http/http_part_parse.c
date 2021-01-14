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
#include "http_part.h"
#include "http_part_parse.h"
#include "http_common.h"
#include "http_util.h"

static int __rrr_http_part_parse_response_code (
		struct rrr_http_part *result,
		size_t *parsed_bytes,
		const char *buf,
		size_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_OK;

	const char *start = buf + start_pos;

	*parsed_bytes = 0;

	const char *crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	if (crlf == start) {
		RRR_MSG_0("No response string found in HTTP response, only CRLF found\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (crlf - start < (ssize_t) strlen("HTTP/1.1 200")) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	const char *start_orig = start;

	rrr_length tmp_len = 0;
	if (rrr_http_util_strcasestr(&start, &tmp_len, start, crlf, "HTTP/1.1") != 0 || start != start_orig) {
		RRR_MSG_0("Could not understand HTTP response header/version in __rrr_http_parse_response_code\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	start += tmp_len;
	start += rrr_http_util_count_whsp(start, end);

	unsigned long long int response_code = 0;
	if (rrr_http_util_strtoull_raw(&response_code, &tmp_len, start, crlf, 10) != 0 || response_code > 999) {
		RRR_MSG_0("Could not understand HTTP response code in __rrr_http_parse_response_code\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}
	result->response_code = response_code;

	start += tmp_len;
	start += rrr_http_util_count_whsp(start, end);

	if (start < crlf) {
		ssize_t response_str_len = crlf - start;
		result->response_str = malloc(response_str_len + 1);
		if (result->response_str == NULL) {
			RRR_MSG_0("Could not allocate memory for response string in __rrr_http_parse_response_code\n");
			goto out;
		}
		memcpy(result->response_str, start, response_str_len);
		result->response_str[response_str_len] = '\0';
	}
	else if (start > crlf) {
		RRR_BUG("pos went beyond CRLF in __rrr_http_parse_response_code\n");
	}

	// Must be set when everything is complete
	result->parsed_protocol_version = RRR_HTTP_APPLICATION_HTTP1;

	*parsed_bytes = (crlf - (buf + start_pos) + 2);

	out:
	return ret;
}

static int __rrr_http_part_parse_request (
		struct rrr_http_part *result,
		size_t *parsed_bytes,
		const char *buf,
		size_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_OK;

	const char *start = buf + start_pos;

	*parsed_bytes = 0;

	const char *crlf = NULL;
	const char *space = NULL;

	if ((crlf = rrr_http_util_find_crlf(start, end)) == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	if (crlf == start) {
		RRR_MSG_0("No request method string found in HTTP request, only CRLF found\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if ((space = rrr_http_util_find_whsp(start, end)) == NULL) {
		RRR_MSG_0("Whitespace missing after request method in HTTP request\n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_nullsafe_str_new_or_replace_raw(&result->request_method_str_nullsafe, start, space - start) != 0) {
		RRR_MSG_0("Could not allocate string for request method in __rrr_http_parse_request \n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	if (rrr_nullsafe_str_len(result->request_method_str_nullsafe) == 0) {
		RRR_MSG_0("Request method missing in HTTP request\n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	start += space - start;
	start += rrr_http_util_count_whsp(start, end);

	if ((space = rrr_http_util_find_whsp(start, end)) == NULL) {
		RRR_MSG_0("Whitespace missing after request uri in HTTP request\n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_nullsafe_str_new_or_replace_raw(&result->request_uri_nullsafe, start, space - start) != 0) {
		RRR_MSG_0("Could not allocate string for uri in __rrr_http_parse_request \n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	start += space - start;
	start += rrr_http_util_count_whsp(start, end);

	const char *start_orig = start;

	rrr_length protocol_length = 0;
	if ((ret = rrr_http_util_strcasestr(&start, &protocol_length, start_orig, crlf, "HTTP/1.1")) != 0 || start != start_orig) {
		RRR_MSG_0("Invalid or missing protocol version in HTTP request\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (start_orig + protocol_length != crlf) {
		RRR_MSG_0("Extra data after protocol version in HTTP request\n");
		rrr_http_util_print_where_message(start_orig + protocol_length, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// Must be set when everything is complete
	result->parsed_protocol_version = RRR_HTTP_APPLICATION_HTTP1;

	*parsed_bytes = (crlf - (buf + start_pos) + 2);

	out:
	return ret;
}

static int __rrr_http_part_parse_chunk_header (
		struct rrr_http_chunk **result_chunk,
		size_t *parsed_bytes,
		const char *buf,
		size_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_OK;

	*parsed_bytes = 0;
	*result_chunk = NULL;

	// TODO : Implement chunk header fields
/*
	char buf_dbg[32];
	memcpy(buf_dbg, buf + start_pos - 16, 16);
	buf_dbg[16] = '\0';

	printf ("Looking for chunk header between %s\n", buf_dbg);
	memcpy(buf_dbg, buf + start_pos, 16);
	buf_dbg[16] = '\0';
	printf ("and %s\n", buf_dbg);
*/
	const char *start = buf + start_pos;
	const char *pos = start;

	if (pos >= end) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	const char *crlf = rrr_http_util_find_crlf(pos, end);

	if (pos >= end) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	// Allow extra \r\n at beginning
	if (crlf == pos) {
		pos += 2;
		crlf = rrr_http_util_find_crlf(pos, end);
//		printf ("Parsed extra CRLF before chunk header\n");
	}

	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	unsigned long long chunk_length = 0;

	rrr_length parsed_bytes_tmp = 0;
	if ((ret = rrr_http_util_strtoull_raw(&chunk_length, &parsed_bytes_tmp, pos, crlf, 16)) != 0) {
		RRR_MSG_0("Error while parsing chunk length, invalid value\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (pos + parsed_bytes_tmp == end) {
		// Chunk header incomplete
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}
	else if (ret != 0 || (size_t) crlf - (size_t) pos != parsed_bytes_tmp) {
		RRR_MSG_0("Error while parsing chunk length, invalid value\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	pos += parsed_bytes_tmp;
	pos += 2; // Plus CRLF after chunk header

	if (pos + 1 >= end) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	struct rrr_http_chunk *new_chunk = NULL;
	rrr_length chunk_start = pos - buf;

//		printf ("First character in chunk: %i\n", *(buf + chunk_start));

	if ((new_chunk = rrr_http_part_chunk_new(chunk_start, chunk_length)) == NULL) {
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	*parsed_bytes = pos - start;
	*result_chunk = new_chunk;

	out:
	return ret;
}

static int __rrr_http_part_header_fields_parse (
		struct rrr_http_header_field_collection *target,
		size_t *parsed_bytes,
		const char *buf,
		size_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_OK;

	const char *pos = buf + start_pos;

	*parsed_bytes = 0;

	ssize_t parsed_bytes_total = 0;
	ssize_t parsed_bytes_tmp = 0;

//	static int run_count_loop = 0;
	while (1) {
//		printf ("Run count loop: %i\n", ++run_count_loop);
		const char *crlf = rrr_http_util_find_crlf(pos, end);
		if (crlf == NULL) {
			// Header incomplete, not enough data
			ret = RRR_HTTP_PARSE_INCOMPLETE;
			goto out;
		}
		else if (crlf == pos) {
			// Header complete
			// pos += 2; -- Enable if needed
			parsed_bytes_total += 2;
			break;
		}

		if ((ret = rrr_http_header_field_parse_name_and_value(target, &parsed_bytes_tmp, pos, end)) != 0) {
			goto out;
		}

		pos += parsed_bytes_tmp;
		parsed_bytes_total += parsed_bytes_tmp;

		if (pos == crlf) {
			pos += 2;
			parsed_bytes_total += 2;
		}
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}

static int __rrr_http_part_parse_chunk (
		struct rrr_http_chunks *chunks,
		size_t *parsed_bytes,
		const char *buf,
		size_t start_pos,
		const char *end
) {
	int ret = 0;

	*parsed_bytes = 0;

	const struct rrr_http_chunk *last_chunk = RRR_LL_LAST(chunks);

	size_t parsed_bytes_total = 0;
	size_t parsed_bytes_previous_chunk = 0;

	if (last_chunk != NULL) {
		if (buf + last_chunk->start + last_chunk->length > end) {
			// Need to read more
			ret = RRR_HTTP_PARSE_INCOMPLETE;
			goto out;
		}

		// Chunk is done. Don't add to to total just yet in case
		// parsing of the next chunk header turns out incomplete
		// and we need to parse it again.
		parsed_bytes_previous_chunk = last_chunk->length;
	}

	struct rrr_http_chunk *new_chunk = NULL;

	if ((ret = __rrr_http_part_parse_chunk_header (
			&new_chunk,
			&parsed_bytes_total,
			buf,
			start_pos + parsed_bytes_previous_chunk,
			end
	)) == 0 && new_chunk != NULL) { // != NULL check due to false positive warning about use of NULL from scan-build
		RRR_DBG_3("Found new HTTP chunk start %li length %li\n", new_chunk->start, new_chunk->length);
		RRR_LL_APPEND(chunks, new_chunk);

		// All of the bytes in the previous chunk (if any) have been read
		parsed_bytes_total += parsed_bytes_previous_chunk;

		if (new_chunk == NULL) {
			RRR_BUG("Bug last_chunk was not set but return from __rrr_http_part_parse_chunk_header was OK in rrr_http_part_parse\n");
		}
		if (new_chunk->length == 0) {
			// Last last_chunk
			ret = RRR_HTTP_PARSE_OK;
		}
		else {
			ret = RRR_HTTP_PARSE_INCOMPLETE;
		}
		goto out;
	}
	else if (ret == RRR_HTTP_PARSE_INCOMPLETE) {
		goto out;
	}
	else {
		RRR_MSG_0("Error while parsing last_chunk header in rrr_http_part_parse\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}

static int __rrr_http_part_request_method_str_to_enum (
		struct rrr_http_part *part,
		const struct rrr_nullsafe_str *content_type_or_null
) {
	int ret = 0;

	if (rrr_nullsafe_str_cmpto(part->request_method_str_nullsafe, "GET") == 0) {
		part->request_method = RRR_HTTP_METHOD_GET;
	}
	else if (rrr_nullsafe_str_cmpto(part->request_method_str_nullsafe, "OPTIONS") == 0) {
		part->request_method = RRR_HTTP_METHOD_OPTIONS;
	}
	else if (rrr_nullsafe_str_cmpto(part->request_method_str_nullsafe, "POST") == 0) {
		part->request_method = RRR_HTTP_METHOD_POST_APPLICATION_OCTET_STREAM;

		if (content_type_or_null != NULL) {
			if (rrr_nullsafe_str_cmpto_case(content_type_or_null, "multipart/form-data") == 0) {
				part->request_method = RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA;
			}
			else if (rrr_nullsafe_str_cmpto_case(content_type_or_null, "application/x-www-form-urlencoded") == 0) {
				part->request_method = RRR_HTTP_METHOD_POST_URLENCODED;
			}
			else if (rrr_nullsafe_str_cmpto_case(content_type_or_null, "text/plain") == 0) {
				part->request_method = RRR_HTTP_METHOD_POST_TEXT_PLAIN;
			}
		}
	}
	else if (rrr_nullsafe_str_cmpto(part->request_method_str_nullsafe, "PUT") == 0) {
		part->request_method = RRR_HTTP_METHOD_PUT;
	}
	else if (rrr_nullsafe_str_cmpto(part->request_method_str_nullsafe, "HEAD") == 0) {
		part->request_method = RRR_HTTP_METHOD_HEAD;
	}
	else if (rrr_nullsafe_str_cmpto(part->request_method_str_nullsafe, "DELETE") == 0) {
		part->request_method = RRR_HTTP_METHOD_DELETE;
	}
	else {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,part->request_method_str_nullsafe);
		RRR_MSG_0("Unknown request method '%s' in HTTP request (not GET/OPTIONS/POST/PUT/HEAD/DELETE)\n", value);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_part_parse_chunked (
		struct rrr_http_part *part,
		size_t *target_size,
		size_t *parsed_bytes,
		const char *data_ptr,
		size_t start_pos,
		const char *end,
		enum rrr_http_parse_type parse_type
) {
	int ret = 0;

	*target_size = 0;
	*parsed_bytes = 0;

	size_t parsed_bytes_tmp = 0;

	if (parse_type == RRR_HTTP_PARSE_MULTIPART) {
		RRR_MSG_0("Chunked transfer encoding found in HTTP multipart body, this is not allowed\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	ret = __rrr_http_part_parse_chunk (
			&part->chunks,
			&parsed_bytes_tmp,
			data_ptr,
			start_pos,
			end
	);

	if (ret == RRR_HTTP_PARSE_OK) {
		if (RRR_LL_LAST(&part->chunks)->length != 0) {
			RRR_BUG("BUG: __rrr_http_part_parse_chunk return OK but last chunk length was not 0 in __rrr_http_part_parse_chunked\n");
		}

		// Part length is position of last chunk plus CRLF minus header and response code
		part->data_length = RRR_LL_LAST(&part->chunks)->start + 2 - part->header_length - part->headroom_length;

		// Target size is total length from start of session to last chunk plus CRLF
		*target_size = RRR_LL_LAST(&part->chunks)->start + 2;
	}

	*parsed_bytes = parsed_bytes_tmp;

	out:
	return ret;
}

int rrr_http_part_parse (
		struct rrr_http_part *part,
		size_t *target_size,
		size_t *parsed_bytes,
		const char *data_ptr,
		size_t start_pos,
		const char *end,
		enum rrr_http_parse_type parse_type
) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

//	static int run_count = 0;
//	printf ("Run count: %i pos %i\n", ++run_count, start_pos);

	*target_size = 0;
	*parsed_bytes = 0;

	size_t parsed_bytes_tmp = 0;
	size_t parsed_bytes_total = 0;

	if (part->is_chunked == 1) {
		// This is merely a shortcut to skip already checked conditions
		goto out_parse_chunked;
	}

	if (part->parsed_protocol_version == 0 && parse_type != RRR_HTTP_PARSE_MULTIPART) {
		if (parse_type == RRR_HTTP_PARSE_REQUEST) {
			ret = __rrr_http_part_parse_request (
					part,
					&parsed_bytes_tmp,
					data_ptr,
					start_pos + parsed_bytes_total,
					end
			);
		}
		else if (parse_type == RRR_HTTP_PARSE_RESPONSE) {
			ret = __rrr_http_part_parse_response_code (
					part,
					&parsed_bytes_tmp,
					data_ptr,
					start_pos + parsed_bytes_total,
					end
			);
		}
		else {
			RRR_BUG("BUG: Unknown parse type %i to rrr_http_part_parse\n", parse_type);
		}

		parsed_bytes_total += parsed_bytes_tmp;

		if (ret == RRR_HTTP_PARSE_INCOMPLETE && end - data_ptr > 65536) {
			RRR_MSG_0("HTTP1 request or response line not found in the first 64K bytes, triggering soft error.\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		else if (ret != RRR_HTTP_PARSE_OK) {
			if (part->parsed_protocol_version != 0) {
				RRR_BUG("BUG: Protocol version was set prior to complete response/request parsing in rrr_http_part_parse\n");
			}
			goto out;
		}
		else if (part->parsed_protocol_version == 0) {
			RRR_BUG("BUG: Protocol version not set after complete response/request parsing in rrr_http_part_parse\n");
		}

		part->headroom_length = parsed_bytes_tmp;
	}

	if (part->header_complete) {
		goto out;
	}

	{
		ret = __rrr_http_part_header_fields_parse (
				&part->headers,
				&parsed_bytes_tmp,
				data_ptr,
				start_pos + parsed_bytes_total,
				end
		);

		parsed_bytes_total += parsed_bytes_tmp;

		// Make sure the maths are done correctly. Header may be partially parsed in a previous round,
		// we need to figure out the header length using the current parsing position
		part->header_length += parsed_bytes_tmp;

		if (ret != RRR_HTTP_PARSE_OK) {
			// Incomplete or error
			goto out;
		}

		part->header_complete = 1;
	}

	if (parse_type == RRR_HTTP_PARSE_REQUEST) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(method, part->request_method_str_nullsafe);
		RRR_DBG_3("HTTP request header parse complete, request method is '%s'\n", method);

		if (part->request_method != 0) {
			RRR_BUG("BUG: Numeric request method was non zero in rrr_http_part_parse\n");
		}

		const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(part, "content-type");
		if ((ret = __rrr_http_part_request_method_str_to_enum (part, (content_type != NULL ? content_type->value : NULL))) != 0) {
			goto out;
		}
	}
	else {
		RRR_DBG_3("HTTP response header parse complete, response was %i\n", part->response_code);
	}

	const struct rrr_http_header_field *content_length = rrr_http_part_header_field_get(part, "content-length");
	const struct rrr_http_header_field *transfer_encoding = rrr_http_part_header_field_get(part, "transfer-encoding");

	if (content_length != NULL) {
		part->data_length = content_length->value_unsigned;
		*target_size = part->headroom_length + part->header_length + content_length->value_unsigned;

		RRR_DBG_3("HTTP content length found: %llu (plus response %li and header %li) target size is %li\n",
				content_length->value_unsigned, part->headroom_length, part->header_length, *target_size);

		ret = RRR_HTTP_PARSE_OK;

		goto out;
	}
	else if (transfer_encoding != NULL && rrr_nullsafe_str_cmpto_case(transfer_encoding->value, "chunked") == 0) {
		goto out_parse_chunked;
	}
	else if (	parse_type == RRR_HTTP_PARSE_REQUEST ||
				part->response_code == RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT ||
				part->response_code == RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS
	) {
		goto out_no_content;
	}

	// Unknown size, parse until connection closes
	part->data_length_unknown = 1;
	*target_size = 0;
	ret = RRR_HTTP_PARSE_INCOMPLETE;

	goto out;
	out_no_content:
		part->data_length = 0;
		*target_size = part->headroom_length + part->header_length;
		ret = RRR_HTTP_PARSE_OK;
		goto out;

	out_parse_chunked:
		part->is_chunked = 1;
		ret = __rrr_http_part_parse_chunked (
				part,
				target_size,
				&parsed_bytes_tmp,
				data_ptr,
				start_pos + parsed_bytes_total,
				end,
				parse_type
		);
		parsed_bytes_total += parsed_bytes_tmp;
		goto out;

	out:
		*parsed_bytes = parsed_bytes_total;
		return ret;
}

// Set all required request data without parsing
int rrr_http_part_parse_request_data_set (
		struct rrr_http_part *part,
		size_t data_length,
		enum rrr_http_application_type protocol_version,
		const struct rrr_nullsafe_str *request_method,
		const struct rrr_nullsafe_str *uri,
		const struct rrr_nullsafe_str *content_type_or_null
) {
	if ((rrr_nullsafe_str_dup(&part->request_uri_nullsafe, uri)) != 0) {
		return 1;
	}
	if ((rrr_nullsafe_str_dup(&part->request_method_str_nullsafe, request_method)) != 0) {
		return 1;
	}
	if (__rrr_http_part_request_method_str_to_enum (part, content_type_or_null) != 0) {
		return 1;
	}

	part->parsed_protocol_version = protocol_version;
	part->data_length = data_length;
	part->header_complete = 1;
	part->parse_complete = 1;

	return 0;
}

// Set all required response data without parsing
int rrr_http_part_parse_response_data_set (
		struct rrr_http_part *part,
		size_t data_length
) {
	part->data_length = data_length;
	part->header_complete = 1;
	part->parse_complete = 1;

	return 0;
}
