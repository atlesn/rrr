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

#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "http_part.h"
#include "http_fields.h"
#include "http_util.h"

static int __rrr_http_header_parse_unsigned_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_OK;

	ssize_t parsed_bytes = 0;

	if ((ret = rrr_http_util_strtoull (
			&field->value_unsigned,
			&parsed_bytes,
			field->value,
			field->value + strlen(field->value),
			10
	)) != 0) {
		RRR_MSG_ERR("Could not get value from field '%s'\n", field->name);
		goto out;
	}

	out:
	return ret;
}


static const struct rrr_http_header_field_definition definitions[] = {
//		{"content-type",	__rrr_http_header_parse_semicolon_separated},
		{"content-length",	__rrr_http_header_parse_unsigned_value},
		{NULL,				NULL}
};

static const struct rrr_http_header_field_definition *__rrr_http_header_field_get_definition (
		const char *field,
		ssize_t field_len
) {
	for (int i = 0; 1; i++) {
		const struct rrr_http_header_field_definition *def = &definitions[i];

		if (def->name_lowercase == NULL) {
			break;
		}

		const char *result = NULL;
		ssize_t result_len = 0;

		if (rrr_http_util_strcasestr (
				&result,
				&result_len,
				field,
				field + field_len,
				def->name_lowercase
		) == 0 && result == field) {
			return def;
		}
	}

	return NULL;
}

static void __rrr_http_header_field_destroy (struct rrr_http_header_field *field) {
	rrr_http_fields_collection_clear(&field->fields);
	RRR_FREE_IF_NOT_NULL(field->name);
	RRR_FREE_IF_NOT_NULL(field->value);
	free (field);
}

static int __rrr_http_header_field_new (
		struct rrr_http_header_field **result,
		const char *field_name,
		ssize_t field_len
) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_header_field *field = malloc(sizeof(*field));
	if (field == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_http_header_field_new\n");
		ret = 1;
		goto out;
	}

	memset (field, '\0', sizeof(*field));

	// Might return NULL, which is OK
	field->definition = __rrr_http_header_field_get_definition(field_name, field_len);

	field->name = malloc(field_len + 1);
	if (field->name == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_http_header_field_new\n");
		ret = 1;
		goto out;
	}
	memcpy(field->name, field_name, field_len);
	field->name[field_len] = '\0';

	rrr_http_util_strtolower(field->name);

	*result = field;
	field = NULL;

	out:
	if (field != NULL) {
		__rrr_http_header_field_destroy(field);
	}

	return ret;
}

static struct rrr_http_header_field *__rrr_http_header_field_collection_get_field (
		struct rrr_http_header_field_collection *collection,
		const char *name_lowercase
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_http_header_field);
		if (strcmp(name_lowercase, node->name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static void __rrr_header_field_collection_add (
		struct rrr_http_header_field_collection *collection,
		struct rrr_http_header_field *field
) {
	RRR_LL_APPEND(collection, field);
}

void rrr_http_part_destroy (struct rrr_http_part *part) {
	RRR_LL_DESTROY(part, struct rrr_http_part, rrr_http_part_destroy(node));
	RRR_LL_DESTROY(&part->headers, struct rrr_http_header_field, __rrr_http_header_field_destroy(node));
	RRR_LL_DESTROY(&part->chunks, struct rrr_http_chunk, free(node));
	rrr_http_fields_collection_clear(&part->fields);
	RRR_FREE_IF_NOT_NULL(part->response_str);
	free (part);
}

int rrr_http_part_new (struct rrr_http_part **result) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_part *part = malloc (sizeof(*part));
	if (part == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_part_new\n");
		ret = 1;
		goto out;
	}

	memset (part, '\0', sizeof(*part));

	*result = part;

	out:
	return ret;
}

const struct rrr_http_header_field *rrr_http_part_get_header_field (
		struct rrr_http_part *part,
		const char *name_lowercase
) {
	return __rrr_http_header_field_collection_get_field(&part->headers, name_lowercase);
}

static int __rrr_http_parse_response_code (
		struct rrr_http_part *result,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_OK;

	const char *start = buf + start_pos;
	ssize_t tmp_len = 0;

	*parsed_bytes = 0;

	const char *crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	if (crlf - start < (ssize_t) strlen("HTTP/1.1 200")) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	const char *start_orig = start;
	if ((ret = rrr_http_util_strcasestr(&start, &tmp_len, start, crlf, "HTTP/1.1")) != 0 || start != start_orig) {
		RRR_MSG_ERR("Could not understand HTTP response header/version in __rrr_http_parse_response_code\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	start += tmp_len;
	start += rrr_http_util_count_whsp(start, end);

	unsigned long long int response_code = 0;
	if ((ret = rrr_http_util_strtoull(&response_code, &tmp_len, start, crlf, 10)) != 0 || response_code > 999) {
		RRR_MSG_ERR("Could not understand HTTP response code in __rrr_http_parse_response_code\n");
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
			RRR_MSG_ERR("Could not allocate memory for response string in __rrr_http_parse_response_code\n");
			goto out;
		}
		memcpy(result->response_str, start, response_str_len);
		result->response_str[response_str_len] = '\0';
	}
	else if (start > crlf) {
		RRR_BUG("pos went beyond CRLF in __rrr_http_parse_response_code\n");
	}

	*parsed_bytes = (crlf - (buf + start_pos) + 2);

	out:
	return ret;
}

static int __rrr_http_parse_header_field (
		struct rrr_http_header_field **result,
		ssize_t *parsed_bytes,
		const char *start_orig,
		const char *end
) {
	int ret = 0;
	struct rrr_http_header_field *field = NULL;
	const char *start = start_orig;

	*result = NULL;
	*parsed_bytes = 0;

	const char *crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	const char *colon = rrr_http_util_strchr(start, crlf, ':');
	if (colon == NULL) {
		RRR_MSG_ERR("Colon not found in HTTP header field in __rrr_http_parse_header_field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if ((ret = __rrr_http_header_field_new(&field, start, colon - start)) != 0) {
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	start = colon + 1;
	start += rrr_http_util_count_whsp(start, crlf);

	if (start >= crlf) {
		RRR_MSG_ERR("No value for header field in __rrr_http_parse_header_field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	ssize_t value_len = crlf - start;
	field->value = malloc(value_len + 1);
	if (field->value == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_http_parse_header_field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}
	memcpy (field->value, start, value_len);
	field->value[value_len] = '\0';

	if (field->definition != NULL && field->definition->parse(field) != 0) {
		RRR_MSG_ERR("Could not parse field '%s' in __rrr_http_parse_header_field\n", field->name);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	*parsed_bytes = (crlf - start_orig) + 2;
	*result = field;
	field = NULL;

	out:
	if (field != NULL) {
		__rrr_http_header_field_destroy(field);
	}
	return ret;
}

static struct rrr_http_chunk *__rrr_http_part_chunk_new (
		ssize_t chunk_start,
		ssize_t chunk_length
) {
	struct rrr_http_chunk *new_chunk = malloc(sizeof(*new_chunk));
	if (new_chunk == NULL) {
		RRR_MSG_ERR("Could not allocate memory for chunk in __rrr_http_part_append_chunk\n");
		return NULL;
	}

	memset(new_chunk, '\0', sizeof(*new_chunk));

	new_chunk->start = chunk_start;
	new_chunk->length = chunk_length;

	return new_chunk;
}

static int __rrr_http_part_parse_chunk_header (
		struct rrr_http_chunk **result_chunk,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

	*parsed_bytes = 0;
	*result_chunk = NULL;

	// TODO : Implement chunk header fields

	/*char buf[32];
	memcpy(buf, start - 16, 16);
	buf[16] = '\0';

	printf ("Looking for chunk header between %s\n", buf);
	memcpy(buf, start, 16);
	buf[16] = '\0';
	printf ("and %s\n", buf);*/

	const char *start = buf + start_pos;
	const char *pos = start;

	ssize_t parsed_bytes_tmp = 0;

	if (pos >= end) {
		return RRR_HTTP_PARSE_INCOMPLETE;
	}

	const char *crlf = rrr_http_util_find_crlf(pos, end);

	if (pos >= end) {
		return RRR_HTTP_PARSE_INCOMPLETE;
	}

	// Allow extra \r\n at beginning
	if (crlf == pos) {
		pos += 2;
		crlf = rrr_http_util_find_crlf(pos, end);
//		printf ("Parsed extra CRLF before chunk header\n");
	}

	if (crlf != NULL) {
		unsigned long long chunk_length = 0;
		if ((ret = rrr_http_util_strtoull(&chunk_length, &parsed_bytes_tmp, pos, crlf, 16)) != 0) {
			RRR_MSG_ERR("Error while parsing chunk length, invalid value\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}

		if (pos + parsed_bytes_tmp == end) {
			// Chunk header incomplete
			ret = RRR_HTTP_PARSE_INCOMPLETE;
			goto out;
		}
		else if (ret != 0 || crlf - pos != parsed_bytes_tmp) {
			RRR_MSG_ERR("Error while parsing chunk length, invalid value\n");
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
		ssize_t chunk_start = pos - buf;

//		printf ("First character in chunk: %i\n", *(buf + chunk_start));

		if ((new_chunk = __rrr_http_part_chunk_new(chunk_start, chunk_length)) == NULL) {
			ret = RRR_HTTP_PARSE_HARD_ERR;
			goto out;
		}

		*parsed_bytes = pos - start;
		*result_chunk = new_chunk;
	}

	out:
	return ret;
}

static int __rrr_http_part_parse_header_fields (
		struct rrr_http_header_field_collection *target,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t start_pos,
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
			pos += 2;
			parsed_bytes_total += 2;
			break;
		}

		struct rrr_http_header_field *field = NULL;
		if ((ret = __rrr_http_parse_header_field(&field, &parsed_bytes_tmp, pos, end)) != 0) {
			goto out;
		}

		__rrr_header_field_collection_add(target, field);

		pos += parsed_bytes_tmp;
		parsed_bytes_total += parsed_bytes_tmp;
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}

static int __rrr_http_part_parse_chunk (
		struct rrr_http_chunks *chunks,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t start_pos,
		const char *end
) {
	int ret = 0;

	*parsed_bytes = 0;

	const struct rrr_http_chunk *last_chunk = RRR_LL_LAST(chunks);

	ssize_t parsed_bytes_total = 0;
	ssize_t parsed_bytes_previous_chunk = 0;

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
	ret = __rrr_http_part_parse_chunk_header (
			&new_chunk,
			&parsed_bytes_total,
			buf,
			start_pos + parsed_bytes_previous_chunk,
			end
	);

	if (ret == 0) {
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
		RRR_MSG_ERR("Error while parsing last_chunk header in rrr_http_part_parse\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}

int rrr_http_part_parse (
		struct rrr_http_part *result,
		ssize_t *target_size,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

//	static int run_count = 0;
//	printf ("Run count: %i pos %i\n", ++run_count, start_pos);

	*target_size = 0;
	*parsed_bytes = 0;

	ssize_t parsed_bytes_tmp = 0;
	ssize_t parsed_bytes_total = 0;

	if (result->is_chunked == 1) {
		goto parse_chunked;
	}

	if (result->response_code == 0) {
		ret = __rrr_http_parse_response_code (
				result,
				&parsed_bytes_tmp,
				buf,
				start_pos + parsed_bytes_total,
				end
		);

		parsed_bytes_total += parsed_bytes_tmp;

		if (ret != RRR_HTTP_PARSE_OK) {
			goto out;
		}

		result->response_code_length = parsed_bytes_tmp;
	}

	if (result->header_complete == 0) {
		ret = __rrr_http_part_parse_header_fields (
				&result->headers,
				&parsed_bytes_tmp,
				buf,
				start_pos + parsed_bytes_total,
				end
		);

		parsed_bytes_total += parsed_bytes_tmp;

		if (ret != RRR_HTTP_PARSE_OK) {
			goto out;
		}

		RRR_DBG_3("HTTP header complete, response was %i\n", result->response_code);

		// Make sure the maths are done correctly. Header may be partially parsed in a previous round,
		// we need to figure out the header length using the current parsing position
		result->header_length = start_pos + parsed_bytes_total - result->response_code_length;
		result->header_complete = 1;

		struct rrr_http_header_field *content_length = __rrr_http_header_field_collection_get_field(&result->headers, "content-length");
		struct rrr_http_header_field *transfer_encoding = __rrr_http_header_field_collection_get_field(&result->headers, "transfer-encoding");

		if (content_length != NULL) {
			result->data_length = content_length->value_unsigned;
			*target_size = result->response_code_length + result->header_length + content_length->value_unsigned;

			RRR_DBG_3("HTTP content length found: %llu (plus response %li and header %li) target size is %li\n",
					content_length->value_unsigned, result->response_code_length, result->header_length, *target_size);

			ret = RRR_HTTP_PARSE_OK;

			goto out;
		}
		else if (transfer_encoding != NULL && strcasecmp(transfer_encoding->value, "chunked") == 0) {
			ret = RRR_HTTP_PARSE_INCOMPLETE;
			result->is_chunked = 1;
			RRR_DBG_3("HTTP chunked transfer encoding specified\n");
			goto parse_chunked;
		}
		else {
			if (result->response_code == 204) {
				// No content
				result->data_length = 0;
				*target_size = 0;
				ret = RRR_HTTP_PARSE_OK;
			}
			else {
				// Unknown size, parse until connection closes
				result->data_length = -1;
				*target_size = 0;
				ret = RRR_HTTP_PARSE_INCOMPLETE;
			}
			goto out;
		}
	}

	goto out;
	parse_chunked:

	ret = __rrr_http_part_parse_chunk (
			&result->chunks,
			&parsed_bytes_tmp,
			buf,
			start_pos + parsed_bytes_total,
			end
	);

	parsed_bytes_total += parsed_bytes_tmp;

	if (ret == RRR_HTTP_PARSE_OK) {
		if (RRR_LL_LAST(&result->chunks)->length != 0) {
			RRR_BUG("BUG: __rrr_http_part_parse_chunk return OK but last chunk length was not 0 in rrr_http_part_parse\n");
		}

		// Part length is position of last chunk plus CRLF minus header and response code
		result->data_length = RRR_LL_LAST(&result->chunks)->start + 2 - result->header_length - result->response_code_length;

		// Target size is total length from start of session to last chunk plus CRLF
		*target_size = RRR_LL_LAST(&result->chunks)->start + 2;
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}
