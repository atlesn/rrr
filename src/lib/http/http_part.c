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

#include "../threads.h"
#include "../util/macro_utils.h"

#define RRR_HTTP_PART_DECLARE_DATA_START_AND_END(part,data_ptr)	\
		const char *data_start =								\
				data_ptr +										\
				part->headroom_length +							\
				part->header_length								\
		;														\
		const char *data_end =									\
				data_start +									\
				part->data_length

static int __rrr_http_part_check_content_type (
		struct rrr_http_part *part,
		const char *content_type_test
) {
	const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(part, "content-type");
	if (content_type == NULL || content_type->value == NULL || *(content_type->value) == '\0') {
		return 0;
	}

	if (rrr_posix_strcasecmp(content_type->value, content_type_test) == 0) {
		return 1;
	}

	return 0;
}

static int __rrr_http_header_parse_verify_single_value (struct rrr_http_header_field *field) {
	if (RRR_LL_COUNT(&field->fields) == 0) {
		RRR_MSG_0("No values found for HTTP header field '%s'\n", field->name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	if (RRR_LL_COUNT(&field->fields) > 1) {
		RRR_MSG_0("Multiple values not allowed for HTTP header field '%s'\n", field->name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	if (RRR_LL_FIRST(&field->fields)->value != NULL) {
		RRR_MSG_0("name=value pair not valid for HTTP header field '%s'\n", field->name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	return RRR_HTTP_PARSE_OK;
}

static int __rrr_http_header_parse_unsigned_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_OK;

	if ((ret = __rrr_http_header_parse_verify_single_value(field)) != RRR_HTTP_PARSE_OK) {
		goto out;
	}

	struct rrr_http_field *subvalue = RRR_LL_FIRST(&field->fields);

	rrr_length parsed_bytes = 0;
	if ((ret = rrr_http_util_strtoull (
			&field->value_unsigned,
			&parsed_bytes,
			subvalue->name,
			subvalue->name + strlen(subvalue->name),
			10
	)) != 0) {
		RRR_MSG_0("Could not get value from field '%s'\n", field->name);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_header_parse_single_string_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_OK;

	if ((ret = __rrr_http_header_parse_verify_single_value(field)) != RRR_HTTP_PARSE_OK) {
		goto out;
	}

	struct rrr_http_field *subvalue = RRR_LL_FIRST(&field->fields);

	if (field->value != NULL) {
		RRR_BUG("BUG: value was not NULL in __rrr_http_header_parse_string_value\n");
	}

	if ((field->value = strdup(subvalue->name)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_parse_string_value\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_header_parse_first_string_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_OK;

	if (RRR_LL_COUNT(&field->fields) == 0) {
		RRR_MSG_0("No value found for HTTP header field '%s'\n", field->name);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (RRR_LL_FIRST(&field->fields)->value != NULL) {
		RRR_MSG_0("name=value pair not valid for HTTP header field '%s' first value\n", field->name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	struct rrr_http_field *subvalue = RRR_LL_FIRST(&field->fields);

	if (field->value != NULL) {
		RRR_BUG("BUG: value was not NULL in __rrr_http_header_parse_string_value\n");
	}

	if ((field->value = strdup(subvalue->name)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_parse_string_value\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	out:
	return ret;
}

static void __rrr_http_header_parse_unquote_fields (
		int *found,
		struct rrr_http_field *field,
		const char *parent_field_name,
		const char *names_match[],
		size_t names_match_count
) {
	*found = 0;

	for (size_t i = 0; i < names_match_count; i++) {
		if (strcmp(names_match[i], field->name) == 0) {
			*found = 1;
			break;
		}
	}

	if (*found == 0) {
		return;
	}

	rrr_length output_size = 0;
	if (rrr_http_util_unquote_string(&output_size, field->value, field->value_size) != 0) {
		RRR_DBG_1("Warning: Syntax error in '%s' subvalue field of '%s' in HTTP header\n",
				field->name, parent_field_name);
		return;
	}
	field->value_size = output_size;

	if (rrr_http_util_decode_urlencoded_string(&output_size, field->value, field->value_size) != 0) {
		RRR_DBG_1("Warning: Error while decoding url encoding of '%s' subvalue field of '%s' in HTTP header\n",
				field->name, parent_field_name);
		return;
	}
	field->value_size = output_size;
}

static int __rrr_http_header_parse_content_type_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = 0;

	if ((ret = __rrr_http_header_parse_first_string_value(field)) != 0) {
		goto out;
	}
	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		int found = 0;
		const char *unquote_field_names[] = {"charset", "boundary"};
		__rrr_http_header_parse_unquote_fields(&found, node, field->name, unquote_field_names, 2);
/*		if (found == 0) {
			RRR_DBG_1("Warning: Unknown field '%s' in content-type header\n", node->name);
		}*/
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_http_header_parse_content_disposition_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = 0;

	if ((ret = __rrr_http_header_parse_first_string_value(field)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		if (RRR_LL_FIRST(&field->fields) == node) {
			if (rrr_posix_strcasecmp(node->name, "form-data") != 0 &&
					rrr_posix_strcasecmp(node->name, "attachment") != 0 &&
					rrr_posix_strcasecmp(node->name, "inline") != 0
			) {
				RRR_DBG_1("Warning: Unknown content-disposition type '%s'\n", node->name);
				RRR_LL_ITERATE_BREAK();
			}
			RRR_LL_ITERATE_NEXT();
		}

		if (node->value == NULL || node->value_size == 0) {
			RRR_DBG_1("Warning: Empty field '%s' in content-disposition\n", node->name);
			RRR_LL_ITERATE_NEXT();
		}

		int found = 0;
		const char *unquote_field_names[] = {"name", "filename"};
		__rrr_http_header_parse_unquote_fields(&found, node, field->name, unquote_field_names, 2);
		if (found == 0) {
			RRR_DBG_1("Warning: Unknown field '%s' in content-disposition header\n", node->name);
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static const struct rrr_http_header_field_definition definitions[] = {
		{"accept",				RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	NULL},
		{"accept-language",		RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	NULL},
		{"accept-encoding",		RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	NULL},
		{"cache-control",		RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	NULL},
		{"connection",			0,										__rrr_http_header_parse_single_string_value},
		{"content-disposition",	0,										__rrr_http_header_parse_content_disposition_value},
		{"content-length",		RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_unsigned_value},
		{"content-type",		0,										__rrr_http_header_parse_content_type_value},
		{"date",				RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_single_string_value},
		{"link",				RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	NULL},
		{"location",			RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_single_string_value},
		{"server",				0,										__rrr_http_header_parse_single_string_value},
		{"server-timing",		RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	__rrr_http_header_parse_first_string_value},
		{"transfer-encoding",	RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_single_string_value},
		{"user-agent",			RRR_HTTP_HEADER_FIELD_NO_PAIRS,			NULL},
		{"vary",				RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	__rrr_http_header_parse_single_string_value},
		{"x-clue",				RRR_HTTP_HEADER_FIELD_NO_PAIRS,			NULL},
		{NULL, 0, NULL}
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

		rrr_length result_len = 0;
		if (rrr_http_util_strcasestr (
				&result,
				&result_len,
				field,
				field + field_len,
				def->name_lowercase
			) == 0 &&
			result == field &&
			field_len == (ssize_t) strlen(def->name_lowercase)
		) {
			return def;
		}
	}

	return NULL;
}

static void __rrr_http_header_field_destroy (struct rrr_http_header_field *field) {
	rrr_http_field_collection_clear(&field->fields);
	RRR_FREE_IF_NOT_NULL(field->name);
	RRR_FREE_IF_NOT_NULL(field->value);
	free (field);
}

static int __rrr_http_header_field_new (
		struct rrr_http_header_field **result,
		const char *field_name,
		ssize_t field_name_len
) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_header_field *field = malloc(sizeof(*field));
	if (field == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_field_new\n");
		ret = 1;
		goto out;
	}

	memset (field, '\0', sizeof(*field));

	// Might return NULL, which is OK
	field->definition = __rrr_http_header_field_get_definition(field_name, field_name_len);

	field->name = malloc(field_name_len + 1);
	if (field->name == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_field_new\n");
		ret = 1;
		goto out;
	}
	memcpy(field->name, field_name, field_name_len);
	field->name[field_name_len] = '\0';

	rrr_http_util_strtolower(field->name);

	*result = field;
	field = NULL;

	out:
	if (field != NULL) {
		__rrr_http_header_field_destroy(field);
	}

	return ret;
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
		if (node->name != NULL && node->value != NULL && rrr_posix_strcasecmp(node->name, subvalue_name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

void rrr_http_part_destroy (struct rrr_http_part *part) {
	RRR_LL_DESTROY(part, struct rrr_http_part, rrr_http_part_destroy(node));
	RRR_LL_DESTROY(&part->headers, struct rrr_http_header_field, __rrr_http_header_field_destroy(node));
	RRR_LL_DESTROY(&part->chunks, struct rrr_http_chunk, free(node));
	rrr_http_field_collection_clear(&part->fields);
	RRR_FREE_IF_NOT_NULL(part->response_str);
	RRR_FREE_IF_NOT_NULL(part->response_raw_data);
	RRR_FREE_IF_NOT_NULL(part->request_uri);
	RRR_FREE_IF_NOT_NULL(part->request_method_str);
	free (part);
}

void rrr_http_part_destroy_void (void *part) {
	rrr_http_part_destroy(part);
}

void rrr_http_part_destroy_void_double_ptr (void *arg) {
	struct rrr_thread_double_pointer *ptr = arg;
//	printf ("Free double ptr: %p\n", *(ptr->ptr));
	if (*(ptr->ptr) != NULL) {
		rrr_http_part_destroy(*(ptr->ptr));
	}
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

void rrr_http_part_set_allocated_raw_response (
		struct rrr_http_part *part,
		char **raw_data_source,
		size_t raw_data_size
) {
	if (part->response_raw_data != NULL) {
		RRR_BUG("BUG: rrr_http_part_set_allocated_raw_response called while raw data was already set\n");
	}
	part->response_raw_data = *raw_data_source;
	part->response_raw_data_size = raw_data_size;
	*raw_data_source = NULL;
}

void rrr_http_part_set_raw_request_ptr (
		struct rrr_http_part *part,
		const char *raw_data,
		size_t raw_data_size
) {
	part->request_raw_data = raw_data;
	part->request_raw_data_size = raw_data_size;
}

const struct rrr_http_header_field *rrr_http_part_header_field_get (
		const struct rrr_http_part *part,
		const char *name_lowercase
) {
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		if (strcmp(name_lowercase, node->name) == 0) {
			if (node->definition == NULL || node->definition->parse == NULL) {
				RRR_BUG("Attempted to retrieve field %s which was not parsed in __rrr_http_header_field_collection_get_field, definition must be added\n",
						node->name);
			}
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static int __rrr_http_parse_allocate_string (char **result, const char *start, const char *end) {
	if (*result != NULL) {
		RRR_BUG("BUG: Target pointer not empty in __rrr_http_parse_allocate_string\n");
	}

	ssize_t str_len = end - start;
	if (((*result) = malloc(str_len + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory for response string in __rrr_http_parse_response_code\n");
		return 1;
	}
	memcpy(*result, start, str_len);
	(*result)[str_len] = '\0';

	return 0;
}

static int __rrr_http_parse_response_code (
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
	if (rrr_http_util_strtoull(&response_code, &tmp_len, start, crlf, 10) != 0 || response_code > 999) {
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
	result->parsed_protocol_version = RRR_HTTP_PART_PROTOCOL_VERSION_1_1;

	*parsed_bytes = (crlf - (buf + start_pos) + 2);

	out:
	return ret;
}

static int __rrr_http_parse_request (
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

	if ((space = rrr_http_util_find_whsp(start, end)) == NULL) {
		RRR_MSG_0("Whitespace missing after request method in HTTP request\n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	RRR_FREE_IF_NOT_NULL(result->request_method_str);
	if (__rrr_http_parse_allocate_string (&result->request_method_str, start, space) != 0) {
		RRR_MSG_0("Could not allocate string for request method in __rrr_http_parse_request \n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
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

	RRR_FREE_IF_NOT_NULL(result->request_uri);
	if (__rrr_http_parse_allocate_string (&result->request_uri, start, space) != 0) {
		RRR_MSG_0("Could not allocate string for uri in __rrr_http_parse_request \n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	start += space - start;
	start += rrr_http_util_count_whsp(start, end);

	const char *start_orig = start;

	rrr_length protocol_length = 0;
	if ((ret = rrr_http_util_strcasestr(&start, &protocol_length, start, crlf, "HTTP/1.1")) != 0 || start != start_orig) {
		if (	rrr_http_util_strcasestr(&start, &protocol_length, start, crlf, "HTTP/0.9") ||
				rrr_http_util_strcasestr(&start, &protocol_length, start, crlf, "HTTP/1.0") ||
				rrr_http_util_strcasestr(&start, &protocol_length, start, crlf, "HTTP/2.0")
		) {
			result->response_code = RRR_HTTP_RESPONSE_CODE_VERSION_NOT_SUPPORTED;
		}
		else {
			result->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
		}
		RRR_MSG_0("Invalid or missing protocol version in HTTP request\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// Must be set when everything is complete
	result->parsed_protocol_version = RRR_HTTP_PART_PROTOCOL_VERSION_1_1;

	start += protocol_length;
	// We are generous, allow spaces after protocol version
	start += rrr_http_util_count_whsp(start, end);

	*parsed_bytes = (crlf - (buf + start_pos) + 2);

	out:
	return ret;
}

static const char *__rrr_http_parse_get_first_position (
		const char *a,
		const char *b,
		const char *c,
		const char *crlf_never_null
) {
	const char *first = crlf_never_null;

	if (a != NULL) {
		first = a;
	}
	if (b != NULL && b < first) {
		first = b;
	}
	if (c != NULL && c < first) {
		first = c;
	}

	return first;
}

static int __rrr_http_parse_header_field_subvalue (
		struct rrr_http_field_collection *target_list,
		ssize_t *parsed_bytes,
		const char *start_orig,
		const char *end,
		int field_flags,
		int no_whitespace_check
) {
	int ret = 0;

	*parsed_bytes = 0;

	struct rrr_http_field *subvalue = NULL;

	const char *start = start_orig;

	const char *crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	if (*start == ';' || *start == ',') {
		start++;
	}

	// New value always begins with spaces, except for in bad implementations
	if (!no_whitespace_check) {
		ssize_t whitespace_count = rrr_http_util_count_whsp(start, crlf);
		if (whitespace_count == 0) {
			// No more values
			*parsed_bytes = start - start_orig;
			return RRR_HTTP_PARSE_OK;
		}

		start += whitespace_count;
	}

	const char *comma = NULL;
	const char *equal = NULL;
	const char *semicolon = NULL;

	if ((field_flags & RRR_HTTP_HEADER_FIELD_NO_PAIRS) == 0) {
		equal = rrr_http_util_strchr(start, crlf, '=');
		semicolon = rrr_http_util_strchr(start, crlf, ';');
	}

	if ((field_flags & RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE) != 0) {
		comma = rrr_http_util_strchr(start, crlf, ',');
	}

	const char *name_end = __rrr_http_parse_get_first_position(comma, semicolon, equal, crlf);

	ssize_t name_length = name_end - start;
	if (name_length <= 0) {
		RRR_MSG_0("No name found while parsing subvalues of HTTP header field\n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_http_field_new_no_value(&subvalue, start, name_length) != 0) {
		RRR_MSG_0("Could not allocate field in __rrr_http_parse_header_field_subvalue\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	RRR_DBG_3("\tsubvalue name: %s\n", subvalue->name);

	if (name_end == crlf) {
		start = name_end + 2;
		goto no_value;
	}
	else if (name_end == comma || name_end == semicolon) {
		start = name_end;
		goto no_value;
	}
	else {
		start = name_end + 1 + rrr_http_util_count_whsp(name_end, crlf);
	}

	if (start >= crlf) {
		RRR_MSG_0("Could not find value after = while parsing subvalues of HTTP header field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// TODO : This method to find value end is naive, need to parse quoted values correctly

	const char *value_end = __rrr_http_parse_get_first_position(comma, semicolon, NULL, crlf);
	ssize_t value_length = value_end - start;

	if (rrr_http_field_set_value(subvalue, start, value_length) != 0) {
		RRR_MSG_0("Could not allocate memory for value in __rrr_http_parse_header_field_subvalue\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

//	printf ("\tsubvalue value: %s\n", subvalue->value);

	start += value_length;

	no_value:
	RRR_LL_APPEND(target_list, subvalue);
	subvalue = NULL;

	// Don't parse the last character, needs to be checked by caller
	*parsed_bytes = (start - start_orig);

	out:
	if (subvalue != NULL) {
		rrr_http_field_destroy(subvalue);
	}
	return ret;
}

static int __rrr_http_parse_header_field (
		struct rrr_http_header_field_collection *target_list,
		ssize_t *parsed_bytes,
		const char *start_orig,
		const char *end
) {
	int ret = 0;
	struct rrr_http_header_field *field = NULL;
	const char *start = start_orig;

	*parsed_bytes = 0;

	// NOTE : Be very careful with choosing to parse up to CRLF or END.
	//        We sometimes search for content up to CRLF and sometimes END (allowing CRLF in between).

	const char *crlf = NULL;
	int bad_client_missing_space_after_comma = 0;

	// >>>> Duplicate field goto target
	do_duplicate_field:

	bad_client_missing_space_after_comma = 0;

	crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	if (field == NULL) {
		const char *colon = rrr_http_util_strchr(start, crlf, ':');
		if (colon == NULL) {
			RRR_MSG_0("Colon not found in HTTP header field in __rrr_http_parse_header_field\n");
			rrr_http_util_print_where_message(start, end);
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}

		if (__rrr_http_header_field_new(&field, start, colon - start) != 0) {
			ret = RRR_HTTP_PARSE_HARD_ERR;
			goto out;
		}

		start = colon + 1;

		RRR_DBG_3("parsing field with name: %s\n", field->name);
	}
	else {
		const char *old_name = field->name;
		size_t old_name_length = strlen(field->name);

		// Field is already added to list, make sure it is not freed if we get an error
		field = NULL;

		if (__rrr_http_header_field_new(&field, old_name, old_name_length) != 0) {
			ret = RRR_HTTP_PARSE_HARD_ERR;
			goto out;
		}

		if (*start == ',') {
			start++;
		}

		if (start >= end) {
			ret = RRR_HTTP_PARSE_INCOMPLETE;
			goto out;
		}

		if (rrr_http_util_count_whsp(start, end) == 0) {
			bad_client_missing_space_after_comma = 1;
		}

		RRR_DBG_3("parsing duplicate field with name: %s\n", field->name);
	}

	if (start >= crlf) {
		RRR_MSG_0("No value for header field in __rrr_http_parse_header_field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	ssize_t whitespace_count = rrr_http_util_count_whsp(start, crlf);

	if (start + whitespace_count == crlf) {
		// Continue on next line
		start = crlf + 2;
		crlf = NULL;
	}
	else if (whitespace_count == 0) {
		if (bad_client_missing_space_after_comma) {
			if (RRR_DEBUGLEVEL_1) {
				RRR_MSG_0("Warning: No whitespace after comma while parsing HTTP header field subvalues\n");
				rrr_http_util_print_where_message(start, end);
			}
		}
		else {
			RRR_MSG_0("Error: No whitespace after separator while parsing HTTP header field subvalues\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}
	}

	crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	int prev_subvalue_count = 0;
	int comma_found_do_duplicate_field = 0;

	do {
		prev_subvalue_count = RRR_LL_COUNT(&field->fields);

		ssize_t parsed_bytes_tmp = 0;
		RRR_DBG_3("subvalue start: %c\n", *start);
		if ((ret = __rrr_http_parse_header_field_subvalue (
				&field->fields,
				&parsed_bytes_tmp,
				start,
				end,
				(field->definition != NULL ? field->definition->flags : 0),
				bad_client_missing_space_after_comma
		)) != 0) {
			goto out;
		}
		start += parsed_bytes_tmp;

		bad_client_missing_space_after_comma = 0;

		if (start >= end) {
			ret = RRR_HTTP_PARSE_INCOMPLETE;
			goto out;
		}

		if (*start == ';') {
			const char *next = start + 1;
			if (next >= end) {
				ret = RRR_HTTP_PARSE_INCOMPLETE;
				goto out;
			}
			if (*next != ' ' && *next != '\t' && *next != '\r') {
				bad_client_missing_space_after_comma = 1;
			}
			if (*next == ',') {
				if (RRR_DEBUGLEVEL_1) {
					RRR_MSG_0("Warning: Comma found after semicolon in HTTP header, bad implementation\n");
					rrr_http_util_print_where_message(start, end);
				}
				start++;
			}
		}

		if (*start == ',') {
			comma_found_do_duplicate_field = 1;
			break;
		}
	} while (prev_subvalue_count != RRR_LL_COUNT(&field->fields));

	// Allow comma and no subvalues?
/*		if (RRR_LL_COUNT(&field->fields) == 0) {
		RRR_MSG_0("No values found after semicolon while parsing HTTP header field subvalues\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}*/

	if (field->definition != NULL && field->definition->parse != NULL && field->definition->parse(field) != 0) {
		RRR_MSG_0("Could not parse field '%s' in __rrr_http_parse_header_field\n", field->name);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	RRR_LL_APPEND(target_list, field);

	if (comma_found_do_duplicate_field) {
		goto do_duplicate_field;
	}

	field = NULL;
	*parsed_bytes = (start - start_orig);

	out:
	if (field != NULL) {
		__rrr_http_header_field_destroy(field);
	}
	return ret;
}

static struct rrr_http_chunk *__rrr_http_part_chunk_new (
		rrr_length chunk_start,
		rrr_length chunk_length
) {
	struct rrr_http_chunk *new_chunk = malloc(sizeof(*new_chunk));
	if (new_chunk == NULL) {
		RRR_MSG_0("Could not allocate memory for chunk in __rrr_http_part_append_chunk\n");
		return NULL;
	}

	memset(new_chunk, '\0', sizeof(*new_chunk));

	new_chunk->start = chunk_start;
	new_chunk->length = chunk_length;

	return new_chunk;
}

static int __rrr_http_part_parse_chunk_header (
		struct rrr_http_chunk **result_chunk,
		size_t *parsed_bytes,
		const char *buf,
		size_t start_pos,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

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

		rrr_length parsed_bytes_tmp = 0;
		if ((ret = rrr_http_util_strtoull(&chunk_length, &parsed_bytes_tmp, pos, crlf, 16)) != 0) {
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

		if ((ret = __rrr_http_parse_header_field(target, &parsed_bytes_tmp, pos, end)) != 0) {
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
		RRR_MSG_0("Error while parsing last_chunk header in rrr_http_part_parse\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}

int rrr_http_part_header_field_push (
		struct rrr_http_part *part,
		const char *name,
		const char *value
) {
	int ret = 0;

	struct rrr_http_header_field *field = NULL;

	if ((ret = __rrr_http_header_field_new(&field, name, strlen(name))) != 0) {
		RRR_MSG_0("Could not create header field in rrr_http_part_push_header_field\n");
		goto out;
	}

	if ((field->value = strdup(value)) == NULL) {
		RRR_MSG_0("Could not allocate memory for value in rrr_http_part_push_header_field\n");
		goto out_destroy;
	}

	RRR_LL_APPEND(&part->headers, field);
	field = NULL;

	goto out;
	out_destroy:
		__rrr_http_header_field_destroy(field);
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
		if (strcasecmp(field, node->name) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&part->headers, 0; __rrr_http_header_field_destroy(node));
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
		rrr_http_part_dump_header(part);
	}

	if (RRR_LL_COUNT(&part->chunks) == 0) {
		ret = callback(0, 1, data_start, data_end - data_start, callback_arg);
		goto out;
	}

	int i = 0;
	int chunks_total = RRR_LL_COUNT(&part->chunks);

	RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
		const char *data_start = data_ptr + node->start;

		if (data_start + node->length > data_end) {
			RRR_BUG("Chunk end overrun in __rrr_http_session_receive_callback\n");
		}

		// NOTE : Length might be 0
		if ((ret = callback(i, chunks_total, data_start, node->length, callback_arg)) != 0) {
			goto out;
		}

		i++;
	RRR_LL_ITERATE_END();

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

//	printf ("Parse part at: %s\n", data_ptr + start_pos);

//	static int run_count = 0;
//	printf ("Run count: %i pos %i\n", ++run_count, start_pos);

	*target_size = 0;
	*parsed_bytes = 0;

	size_t parsed_bytes_tmp = 0;
	size_t parsed_bytes_total = 0;

	if (part->is_chunked == 1) {
		goto parse_chunked;
	}

	if (part->parsed_protocol_version == 0 && parse_type != RRR_HTTP_PARSE_MULTIPART) {
		if (parse_type == RRR_HTTP_PARSE_REQUEST) {
			ret = __rrr_http_parse_request (
					part,
					&parsed_bytes_tmp,
					data_ptr,
					start_pos + parsed_bytes_total,
					end
			);
		}
		else if (parse_type == RRR_HTTP_PARSE_RESPONSE) {
			ret = __rrr_http_parse_response_code (
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

		if (ret != RRR_HTTP_PARSE_OK) {
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

	if (part->header_complete == 0) {
		ret = __rrr_http_part_parse_header_fields (
				&part->headers,
				&parsed_bytes_tmp,
				data_ptr,
				start_pos + parsed_bytes_total,
				end
		);

		parsed_bytes_total += parsed_bytes_tmp;

		// Make sure the maths are done correctly. Header may be partially parsed in a previous round,
		// we need to figure out the header length using the current parsing position
//		result->header_length = start_pos + parsed_bytes_total - part->headroom_length;
		part->header_length += parsed_bytes_tmp;

//		printf("header length %p: %li + %li = %li\n",
//				result, parsed_bytes_total - parsed_bytes_tmp, parsed_bytes_tmp, part->header_length);

		if (ret != RRR_HTTP_PARSE_OK) {
			goto out;
		}

		part->header_complete = 1;

		const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(part, "content-type");
		const struct rrr_http_header_field *content_length = rrr_http_part_header_field_get(part, "content-length");
		const struct rrr_http_header_field *transfer_encoding = rrr_http_part_header_field_get(part, "transfer-encoding");

		if (parse_type == RRR_HTTP_PARSE_REQUEST) {
			RRR_DBG_3("HTTP request header parse complete\n");

			if (part->request_method_str == NULL) {
				RRR_BUG("Request method not set in rrr_http_part_parse after header completed\n");
			}

			if (part->request_method != 0) {
				RRR_BUG("Numeric request method was non zero in rrr_http_part_parse\n");
			}

			if (rrr_posix_strcasecmp(part->request_method_str, "GET") == 0) {
				part->request_method = RRR_HTTP_METHOD_GET;
			}
			else if (rrr_posix_strcasecmp(part->request_method_str, "OPTIONS") == 0) {
				part->request_method = RRR_HTTP_METHOD_OPTIONS;
			}
			else if (rrr_posix_strcasecmp(part->request_method_str, "POST") == 0) {
				part->request_method = RRR_HTTP_METHOD_POST_APPLICATION_OCTET_STREAM;

				if (content_type != NULL) {
					if (rrr_posix_strcasecmp(content_type->name, "multipart/form-data")) {
						part->request_method = RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA;
					}
					else if (rrr_posix_strcasecmp(content_type->name, "application/x-www-form-urlencoded")) {
						part->request_method = RRR_HTTP_METHOD_POST_URLENCODED;
					}
					else if (rrr_posix_strcasecmp(content_type->name, "text/plain")) {
						part->request_method = RRR_HTTP_METHOD_POST_TEXT_PLAIN;
					}
				}
			}
			else if (rrr_posix_strcasecmp(part->request_method_str, "PUT") == 0) {
				part->request_method = RRR_HTTP_METHOD_PUT;
			}
			else if (rrr_posix_strcasecmp(part->request_method_str, "HEAD") == 0) {
				part->request_method = RRR_HTTP_METHOD_HEAD;
			}
			else if (rrr_posix_strcasecmp(part->request_method_str, "DELETE") == 0) {
				part->request_method = RRR_HTTP_METHOD_DELETE;
			}
			else {
				RRR_MSG_0("Unknown request method '%s' in HTTP request\n", part->request_method_str);
				part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
				ret = RRR_HTTP_PARSE_SOFT_ERR;
				goto out;
			}

			if (part->request_method == RRR_HTTP_METHOD_GET ||
				part->request_method == RRR_HTTP_METHOD_OPTIONS ||
				part->request_method == RRR_HTTP_METHOD_HEAD ||
				part->request_method == RRR_HTTP_METHOD_DELETE
			) {
				if (content_length != NULL && content_length->value_unsigned != 0) {
					RRR_MSG_0("Content-Length was non-zero for GET, HEAD, DELETE or OPTIONS request, this is an error.\n");
					part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
					ret = RRR_HTTP_PARSE_SOFT_ERR;
					goto out;
				}

				if (transfer_encoding != NULL) {
					RRR_MSG_0("Transfer-Encoding header was set for GET, HEAD, DELETE or OPTIONS request, this is an error.\n");
					part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
					ret = RRR_HTTP_PARSE_SOFT_ERR;
					goto out;
				}

				if (content_type != NULL) {
					RRR_MSG_0("Content-Type was set for GET, HEAD, DELETE or OPTIONS request, this is an error.\n");
					part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
					ret = RRR_HTTP_PARSE_SOFT_ERR;
					goto out;
				}
			}
		}
		else {
			RRR_DBG_3("HTTP header parse complete, response was %i\n", part->response_code);
		}

		if (content_length != NULL) {
			part->data_length = content_length->value_unsigned;
			*target_size = part->headroom_length + part->header_length + content_length->value_unsigned;

			RRR_DBG_3("HTTP content length found: %llu (plus response %li and header %li) target size is %li\n",
					content_length->value_unsigned, part->headroom_length, part->header_length, *target_size);

			ret = RRR_HTTP_PARSE_OK;

			goto out;
		}
		else if (transfer_encoding != NULL && rrr_posix_strcasecmp(transfer_encoding->value, "chunked") == 0) {
			if (parse_type == RRR_HTTP_PARSE_MULTIPART) {
				RRR_MSG_0("Chunked transfer encoding found in HTTP multipart body, this is not allowed\n");
				part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}
			part->is_chunked = 1;
			RRR_DBG_3("HTTP chunked transfer encoding specified\n");
			goto parse_chunked;
		}
		else {
			if (parse_type == RRR_HTTP_PARSE_REQUEST || part->response_code == 204) {
				// No content
				part->data_length = 0;
				*target_size = parsed_bytes_total;
				ret = RRR_HTTP_PARSE_OK;
			}
			else {
				// Unknown size, parse until connection closes
				part->data_length_unknown = 1;
				*target_size = 0;
				ret = RRR_HTTP_PARSE_INCOMPLETE;
			}
			goto out;
		}
	}

	goto out;
	parse_chunked:

	ret = __rrr_http_part_parse_chunk (
			&part->chunks,
			&parsed_bytes_tmp,
			data_ptr,
			start_pos + parsed_bytes_total,
			end
	);

	parsed_bytes_total += parsed_bytes_tmp;

	if (ret == RRR_HTTP_PARSE_OK) {
		if (RRR_LL_LAST(&part->chunks)->length != 0) {
			RRR_BUG("BUG: __rrr_http_part_parse_chunk return OK but last chunk length was not 0 in rrr_http_part_parse\n");
		}

		// Part length is position of last chunk plus CRLF minus header and response code
		part->data_length = RRR_LL_LAST(&part->chunks)->start + 2 - part->header_length - part->headroom_length;

		// Target size is total length from start of session to last chunk plus CRLF
		*target_size = RRR_LL_LAST(&part->chunks)->start + 2;
	}

	out:
	*parsed_bytes = parsed_bytes_total;
	return ret;
}

static int __rrr_http_part_find_boundary (
		const char **result,
		const char *start,
		const char *end,
		const char *boundary,
		size_t boundary_length
) {
	int ret = 1;

//	printf("Looking for boundary '%s' length %li\n", boundary, boundary_length);

	const char *boundary_pos = NULL;

	while (start + 1 + boundary_length < end) {
		if (*start == '-' && *(start + 1) == '-') {
			start += 2;
			if (strncmp(start, boundary, boundary_length) == 0) {
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

static int __rrr_http_part_process_multipart_part (
		struct rrr_http_part *parent,
		const char *data_ptr,
		size_t *parsed_bytes,
		int *end_found,
		const char *start_orig,
		const char *end,
		const char *boundary,
		size_t boundary_length
) {
	int ret = RRR_HTTP_PARSE_OK;

	*parsed_bytes = 0;
	*end_found = 0;

	struct rrr_http_part *new_part = NULL;
	struct rrr_thread_double_pointer new_part_cleanup_ptr = { (void**) &new_part };

	// We do this here due to our recursive nature and to avoid
	// leaking memory upon a potential pthread_cancel
	pthread_cleanup_push(rrr_http_part_destroy_void_double_ptr, &new_part_cleanup_ptr);

	const char *start = start_orig;
	const char *crlf = NULL;
	const char *boundary_pos = NULL;

	if (__rrr_http_part_find_boundary(&boundary_pos, start, end, boundary, boundary_length) != 0) {
		RRR_MSG_0("Could not find boundary while looking for part begin in HTTP multipart request\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	// 4 bytes are OK, thats the previous -- and CRLF
	if (boundary_pos - start > 4) {
		RRR_DBG_1("Warning: HTTP multipart request contains some data before boundary, %li bytes\n", boundary_pos - start);
	}

	start = boundary_pos + boundary_length;

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
	if (__rrr_http_part_find_boundary(&boundary_pos, start, end, boundary, boundary_length) != 0) {
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
		rrr_http_part_dump_header(new_part);
	}

	if ((ret = rrr_http_part_process_multipart(new_part, data_ptr)) != 0) {
		RRR_MSG_0("Error while processing sub-multipart in HTTP multipart request\n");
		goto out;
	}

	RRR_LL_APPEND(parent, new_part);
	new_part = NULL;

	*parsed_bytes = boundary_pos - start_orig;

	out:
		pthread_cleanup_pop(1);
		return ret;
}

int rrr_http_part_process_multipart (
		struct rrr_http_part *part,
		const char *data_ptr
) {
	int ret = RRR_HTTP_PARSE_OK;

	if (!__rrr_http_part_check_content_type(part, "multipart/form-data")) {
		goto out;
	}

	if (part->request_method == RRR_HTTP_METHOD_GET) {
		RRR_MSG_0("Received multipart message in GET request which is not a valid combination\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	const struct rrr_http_field *boundary = __rrr_http_part_header_field_subvalue_get(part, "content-type", "boundary");
	if (boundary == NULL || boundary->value == NULL || *(boundary->value) == '\0') {
		RRR_MSG_0("No multipart boundary found in content-type of HTTP header\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}


	const char *boundary_str = boundary->value;

	ssize_t boundary_length = boundary->value_size;
	if (boundary_length == 0) {
		RRR_MSG_0("Boundary too short while parsing HTTP multipart body\n");
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

		if ((ret = __rrr_http_part_process_multipart_part (
				part,
				data_ptr,
				&parsed_bytes_tmp,
				&end_found,
				data_start,
				data_end,
				boundary_str,
				boundary_length
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

static int __rrr_http_part_parse_query_string (
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
		RRR_MSG_0("Could not allocate memory for buffer in rrr_http_part_parse_query_string\n");
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
				RRR_BUG("Result after converting %%-sequence too big in rrr_http_part_parse_query_string\n");
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
				RRR_MSG_0("Could not set value in rrr_http_part_parse_query_string\n");
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
					RRR_MSG_0("Could not allocate new field in rrr_http_part_parse_query_string\n");
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

static int __rrr_http_part_extract_query_fields_from_uri (
		struct rrr_http_part *target
) {
	int ret = 0;

	const char *query_end = target->request_uri + strlen(target->request_uri);
	const char *query_start = strchr(target->request_uri, '?');

	if (query_start == NULL) {
		ret = 0;
		goto out;
	}

	// Skip ?
	query_start++;

	if (strlen(query_start) == 0) {
		goto out;
	}

	if ((ret = __rrr_http_part_parse_query_string (&target->fields, query_start, query_end)) != 0) {
		RRR_MSG_0("Error while parsing query string in __rrr_http_part_extract_query_fields_from_uri\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_http_part_extract_post_and_query_fields (
		struct rrr_http_part *target,
		const char *data_ptr
) {
	int ret = 0;

	struct rrr_http_field *field_tmp = NULL;

	if (__rrr_http_part_check_content_type(target, "application/x-www-form-urlencoded")) {
		RRR_HTTP_PART_DECLARE_DATA_START_AND_END(target, data_ptr);

		if ((ret = __rrr_http_part_parse_query_string (&target->fields, data_start, data_end)) != 0) {
			RRR_MSG_0("Error while parsing query string in rrr_http_part_extract_post_and_query_fields\n");
			goto out;
		}
	}
	else if (__rrr_http_part_check_content_type(target, "multipart/form-data")) {
		RRR_LL_ITERATE_BEGIN(target, struct rrr_http_part);
			RRR_HTTP_PART_DECLARE_DATA_START_AND_END(node, data_ptr);

			const struct rrr_http_field *field_name = __rrr_http_part_header_field_subvalue_get(node, "content-disposition", "name");
			if (field_name == NULL || field_name->value == NULL || field_name->value_size == 0) {
				RRR_DBG_1("Warning: Unknown field or invalid content-disposition of multipart part\n");
				RRR_LL_ITERATE_NEXT();
			}

			if ((ret = rrr_http_field_new_no_value(&field_tmp, field_name->value, field_name->value_size)) != 0) {
				RRR_MSG_0("Could not create new field in rrr_http_part_extract_post_and_query_fields\n");
				goto out;
			}

			if ((ret = rrr_http_field_set_value(field_tmp, data_start, data_end - data_start)) != 0) {
				RRR_MSG_0("Could not set value of field in rrr_http_part_extract_post_and_query_fields\n");
				goto out;
			}

			const struct rrr_http_header_field *field_content_type = rrr_http_part_header_field_get(node, "content-type");

			if (field_content_type != NULL && field_content_type->value != NULL) {
				if ((ret = rrr_http_field_set_content_type(
						field_tmp,
						field_content_type->value
				)) != 0) {
					RRR_MSG_0("Could not set content type of field in rrr_http_part_extract_post_and_query_fields\n");
					goto out;
				}
			}

			RRR_LL_APPEND(&target->fields, field_tmp);
			field_tmp = NULL;
		RRR_LL_ITERATE_END();
	}

	if ((ret =  __rrr_http_part_extract_query_fields_from_uri(target)) != 0) {
		goto out;
	}

	out:
	if (field_tmp != NULL) {
		rrr_http_field_destroy(field_tmp);
	}
	return ret;
}

int rrr_http_part_merge_chunks (
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
		RRR_MSG_0("Could not allocate memory in rrr_http_part_merge_chunks\n");
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

static void __rrr_http_part_dump_header_field (
		struct rrr_http_header_field *field
) {
	printf ("%s: unsigned %llu - signed %lli - raw '%s'\n",
			field->name, field->value_unsigned, field->value_signed, field->value);

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		printf("\t%s: %" PRIrrrl " bytes\n", node->name, node->value_size);
	RRR_LL_ITERATE_END();
}

void rrr_http_part_dump_header (
		struct rrr_http_part *part
) {
	printf ("== DUMP HTTP PART HEADER ====================================\n");
	RRR_LL_ITERATE_BEGIN(&part->headers, struct rrr_http_header_field);
		__rrr_http_part_dump_header_field(node);
	RRR_LL_ITERATE_END();
	printf ("== DUMP HTTP PART HEADER END ================================\n");
}
