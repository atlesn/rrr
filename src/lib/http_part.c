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

static int __rrr_http_header_parse_semicolon_separated (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

	return ret;
}

static int __rrr_http_header_parse_unsigned_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_OK;

	ssize_t parsed_bytes = 0;

	if ((ret = rrr_http_util_strtoull (
			&field->value_unsigned,
			&parsed_bytes,
			field->value,
			field->value + strlen(field->value)
	)) != 0) {
		VL_MSG_ERR("Could not get value from field '%s'\n", field->name);
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
		VL_MSG_ERR("Could not allocate memory in __rrr_http_header_field_new\n");
		ret = 1;
		goto out;
	}

	memset (field, '\0', sizeof(*field));

	// Might return NULL, which is OK
	field->definition = __rrr_http_header_field_get_definition(field_name, field_len);

	field->name = malloc(field_len + 1);
	if (field->name == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_http_header_field_new\n");
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

static struct rrr_http_header_field *__rrr_header_field_collection_get_field (
		struct rrr_http_header_field_collection *collection,
		const char *name_lowercase
) {
	RRR_LINKED_LIST_ITERATE_BEGIN(collection, struct rrr_http_header_field);
		if (strcmp(name_lowercase, node->name) == 0) {
			return node;
		}
	RRR_LINKED_LIST_ITERATE_END(collection);
	return NULL;
}

static void __rrr_header_field_collection_add (
		struct rrr_http_header_field_collection *collection,
		struct rrr_http_header_field *field
) {
	RRR_LINKED_LIST_APPEND(collection, field);
}

void rrr_http_part_destroy (struct rrr_http_part *part) {
	RRR_LINKED_LIST_DESTROY(part, struct rrr_http_part, rrr_http_part_destroy(node));
	RRR_LINKED_LIST_DESTROY(&part->headers, struct rrr_http_header_field, __rrr_http_header_field_destroy(node));
	RRR_FREE_IF_NOT_NULL(part->response_str);
	free (part);
}

int rrr_http_part_new (struct rrr_http_part **result) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_part *part = malloc (sizeof(*part));
	if (part == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_http_part_new\n");
		ret = 1;
		goto out;
	}

	memset (part, '\0', sizeof(*part));

	*result = part;

	out:
	return ret;
}

static int __rrr_http_parse_response_code (
		struct rrr_http_part *result,
		ssize_t *parsed_bytes,
		const char *start_orig,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_OK;

	const char *start = start_orig;
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

	if ((ret = rrr_http_util_strcasestr(&start, &tmp_len, start, crlf, "HTTP/1.1")) != 0 || start != start_orig) {
		VL_MSG_ERR("Could not understand HTTP response header/version in __rrr_http_parse_response_code\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	start += tmp_len;
	start += rrr_http_util_count_whsp(start, end);

	unsigned long long int response_code = 0;
	if ((ret = rrr_http_util_strtoull(&response_code, &tmp_len, start, crlf)) != 0 || response_code > 999) {
		VL_MSG_ERR("Could not understand HTTP response code in __rrr_http_parse_response_code\n");
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
			VL_MSG_ERR("Could not allocate memory for response string in __rrr_http_parse_response_code\n");
			goto out;
		}
		memcpy(result->response_str, start, response_str_len);
		result->response_str[response_str_len] = '\0';
	}
	else if (start > crlf) {
		VL_BUG("pos went beyond CRLF in __rrr_http_parse_response_code\n");
	}

	*parsed_bytes = (crlf - start_orig + 2);

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
		VL_MSG_ERR("Colon not found in HTTP header field in __rrr_http_parse_header_field\n");
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
		VL_MSG_ERR("No value for header field in __rrr_http_parse_header_field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	ssize_t value_len = crlf - start;
	field->value = malloc(value_len + 1);
	if (field->value == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_http_parse_header_field\n");
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}
	memcpy (field->value, start, value_len);
	field->value[value_len] = '\0';

	if (field->definition != NULL && field->definition->parse(field) != 0) {
		VL_MSG_ERR("Could not parse field '%s' in __rrr_http_parse_header_field\n", field->name);
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

int rrr_http_part_parse (
		struct rrr_http_part *result,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	int ret = RRR_HTTP_PARSE_INCOMPLETE;

	*parsed_bytes = 0;
	const char *pos = start;
	ssize_t parsed_bytes_tmp = 0;

	if (result->response_code == 0) {
		if ((ret = __rrr_http_parse_response_code(result, &parsed_bytes_tmp, pos, end)) != 0) {
			goto out;
		}
		pos += parsed_bytes_tmp;
		*parsed_bytes += parsed_bytes_tmp;
	}

	while (1) {
		const char *crlf = rrr_http_util_find_crlf(pos, end);
		if (crlf == NULL) {
			// Header incomplete, not enough data
			goto out;
		}
		else if (crlf == pos) {
			// Header complete
			result->header_complete = 1;
			pos += 2;
			*parsed_bytes += 2;
			break;
		}

		struct rrr_http_header_field *field = NULL;
		if ((ret = __rrr_http_parse_header_field(&field, &parsed_bytes_tmp, pos, end)) != 0) {
			goto out;
		}

		__rrr_header_field_collection_add(&result->headers, field);

		pos += parsed_bytes_tmp;
		*parsed_bytes += parsed_bytes_tmp;
	}

	if (result->header_complete != 0) {
		struct rrr_http_header_field *content_length = __rrr_header_field_collection_get_field(&result->headers, "content-length");
		if (content_length != NULL) {
			result->data_length = content_length->value_unsigned;
			ret = RRR_HTTP_PARSE_OK;
			goto out;
		}
		else {
			ret = RRR_HTTP_PARSE_UNTIL_CLOSE;
			goto out;
		}
	}

	out:
	return ret;
}
