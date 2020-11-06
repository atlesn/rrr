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
#include "http_header_fields.h"
#include "http_common.h"
#include "http_util.h"
#include "../util/base64.h"

static int __rrr_http_header_parse_verify_single_value (struct rrr_http_header_field *field) {
	if (!rrr_nullsafe_str_isset(field->name)) {
		RRR_BUG("BUG: Name not set for header field in __rrr_http_header_parse_verify_single_value\n");
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);

	if (RRR_LL_COUNT(&field->fields) == 0) {
		RRR_MSG_0("No values found for HTTP header field '%s'\n", name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	if (RRR_LL_COUNT(&field->fields) > 1) {
		RRR_MSG_0("Multiple values not allowed for HTTP header field '%s'\n", name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	if (rrr_nullsafe_str_isset(RRR_LL_FIRST(&field->fields)->value)) {
		RRR_MSG_0("name=value pair not valid for HTTP header field '%s'\n", name);
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
			subvalue->name->str,
			subvalue->name->str + subvalue->name->len,
			10
	)) != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
		RRR_MSG_0("Could not get value from field '%s'\n", name);
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

	if (rrr_nullsafe_str_dup (&field->value, subvalue->name) != 0) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_parse_string_value\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_header_parse_base64_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = 0;

	void *base64_data = NULL;
	size_t base64_len = 0;

	if ((ret = __rrr_http_header_parse_single_string_value(field)) != 0) {
		goto out;
	}

	if (rrr_nullsafe_str_isset(field->binary_value_nullsafe)) {
		RRR_BUG("BUG: binary_value was not NULL in __rrr_http_header_parse_base64_value\n");
	}

	if ((base64_data = rrr_base64_decode (
			field->value->str,
			field->value->len,
			&base64_len
	)) == NULL) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
		RRR_MSG_0("Base64 decoding failed for field '%s'\n", name);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_nullsafe_str_new(&field->binary_value_nullsafe, NULL, 0)) != 0) {
		RRR_MSG_0("Failed to allocate memory in __rrr_http_header_parse_base64_value\n");
		goto out;
	}

	rrr_nullsafe_str_set_allocated(field->binary_value_nullsafe, &base64_data, base64_len);

	out:
	RRR_FREE_IF_NOT_NULL(base64_data);
	return ret;
}

static int __rrr_http_header_parse_first_string_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = RRR_HTTP_PARSE_OK;

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);

	if (RRR_LL_COUNT(&field->fields) == 0) {
		RRR_MSG_0("No value found for HTTP header field '%s'\n", name);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_nullsafe_str_isset(RRR_LL_FIRST(&field->fields)->value)) {
		RRR_MSG_0("name=value pair not valid for HTTP header field '%s' first value\n", name);
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	struct rrr_http_field *subvalue = RRR_LL_FIRST(&field->fields);

	if (field->value != NULL) {
		RRR_BUG("BUG: value was not NULL in __rrr_http_header_parse_first_string_value\n");
	}

	if (rrr_nullsafe_str_dup (&field->value, subvalue->name) != 0) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_parse_first_string_value\n");
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
		if (rrr_nullsafe_str_cmpto_case(field->name, names_match[i]) == 0) {
			*found = 1;
			break;
		}
	}

	if (*found == 0) {
		return;
	}

	if (!rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: value was NULL in __rrr_http_header_parse_unquote_fields\n");
	}

	rrr_length output_size = 0;
	if (rrr_http_util_unquote_string(&output_size, field->value) != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->value);
		RRR_DBG_1("Warning: Syntax error in '%s' subvalue field of '%s' in HTTP header\n",
				name, parent_field_name);
		return;
	}
	field->value->len = output_size;

	if (rrr_http_util_decode_urlencoded_string(&output_size, field->value) != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->value);
		RRR_DBG_1("Warning: Error while decoding url encoding of '%s' subvalue field of '%s' in HTTP header\n",
				name, parent_field_name);
		return;
	}
	field->value->len = output_size;
}

static int __rrr_http_header_parse_content_type_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = 0;

	if ((ret = __rrr_http_header_parse_first_string_value(field)) != 0) {
		goto out;
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		int found = 0;
		const char *unquote_field_names[] = {"charset", "boundary"};
		__rrr_http_header_parse_unquote_fields(&found, node, name, unquote_field_names, 2);
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_http_header_parse_content_disposition_value (RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION) {
	int ret = 0;

	if ((ret = __rrr_http_header_parse_first_string_value(field)) != 0) {
		goto out;
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(parent_name,field->name);

	RRR_LL_ITERATE_BEGIN(&field->fields, struct rrr_http_field);
		if (RRR_LL_FIRST(&field->fields) == node) {
			if (rrr_nullsafe_str_cmpto_case(node->name, "form-data") != 0 &&
					rrr_nullsafe_str_cmpto_case(node->name, "attachment") != 0 &&
					rrr_nullsafe_str_cmpto_case(node->name, "inline") != 0
			) {
				RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(node_name,node->name);
				RRR_DBG_1("Warning: Unknown content-disposition type '%s'\n", node_name);
				RRR_LL_ITERATE_BREAK();
			}
			RRR_LL_ITERATE_NEXT();
		}

		if (!rrr_nullsafe_str_isset(node->value)) {
			RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(node_name,node->name);
			RRR_DBG_1("Warning: Empty field '%s' in content-disposition\n", node_name);
			RRR_LL_ITERATE_NEXT();
		}

		int found = 0;
		const char *unquote_field_names[] = {"name", "filename"};
		__rrr_http_header_parse_unquote_fields(&found, node, parent_name, unquote_field_names, 2);
		if (found == 0) {
			RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(node_name,node->name);
			RRR_DBG_1("Warning: Unknown field '%s' in content-disposition header\n", node_name);
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
		{"connection",			RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE,	__rrr_http_header_parse_single_string_value},
		{"upgrade",				RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_single_string_value},
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
		{"sec-websocket-key",	RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_base64_value},
		{"sec-websocket-accept",RRR_HTTP_HEADER_FIELD_NO_PAIRS,			__rrr_http_header_parse_base64_value},
		{"sec-websocket-version",RRR_HTTP_HEADER_FIELD_NO_PAIRS,		__rrr_http_header_parse_single_string_value},
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

void rrr_http_header_field_destroy (
		struct rrr_http_header_field *field
) {
	rrr_http_field_collection_clear(&field->fields);
	rrr_nullsafe_str_destroy_if_not_null(field->name);
	rrr_nullsafe_str_destroy_if_not_null(field->binary_value_nullsafe);
	rrr_nullsafe_str_destroy_if_not_null(field->value);
	free (field);
}

void rrr_http_header_field_collection_clear (
		struct rrr_http_header_field_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_http_header_field, rrr_http_header_field_destroy(node));
}

int rrr_http_header_field_new (
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

	if ((rrr_nullsafe_str_new(&field->name, field_name, field_name_len)) != 0) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_header_field_new\n");
		ret = 1;
		goto out;
	}

	rrr_nullsafe_str_tolower(field->name);

	*result = field;
	field = NULL;

	out:
	if (field != NULL) {
		rrr_http_header_field_destroy(field);
	}

	return ret;
}

static const char *__rrr_http_header_field_parse_get_first_position (
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

static int __rrr_http_header_field_subvalue_parse (
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
		printf("subvalue no crlf\n");
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
			printf("subvalue no more values\n");
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

	const char *name_end = __rrr_http_header_field_parse_get_first_position(comma, semicolon, equal, crlf);

	ssize_t name_length = name_end - start;
	if (name_length <= 0) {
		RRR_MSG_0("No name found while parsing subvalues of HTTP header field\n");
		rrr_http_util_print_where_message(start, end);
		ret = RRR_HTTP_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_http_field_new_no_value(&subvalue, start, name_length) != 0) {
		RRR_MSG_0("Could not allocate field in __rrr_http_header_field_subvalue_parse\n");
		ret = RRR_HTTP_PARSE_HARD_ERR;
		goto out;
	}

	{
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,subvalue->name);
		RRR_DBG_3("\tsubvalue name: %s\n", name);
	}

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

	const char *value_end = __rrr_http_header_field_parse_get_first_position(comma, semicolon, NULL, crlf);
	ssize_t value_length = value_end - start;

	if (rrr_http_field_set_value(subvalue, start, value_length) != 0) {
		RRR_MSG_0("Could not allocate memory for value in __rrr_http_header_field_subvalue_parse\n");
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

static int __rrr_http_header_field_parse_subvalues (
		ssize_t *parsed_bytes,
		int *comma_found_do_duplicate_field,
		struct rrr_http_header_field *field,
		const char *start,
		const char *end,
		int bad_client_missing_space_after_comma
) {
	int ret = 0;

	const char *start_orig = start;

	*parsed_bytes = 0;
	*comma_found_do_duplicate_field = 0;

	int prev_subvalue_count = 0;

	do {
		prev_subvalue_count = RRR_LL_COUNT(&field->fields);

		ssize_t parsed_bytes_tmp = 0;
		RRR_DBG_3("subvalue start: %c bad client: %i\n", *start, bad_client_missing_space_after_comma);
		if ((ret = __rrr_http_header_field_subvalue_parse (
				&field->fields,
				&parsed_bytes_tmp,
				start,
				end,
				(field->definition != NULL ? field->definition->flags : 0),
				bad_client_missing_space_after_comma
		)) != 0) {
			return ret;
		}
		start += parsed_bytes_tmp;

		bad_client_missing_space_after_comma = 0;

		if (start >= end) {
			return RRR_HTTP_PARSE_INCOMPLETE;
		}

		if (*start == ';') {
			const char *next = start + 1;
			if (next >= end) {
				return RRR_HTTP_PARSE_INCOMPLETE;
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
			*comma_found_do_duplicate_field = 1;
			break;
		}
	} while (prev_subvalue_count != RRR_LL_COUNT(&field->fields));

	*parsed_bytes = start - start_orig;

	return ret;
}

#define CALLBACK_ARGS 										\
	ssize_t *parsed_bytes,									\
	const char *start,										\
	const char *end,										\
	struct rrr_http_header_field **field,					\
	struct rrr_http_header_field_collection *fields_tmp,	\
	int *missing_space_after_comma,							\
	void *arg

#define CALL_CALLBACK(name)																		\
	do {ssize_t parsed_bytes = 0;																\
		if ((ret = name(&parsed_bytes, start, end, &field, &fields_tmp, &missing_space_after_comma, callback_arg)) != 0) { \
			goto out;																			\
		}																						\
		start += parsed_bytes;																	\
	} while(0)

static int __rrr_http_header_field_parse (
		struct rrr_http_header_field_collection *target_list,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end,
		int (*create_field)(CALLBACK_ARGS),
		int (*check_whitespace)(CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;
	const char *start_orig = start;
	struct rrr_http_header_field_collection fields_tmp = {0};
	struct rrr_http_header_field *field = NULL;

	*parsed_bytes = 0;

	int missing_space_after_comma = 0;
	int more_fields = 1;
	while (more_fields) {
		CALL_CALLBACK(create_field);

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
		RRR_DBG_3("parsing field with name: %s%s\n", name, RRR_LL_COUNT(&fields_tmp) != 0 ? " (multi-value)" : "");

		if (start >= end) {
			RRR_MSG_0("No value for HTTP header field\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}

		CALL_CALLBACK(check_whitespace);

		ssize_t subvalues_parsed_bytes = 0;
		if ((ret = __rrr_http_header_field_parse_subvalues (
				&subvalues_parsed_bytes,
				&more_fields,
				field,
				start,
				end,
				missing_space_after_comma
		)) != 0) {
			if (ret != RRR_HTTP_PARSE_INCOMPLETE) {
				RRR_MSG_0("Invalid syntax in HTTP header field\n");
				rrr_http_util_print_where_message(start, end);
				ret = RRR_HTTP_PARSE_SOFT_ERR;
			}
			goto out;
		}

		start += subvalues_parsed_bytes;

		if (field->definition != NULL && field->definition->parse != NULL && field->definition->parse(field) != 0) {
			RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
			RRR_MSG_0("Could not process HTTP header field '%s'\n", name);
			ret = RRR_HTTP_PARSE_SOFT_ERR;
			goto out;
		}

		RRR_LL_APPEND(&fields_tmp, field);
		field = NULL;
	}

	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(target_list, &fields_tmp);
	*parsed_bytes = (start - start_orig);

	out:
	if (field != NULL) {
		rrr_http_header_field_destroy(field);
	}
	RRR_LL_DESTROY(&fields_tmp, struct rrr_http_header_field, rrr_http_header_field_destroy(node));
	return ret;
}

struct rrr_http_header_field_parse_value_callback_data {
	const char *name;
};

static int __rrr_http_header_field_parse_value_create_field_callback (CALLBACK_ARGS) {
	struct rrr_http_header_field_parse_value_callback_data *callback_data = arg;

	(void)(start);
	(void)(end);
	(void)(fields_tmp);
	(void)(parsed_bytes);
	(void)(missing_space_after_comma);

	if (RRR_LL_COUNT(fields_tmp) == 0) {
		if (rrr_http_header_field_new(field, callback_data->name, strlen(callback_data->name)) != 0) {
			return RRR_HTTP_PARSE_HARD_ERR;
		}
	}
	else {
		// Duplicate field (after comma) or name from caller
	}

	return RRR_HTTP_PARSE_OK;
}

static int __rrr_http_header_field_parse_value_check_whitespace_callback (CALLBACK_ARGS) {
	struct rrr_http_header_field_parse_value_callback_data *callback_data = arg;

	(void)(callback_data);
	(void)(parsed_bytes);
	(void)(field);
	(void)(fields_tmp);
	(void)(start);
	(void)(end);

	*missing_space_after_comma = 1;

	return RRR_HTTP_PARSE_OK;
}

int rrr_http_header_field_parse_value (
		struct rrr_http_header_field_collection *target_list,
		ssize_t *parsed_bytes,
		const char *name,
		const char *value
) {
	struct rrr_http_header_field_parse_value_callback_data callback_data = {
		name
	};

	return __rrr_http_header_field_parse (
			target_list,
			parsed_bytes,
			value,
			value + strlen(value),
			__rrr_http_header_field_parse_value_create_field_callback,
			__rrr_http_header_field_parse_value_check_whitespace_callback,
			&callback_data
	);
}

static int __rrr_http_header_field_parse_name_and_value_create_field_callback (CALLBACK_ARGS) {
	(void)(missing_space_after_comma);
	(void)(arg);

	const char *start_orig = start;

	const char *crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		return RRR_HTTP_PARSE_INCOMPLETE;
	}

	if (start >= crlf) {
		RRR_MSG_0("No value for header field in __rrr_http_parse_header_field\n");
		return RRR_HTTP_PARSE_SOFT_ERR;
	}

	if (RRR_LL_COUNT(fields_tmp) == 0) {
		const char *colon = rrr_http_util_strchr(start, crlf, ':');
		if (colon == NULL) {
			RRR_MSG_0("Colon not found in HTTP header field\n");
			rrr_http_util_print_where_message(start, end);
			return RRR_HTTP_PARSE_SOFT_ERR;
		}

		if (rrr_http_header_field_new(field, start, colon - start) != 0) {
			return RRR_HTTP_PARSE_HARD_ERR;
		}

		start = colon + 1;
	}
	else {
		// Duplicate field (after comma) or name from caller
		const struct rrr_nullsafe_str *last_field_name = RRR_LL_LAST(fields_tmp)->name;

		if (rrr_http_header_field_new(field, last_field_name->str, last_field_name->len) != 0) {
			return RRR_HTTP_PARSE_HARD_ERR;
		}

		if (*start == ',') {
			start++;
		}

		if (start >= end) {
			return RRR_HTTP_PARSE_INCOMPLETE;
		}
	}

	*parsed_bytes = start - start_orig;

	return RRR_HTTP_PARSE_OK;
}

static int __rrr_http_header_field_parse_name_and_value_check_whitespace_callback (CALLBACK_ARGS) {
	(void)(field);
	(void)(fields_tmp);
	(void)(arg);

	const char *start_orig = start;

	const char *crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		return RRR_HTTP_PARSE_INCOMPLETE;
	}

	ssize_t whitespace_count = rrr_http_util_count_whsp(start, crlf);
	if (start + whitespace_count == crlf) {
		// Continue on next line
		start = crlf + 2;
		crlf = NULL;
	}
	else if (whitespace_count == 0) {
		if (RRR_DEBUGLEVEL_3) {
			RRR_MSG_3("Note: No whitespace after separator while parsing HTTP header field subvalues\n");
			rrr_http_util_print_where_message(start, end);
			*missing_space_after_comma = 1;
		}
	}

	crlf = rrr_http_util_find_crlf(start, end);
	if (crlf == NULL) {
		return RRR_HTTP_PARSE_INCOMPLETE;
	}

	*parsed_bytes = start - start_orig;

	return RRR_HTTP_PARSE_OK;
}

int rrr_http_header_field_parse_name_and_value (
		struct rrr_http_header_field_collection *target_list,
		ssize_t *parsed_bytes,
		const char *start_orig,
		const char *end
) {
	return __rrr_http_header_field_parse (
			target_list,
			parsed_bytes,
			start_orig,
			end,
			__rrr_http_header_field_parse_name_and_value_create_field_callback,
			__rrr_http_header_field_parse_name_and_value_check_whitespace_callback,
			NULL
	);
}
