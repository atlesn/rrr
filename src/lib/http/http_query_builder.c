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

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "http_query_builder.h"
#include "http_common.h"

#include "../map.h"
#include "../log.h"
#include "../allocator.h"
#include "../string_builder.h"
#include "../array.h"
#include "../fixed_point.h"
#include "../util/base64.h"
#include "../util/macro_utils.h"

int rrr_http_query_builder_init (
		struct rrr_http_query_builder *query_builder
) {
	memset(query_builder, '\0', sizeof(*query_builder));
	if (rrr_string_builder_new(&query_builder->string_builder) != 0) {
		RRR_MSG_0("Could not create string builder in rrr_http_query_builder_init\n");
		return 1;
	}
	return 0;
}

void rrr_http_query_builder_cleanup (
		struct rrr_http_query_builder *query_builder
) {
	// Call "destroy", not "clear"
	rrr_string_builder_destroy(query_builder->string_builder);
	memset(query_builder, '\0', sizeof(*query_builder));
}

static int __rrr_http_query_builder_escape_field (
		char **target,
		const char *source,
		rrr_biglength length,
		int add_double_quotes
) {
	if (length > SIZE_MAX / 2 - 1 - 2) {
		RRR_MSG_0("Input too long in __rrr_http_query_builder_escape_field (%llu>%llu)\n",
			(unsigned long long) length,
			(unsigned long long) SIZE_MAX / 2 - 1 - 2);
		return RRR_HTTP_SOFT_ERROR;
	}

	size_t new_size = length * 2 + 1 + 2;

	*target = NULL;

	char *result = rrr_allocate(new_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_query_builder_escape_field\n");
		return 1;
	}

	char *wpos = result;

	if (add_double_quotes != 0) {
		*(wpos++) = '"';
	}

	for (rrr_biglength i = 0; i < length; i++) {
		char c = *(source + i);
		if (c == '"' || (add_double_quotes == 0 && (c == ',' || c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n'))) {
			*(wpos++) = '\\';
		}
		*(wpos++) = c;
	}

	if (add_double_quotes != 0) {
		*(wpos++) = '"';
	}

	*wpos = '\0';

	*target = result;

	return 0;
}

int rrr_http_query_builder_append_type_value_as_escaped_string (
		int *value_was_empty,
		struct rrr_http_query_builder *query_builder,
		const struct rrr_type_value *value,
		int do_quote_values
) {
	struct rrr_string_builder *string_builder = query_builder->string_builder;

	int ret = RRR_HTTP_OK;

	*value_was_empty = 0;

	char *value_tmp = NULL;

	if (RRR_TYPE_IS_FIXP(value->definition->type)) {
		char buf[512];

		if ((ret = rrr_fixp_to_str_double(buf, 511, *((rrr_fixp*) value->data))) != 0) {
			RRR_MSG_0("Could not convert fixed point to string in rrr_http_query_builder_append_type_value_as_escaped_string\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, buf, "Could not append fixed point to query buffer in rrr_http_query_builder_append_type_value_as_escaped_string\n");
	}
	else if (RRR_TYPE_IS_64(value->definition->type)) {
		char buf[64];
		if (RRR_TYPE_FLAG_IS_SIGNED(value->flags)) {
			sprintf(buf, "%" PRIi64, *((int64_t*) value->data));
		}
		else {
			sprintf(buf, "%" PRIu64, *((uint64_t*) value->data));
		}

		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, buf, "Could not append 64 type to query buffer in rrr_http_query_builder_append_type_value_as_escaped_string\n");
	}
	else if (RRR_TYPE_IS_BLOB(value->definition->type)) {
		// For value with 0 length, only the tag is output with value 1
		if (value->total_stored_length > 0) {
			if (__rrr_http_query_builder_escape_field(&value_tmp, value->data, value->total_stored_length, do_quote_values) != 0) {
				RRR_MSG_0("Could not escape blob field in rrr_http_query_builder_append_type_value_as_escaped_string\n");
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}

			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, value_tmp, "Could not append blob type to query buffer in rrr_http_query_builder_append_type_value_as_escaped_string\n");
		}
		else {
			*value_was_empty = 1;
		}
	}
	else if (RRR_TYPE_IS_VAIN(value->definition->type)) {
		*value_was_empty = 1;
	}
	else {
		RRR_MSG_0("Unknown value type %u with tag '%s' while constructing HTTP query\n",
				value->definition->type, (value->tag != NULL ? value->tag : "(no tag)"));
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(value_tmp);
	return ret;
}

static int __rrr_http_query_builder_append_type_value (
		struct rrr_http_query_builder *query_builder,
		const struct rrr_type_value *value,
		const char *node_tag,
		const char *separator,
		int do_quote_values
) {
	struct rrr_string_builder *string_builder = query_builder->string_builder;

	int ret = RRR_HTTP_OK;

	char *name_escaped_tmp = NULL;

	if (node_tag == NULL || *node_tag == '\0') {
		RRR_MSG_0("Error: No tag set in rrr_http_query_builder_append_type_value\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	if (__rrr_http_query_builder_escape_field(&name_escaped_tmp, node_tag, strlen(node_tag), 0)) {
		RRR_MSG_0("Could not escape field in rrr_http_query_builder_append_values_from_array\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	if (separator != NULL && *separator != '\0') {
		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, separator, "Could not append separator to query buffer in rrr_http_query_builder_append_values_from_array\n");
	}

	RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, name_escaped_tmp, "Could not append name to query buffer in rrr_http_query_builder_append_values_from_array\n");
	RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, "=", "Could not append equal sign to query buffer in rrr_http_query_builder_append_values_from_array\n");

	int value_was_empty = 0;

	if ((ret = rrr_http_query_builder_append_type_value_as_escaped_string (
			&value_was_empty,
			query_builder,
			value,
			do_quote_values
	)) != RRR_HTTP_OK) {
		RRR_MSG_0("Error while adding value with tag '%s' to query\n", node_tag);
		goto out;
	}

	if (value_was_empty) {
		rrr_string_builder_chop(string_builder);
	}

	out:
	RRR_FREE_IF_NOT_NULL(name_escaped_tmp);
	return ret;
}

int rrr_http_query_builder_append_values_from_array (
		struct rrr_http_query_builder *query_builder,
		const struct rrr_array *array,
		const struct rrr_map *columns,
		const char *separator,
		int no_separator_on_first,
		int do_quote_values
) {
	int ret = RRR_HTTP_OK;

	char buf[512];
	memset(buf, '\0', 511); // Valgrind moans about conditional jumps on uninitialized bytes

	if (array->version != 7) {
		RRR_BUG("Array version mismatch in rrr_http_query_builder_append_values_from_array (%u vs %i), module must be updated\n",
				array->version, 7);
	}

	if (RRR_MAP_COUNT(columns) > 0) {
		// Add only configured values
		int i = 0;
		RRR_MAP_ITERATE_BEGIN_CONST(columns);
			const struct rrr_type_value *value = rrr_array_value_get_by_tag_const(array, node_tag);

			if (value == NULL) {
				RRR_MSG_0("Warning: Could not find value with tag %s in incoming message\n",
						node_tag);
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			if (value->element_count > 1) {
				RRR_MSG_0("Warning: Received message with array of value (multi-value) with tag %s in\n",
						node_tag);
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			// If value is set, translation is to be used
			const char *tag_to_use = node_value != NULL ? node_value : node_tag;

			if ((ret = __rrr_http_query_builder_append_type_value (
				query_builder,
				value,
				tag_to_use,
				i > 0 || no_separator_on_first == 0 ? separator : NULL,
				do_quote_values
			)) != 0) {
				RRR_MSG_0("Error while adding column '%s'=>'%s' to HTTP query\n",
						node_tag != NULL ? node_tag : "",
						node_value != NULL ? node_value : ""
				);
				goto out;
			}
			i++;
		RRR_MAP_ITERATE_END();
	}
	else {
		// Add all values
		int i = 0;
		RRR_LL_ITERATE_BEGIN(array, struct rrr_type_value);
			if ((ret = __rrr_http_query_builder_append_type_value (
				query_builder,
				node,
				node->tag,
				i > 0 || no_separator_on_first == 0 ? separator : NULL,
				do_quote_values
			)) != 0) {
				RRR_MSG_0("Error while adding array value at position %i tag '%s' to HTTP query\n",
						i, (node->tag != NULL ? node->tag : "(no tag)"));
				goto out;
			}
			i++;
		RRR_LL_ITERATE_END();
	}

	out:
	return ret;
}

int rrr_http_query_builder_append_values_from_map (
		struct rrr_http_query_builder *query_builder,
		struct rrr_map *columns,
		const char *separator,
		int no_separator_on_first
) {
	struct rrr_string_builder *string_builder = query_builder->string_builder;

	int ret = RRR_HTTP_OK;

	char *name_tmp = NULL;
	char *value_tmp = NULL;

	int first = 1;

	RRR_MAP_ITERATE_BEGIN(columns);
		RRR_FREE_IF_NOT_NULL(name_tmp);
		RRR_FREE_IF_NOT_NULL(value_tmp);

		if (__rrr_http_query_builder_escape_field(&name_tmp, node_tag, strlen(node_tag), 0) != 0) {
			RRR_MSG_0("Could not escape field in rrr_http_query_builder_append_values_from_map\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}

		if (no_separator_on_first == 0 || first == 0) {
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, separator, "Could not append separator to query buffer in rrr_http_query_builder_append_values_from_map\n");
		}
		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, name_tmp, "Could not append name to query buffer in rrr_http_query_builder_append_values_from_map\n");

		if (node_value != NULL && *node_value != '\0') {
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, "=", "Could not append equal sign to query buffer in rrr_http_query_builder_append_values_from_map\n");

			if (__rrr_http_query_builder_escape_field(&value_tmp, node_value, strlen(node_value), 0) != 0) {
				RRR_MSG_0("Could not escape field in rrr_http_query_builder_append_values_from_map\n");
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}

			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, value_tmp, "Could not append blob type to query buffer in rrr_http_query_builder_append_values_from_map\n");
		}

		first = 0;
	RRR_MAP_ITERATE_END();

	out:
	RRR_FREE_IF_NOT_NULL(name_tmp);
	RRR_FREE_IF_NOT_NULL(value_tmp);
	return ret;
}

int rrr_http_query_builder_append_raw (
		struct rrr_http_query_builder *query_builder,
		const char *str
) {
	struct rrr_string_builder *string_builder = query_builder->string_builder;

	int ret = RRR_HTTP_OK;

	RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, str, "Could not append in rrr_http_query_builder_append_raw\n");

	out:
	return ret;
}

const char *rrr_http_query_builder_buf_get (
		struct rrr_http_query_builder *query_builder
) {
	return query_builder->string_builder->buf;
}

rrr_biglength rrr_http_query_builder_wpos_get (
		struct rrr_http_query_builder *query_builder
) {
	return query_builder->string_builder->wpos;
}

void rrr_http_query_builder_buf_takeover (
		char **target,
		struct rrr_http_query_builder *query_builder
) {
	*target = rrr_string_builder_buffer_takeover(query_builder->string_builder);
}
