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
#include <inttypes.h>

// Needed by http_fields
#include "../log.h"
#include "../allocator.h"

#include "http_fields.h"
#include "http_util.h"
#include "http_query_builder.h"

#include "../array.h"
#include "../type.h"
#ifdef RRR_WITH_JSONC
#	include "../json/json.h"
#endif
#include "../util/linked_list.h"
#include "../util/macro_utils.h"
#include "../helpers/nullsafe_str.h"

void rrr_http_field_destroy(struct rrr_http_field *field) {
	rrr_nullsafe_str_destroy_if_not_null(&field->name);
	rrr_nullsafe_str_destroy_if_not_null(&field->content_type);
	rrr_nullsafe_str_destroy_if_not_null(&field->value);
	if (field->value_orig != NULL) {
		rrr_type_value_destroy(field->value_orig);
	}
	rrr_free(field);
}

int rrr_http_field_new_no_value_raw (
		struct rrr_http_field **target,
		const char *name,
		rrr_length  name_length
) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_field *field = rrr_allocate(sizeof(*field));
	if (field == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_field_new_no_value\n");
		ret = 1;
		goto out;
	}
	memset (field, '\0', sizeof(*field));

	if (rrr_nullsafe_str_new_or_replace_raw(&field->name, name, name_length) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_http_field_new_no_value\n");
		ret = 1;
		goto out_free;
	}

	*target = field;
	field = NULL;

	goto out;
	out_free:
		rrr_http_field_destroy(field);
	out:
		return ret;
}

static int __rrr_http_field_new_no_value_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_http_field **target = arg;

	if (len > RRR_LENGTH_MAX) {
		RRR_MSG_0("HTTP field too long to save (%" PRIrrr_nullsafe_len ">%llu)\n",
			len, (long long unsigned) RRR_LENGTH_MAX);
		return 1;
	}

	return rrr_http_field_new_no_value_raw(target, str, (rrr_length) len);
}

int rrr_http_field_new_no_value (
		struct rrr_http_field **target,
		const struct rrr_nullsafe_str *nullsafe
) {
	return rrr_nullsafe_str_with_raw_do_const(nullsafe, __rrr_http_field_new_no_value_callback, target);
}

int rrr_http_field_content_type_set (
		struct rrr_http_field *target,
		const struct rrr_nullsafe_str *content_type
) {
	int ret = 0;

	if (rrr_nullsafe_str_new_or_replace(&target->content_type, content_type) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_http_field_set_content_type\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_http_field_value_set (
		struct rrr_http_field *target,
		const char *value,
		rrr_length value_length
) {
	int ret = 0;

	if (value != NULL && *value != '\0' && value_length != 0) {
		if (rrr_nullsafe_str_new_or_replace_raw(&target->value, value, value_length) != 0) {
			RRR_MSG_0("Could not allocate memory in rrr_http_field_set_value\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_http_field_collection_iterate_const (
		const struct rrr_http_field_collection *fields,
		int (*callback)(const struct rrr_http_field *field, void *callback_arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(fields, const struct rrr_http_field);
		if ((ret = callback(node, callback_arg)) != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}


static int __rrr_http_field_collection_dump_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	(void)(arg);
	RRR_MSG_PLAIN_N(str, len);
	return 0;
}

void rrr_http_field_collection_dump (
		struct rrr_http_field_collection *fields
) {
	struct rrr_nullsafe_str *urlencoded_nullsafe = NULL;

	RRR_MSG_3 ("== DUMP FIELD COLLECTION ====================================\n");
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, node->name);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(content_type, node->content_type);

		RRR_MSG_3 ("%s =>", node->value_orig != NULL ? node->value_orig->tag : name);
	
		if (node->value_orig != NULL) {
			char *tmp = NULL;

			// Ignore errors
			if (node->value_orig->definition->to_str(&tmp, node->value_orig) != 0) {
				goto free_tmp;
			}

			RRR_MSG_PLAIN(" (%" PRIrrrl " bytes of type '%s') ", node->value_orig->total_stored_length, node->value_orig->definition->identifier);
			RRR_MSG_PLAIN("%s", tmp);

			free_tmp:
			RRR_FREE_IF_NOT_NULL(tmp);
		}
		else if (rrr_nullsafe_str_isset(node->value)) {
			if (rrr_http_util_uri_encode (
					&urlencoded_nullsafe,
					node->value
			) != 0) {
				RRR_MSG_0("Warning: Error while encoding value in rrr_http_field_collection_dump\n");
				RRR_LL_ITERATE_NEXT();
			}

			RRR_MSG_PLAIN(" (%" PRIrrr_nullsafe_len " bytes of type '%s') ", rrr_nullsafe_str_len(node->value), content_type);
			rrr_nullsafe_str_with_raw_do_const (node->value, __rrr_http_field_collection_dump_callback, NULL);
		}
		else {
			RRR_MSG_PLAIN(" (no value)");
		}

		RRR_MSG_PLAIN("\n");
	RRR_LL_ITERATE_END();
	RRR_MSG_3 ("== DUMP FIELD COLLECTION END ================================\n");

	rrr_nullsafe_str_destroy_if_not_null(&urlencoded_nullsafe);
}

void rrr_http_field_collection_clear (
		struct rrr_http_field_collection *fields
) {
	RRR_LL_DESTROY(fields, struct rrr_http_field, rrr_http_field_destroy(node));
}

// When values are converyed to form data, the value_orig takes precedence over the others if present
int rrr_http_field_collection_add (
		struct rrr_http_field_collection *fields,
		const char *name,
		rrr_length name_length,
		const char *value,
		rrr_length value_length,
		const char *content_type,
		rrr_length content_type_length,
		const struct rrr_type_value *value_orig
) {
	int ret = 0;

	struct rrr_http_field *field = rrr_allocate(sizeof(*field));
	if (field == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_fields_collection_add_field_raw A\n");
		ret = 1;
		goto out;
	}
	memset (field, '\0', sizeof(*field));

	if (name != NULL && name_length != 0) {
		if (rrr_nullsafe_str_new_or_replace_raw(&field->name, name, name_length) != 0) {
			RRR_MSG_0("Could not allocate memory for name in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (content_type != NULL && content_type_length != 0) {
		if (rrr_nullsafe_str_new_or_replace_raw(&field->content_type, content_type, content_type_length) != 0) {
			RRR_MSG_0("Could not allocate memory for content_type in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (value != NULL && value_length != 0) {
		if (rrr_nullsafe_str_new_or_replace_raw(&field->value, value, value_length) != 0) {
			RRR_MSG_0("Could not allocate memory for value in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (value_orig != NULL) {
		if ((ret = rrr_type_value_clone(&field->value_orig, value_orig, 1)) != 0) {
			goto out;
		}
	}

	RRR_LL_APPEND(fields, field);
	field = NULL;

	out:
	if (field != NULL) {
		rrr_http_field_destroy(field);
	}

	return ret;
}

#define REPLACE_STR_OR_OUT_LEN(target,str,len) \
	do {if ((ret = rrr_nullsafe_str_new_or_replace_raw(&(target), str, len)) != 0) { goto out; }} while(0)

#define REPLACE_STR_OR_OUT(target,str) \
	do {if ((ret = rrr_nullsafe_str_new_or_replace_raw(&(target), str, rrr_length_from_biglength_bug_const(strlen(str)))) != 0) { goto out; }} while(0)

static int __rrr_http_field_value_to_strings (
		const struct rrr_type_value *value,
		int (*callback)(const struct rrr_nullsafe_str *name, const struct rrr_nullsafe_str *value, const struct rrr_nullsafe_str *content_type, void *arg),
		void *callback_arg
) {
	int ret = 0;

	char *buf_tmp = NULL;
	struct rrr_http_query_builder query_builder = {0};

	struct rrr_nullsafe_str *name_to_callback = NULL;
	struct rrr_nullsafe_str *value_to_callback = NULL;
	struct rrr_nullsafe_str *content_type_to_callback = NULL;

	if ((rrr_http_query_builder_init(&query_builder)) != 0) {
		RRR_MSG_0("Could not initialize query builder in __rrr_http_field_collection_node_to_strings\n");
		ret = 1;
		goto out;
	}

	if (RRR_TYPE_IS_MSG(value->definition->type)) {
		rrr_length value_size = 0;
		if (rrr_type_value_allocate_and_export(&buf_tmp, &value_size, value) != 0) {
			RRR_MSG_0("Error while exporting RRR message in __rrr_http_field_collection_node_to_strings\n");
			ret = 1;
			goto out;
		}

		REPLACE_STR_OR_OUT(content_type_to_callback, RRR_MESSAGE_MIME_TYPE);
		REPLACE_STR_OR_OUT_LEN(value_to_callback, buf_tmp, value_size);
	}
	else if (RRR_TYPE_IS_STR(value->definition->type)) {
		REPLACE_STR_OR_OUT(content_type_to_callback, "text/plain");
		REPLACE_STR_OR_OUT_LEN(value_to_callback, value->data, value->total_stored_length);
	}
	else if (RRR_TYPE_IS_BLOB(value->definition->type)) {
		REPLACE_STR_OR_OUT(content_type_to_callback, "application/octet-stream");
		REPLACE_STR_OR_OUT_LEN(value_to_callback, value->data, value->total_stored_length);
	}
	else {
		int value_was_empty = 0;

		// BLOB and STR must be treated as special case above, this
		// function would otherwise modify the data by escaping
		if ((ret = rrr_http_query_builder_append_type_value_as_escaped_string (
				&value_was_empty,
				&query_builder,
				value,
				0
		)) != 0) {
			RRR_MSG_0("Error while exporting non-BLOB in __rrr_http_field_collection_node_to_strings\n");
			goto out;
		}

		if (!value_was_empty) {
			rrr_biglength length_tmp = rrr_http_query_builder_wpos_get(&query_builder);
			if (length_tmp > RRR_LENGTH_MAX) {
				RRR_MSG_0("Value was too long in __rrr_http_field_collection_node_to_strings\n");
				ret = 1;
				goto out;
			}

			REPLACE_STR_OR_OUT(value_to_callback, rrr_http_query_builder_buf_get(&query_builder));
		}

		REPLACE_STR_OR_OUT(content_type_to_callback, "text/plain");
	}

	if (value->tag != NULL) {
		REPLACE_STR_OR_OUT(name_to_callback, value->tag);
	}

	ret = callback (
		name_to_callback,
		value_to_callback,
		content_type_to_callback,
		callback_arg
	);

	out:
	rrr_nullsafe_str_destroy_if_not_null(&name_to_callback);
	rrr_nullsafe_str_destroy_if_not_null(&value_to_callback);
	rrr_nullsafe_str_destroy_if_not_null(&content_type_to_callback);
	RRR_FREE_IF_NOT_NULL(buf_tmp);
	rrr_http_query_builder_cleanup(&query_builder);
	return ret;
}

int rrr_http_field_collection_iterate_as_strings (
		const struct rrr_http_field_collection *fields,
		int (*callback)(const struct rrr_nullsafe_str *name, const struct rrr_nullsafe_str *value, const struct rrr_nullsafe_str *content_type, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(fields, const struct rrr_http_field);
		if (node->value_orig != NULL) {
			if ((ret = __rrr_http_field_value_to_strings(node->value_orig, callback, callback_arg)) != 0) {
				goto out;
			}
		}
		else {
			if ((ret = callback(node->name, node->value, node->content_type, callback_arg)) != 0) {
				goto out;
			}
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

struct rrr_http_field_collection_to_form_data_callback_data {
	struct rrr_nullsafe_str *target;
	int count;
	int no_urlencoding;
};

static int __rrr_http_field_collection_to_form_data_field_callback (
		const struct rrr_nullsafe_str *name,
		const struct rrr_nullsafe_str *value,
		const struct rrr_nullsafe_str *content_type,
		void *arg
) {
	(void)(content_type);

	struct rrr_http_field_collection_to_form_data_callback_data *callback_data = arg;

	int ret = 0;

	if (++(callback_data->count) > 1) {
		if ((ret = rrr_nullsafe_str_append_raw(callback_data->target, "&", 1)) != 0) {
			goto out;
		}
	}

	// We allow either name, value or both. If both are present, add = between.

	if (rrr_nullsafe_str_isset(name)) {
		if (callback_data->no_urlencoding == 0) {
			if ((ret = rrr_nullsafe_str_append_with_converter(callback_data->target, name, rrr_http_util_uri_encode)) != 0) {
				goto out;
			}
		}
		else {
			if ((ret = rrr_nullsafe_str_append(callback_data->target, name)) != 0) {
				goto out;
			}
		}
	}

	if (rrr_nullsafe_str_isset(value)) {
		if (rrr_nullsafe_str_isset(name)) {
			if ((ret = rrr_nullsafe_str_append_raw(callback_data->target, "=", 1)) != 0) {
				goto out;
			}
		}

		if (callback_data->no_urlencoding == 0) {
			if (rrr_nullsafe_str_len(value) > 0) {
				if ((ret = rrr_nullsafe_str_append_with_converter(callback_data->target, value, rrr_http_util_uri_encode)) != 0) {
					goto out;
				}
			}
		}
		else {
			if ((ret = rrr_nullsafe_str_append(callback_data->target, value)) != 0) {
				goto out;
			}
		}
	}

	out:
	return ret;
}

static int __rrr_http_field_collection_to_form_data (
		struct rrr_nullsafe_str **target,
		struct rrr_http_field_collection *fields,
		int no_urlencoding
) {
	int ret = 0;

	struct rrr_nullsafe_str *nullsafe = NULL;

	if ((ret = rrr_nullsafe_str_new_or_replace_empty(&nullsafe)) != 0) {
		goto out;
	}

	struct rrr_http_field_collection_to_form_data_callback_data callback_data = {
		nullsafe,
		0,
		no_urlencoding
	};

	if ((ret = rrr_http_field_collection_iterate_as_strings (
			fields,
			__rrr_http_field_collection_to_form_data_field_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	*target = nullsafe;
	nullsafe = NULL;

	out:
	rrr_nullsafe_str_destroy_if_not_null(&nullsafe);
	return ret;
}

int rrr_http_field_collection_to_urlencoded_form_data (
		struct rrr_nullsafe_str **target,
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_field_collection_to_form_data(target, fields, 0);
}

int rrr_http_field_collection_to_raw_form_data (
		struct rrr_nullsafe_str **target,
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_field_collection_to_form_data(target, fields, 1);
}

#ifdef RRR_WITH_JSONC
struct rrr_http_field_collection_to_json_value_callback_data {
	struct rrr_array *target;
	const struct rrr_nullsafe_str *value;
};

static int __rrr_http_field_collection_to_json_value_callback (const char *str, void *arg) {
	struct rrr_http_field_collection_to_json_value_callback_data *callback_data = arg;
	return rrr_array_push_value_str_with_tag_nullsafe(callback_data->target, str, callback_data->value);
}

int rrr_http_field_collection_to_json (
		struct rrr_nullsafe_str **target,
		const struct rrr_http_field_collection *fields
) {
	int ret = 0;

	char *json_tmp = NULL;
	struct rrr_array array_tmp = {0};

	// Note that original array values take precedence over any string values

	RRR_LL_ITERATE_BEGIN(fields, const struct rrr_http_field);
		if (node->value_orig != NULL) {
			struct rrr_type_value *value_tmp = NULL;
			if ((ret = rrr_type_value_clone(&value_tmp, node->value_orig, 1)) != 0) {
				goto out;
			}
			RRR_LL_APPEND(&array_tmp, value_tmp);
		}
		else {
			struct rrr_http_field_collection_to_json_value_callback_data callback_data = {
				&array_tmp,
				node->value
			};

			if ((ret = rrr_nullsafe_str_with_raw_null_terminated_do (
					node->name,
					__rrr_http_field_collection_to_json_value_callback,
					&callback_data
			)) != 0) {
				goto out;
			}
		}
	RRR_LL_ITERATE_END();

	int found_tags_dummy = 0;
	if ((ret = rrr_json_from_array(&json_tmp, &found_tags_dummy, &array_tmp, NULL)) != 0) {
		goto out;
	}

	size_t json_length = strlen(json_tmp);

	if ((ret = rrr_nullsafe_str_new_or_replace_raw_allocated(target, (void **) &json_tmp, (rrr_nullsafe_len) json_length)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(json_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}
#endif
