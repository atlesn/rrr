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

#include "http_fields.h"
#include "http_util.h"

#include "../array.h"
#include "../type.h"
#include "../json/json.h"
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
	free(field);
}

int rrr_http_field_new_no_value_raw (
		struct rrr_http_field **target,
		const char *name,
		rrr_length  name_length
) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_field *field = malloc(sizeof(*field));
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
		rrr_length len,
		void *arg
) {
	struct rrr_http_field **target = arg;

	return rrr_http_field_new_no_value_raw(target, str, len);
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
		rrr_length len,
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

		RRR_MSG_3 ("%s=>", name);

		if (rrr_nullsafe_str_isset(node->value)) {
			if (rrr_http_util_uri_encode (
					&urlencoded_nullsafe,
					node->value
			) != 0) {
				RRR_MSG_0("Warning: Error while encoding value in rrr_http_field_collection_dump\n");
				RRR_LL_ITERATE_NEXT();
			}

			RRR_MSG_PLAIN("=(%" PRIrrrl " bytes of type '%s') ", rrr_nullsafe_str_len(node->value), content_type);
			rrr_nullsafe_str_with_raw_do_const (node->value, __rrr_http_field_collection_dump_callback, NULL);
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

	struct rrr_http_field *field = malloc(sizeof(*field));
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

rrr_length rrr_http_field_collection_get_total_length (
		struct rrr_http_field_collection *fields
) {
	RRR_TYPES_CHECKED_LENGTH_COUNTER_INIT(ret);

	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		RRR_TYPES_CHECKED_LENGTH_COUNTER_ADD(ret, (node->name != NULL ? rrr_nullsafe_str_len(node->name) : 0));
		RRR_TYPES_CHECKED_LENGTH_COUNTER_ADD(ret, (node->value != NULL ? rrr_nullsafe_str_len(node->value) : 0));
	RRR_LL_ITERATE_END();

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

	// Note that original array values are not used in this function, only the strings

	int count = 0;
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		if (++count > 1) {
			if ((ret = rrr_nullsafe_str_append_raw(nullsafe, "&", 1)) != 0) {
				goto out;
			}
		}

		// We allow either name, value or both. If both are present, add = between.

		if (rrr_nullsafe_str_isset(node->name)) {
			if (no_urlencoding == 0) {
				if ((ret = rrr_nullsafe_str_append_with_converter(nullsafe, node->name, rrr_http_util_uri_encode)) != 0) {
					goto out;
				}
			}
			else {
				if ((ret = rrr_nullsafe_str_append(nullsafe, node->name)) != 0) {
					goto out;
				}
			}
		}

		if (rrr_nullsafe_str_isset(node->value)) {
			if (rrr_nullsafe_str_isset(node->name)) {
				if ((ret = rrr_nullsafe_str_append_raw(nullsafe, "=", 1)) != 0) {
					goto out;
				}
			}

			if (no_urlencoding == 0) {
				if (rrr_nullsafe_str_len(node->value) > 0) {
					if ((ret = rrr_nullsafe_str_append_with_converter(nullsafe, node->value, rrr_http_util_uri_encode)) != 0) {
						goto out;
					}
				}
			}
			else {
				if ((ret = rrr_nullsafe_str_append(nullsafe, node->value)) != 0) {
					goto out;
				}
			}
		}
	RRR_LL_ITERATE_END();

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

	if ((ret = rrr_nullsafe_str_new_or_replace_raw_allocated(target, (void **) &json_tmp, strlen(json_tmp))) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(json_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}
