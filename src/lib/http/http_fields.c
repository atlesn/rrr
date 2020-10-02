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

#include "../util/linked_list.h"
#include "../util/macro_utils.h"
#include "../helpers/nullsafe_str.h"

void rrr_http_field_destroy(struct rrr_http_field *field) {
	rrr_nullsafe_str_destroy_if_not_null(field->name);
	rrr_nullsafe_str_destroy_if_not_null(field->content_type);
	rrr_nullsafe_str_destroy_if_not_null(field->value);
	free(field);
}

int rrr_http_field_new_no_value (
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

	if (rrr_nullsafe_str_new(&field->name, name, name_length) != 0) {
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

int rrr_http_field_set_content_type (
		struct rrr_http_field *target,
		const char *content_type,
		rrr_length content_type_length
) {
	int ret = 0;

	rrr_nullsafe_str_destroy_if_not_null(target->content_type);
	if (content_type != NULL && *content_type != '\0') {
		if (rrr_nullsafe_str_new(&target->content_type, content_type, content_type_length) != 0) {
			RRR_MSG_0("Could not allocate memory in rrr_http_field_set_content_type\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;

}

int rrr_http_field_set_value (
		struct rrr_http_field *target,
		const char *value,
		rrr_length value_length
) {
	int ret = 0;

	rrr_nullsafe_str_destroy_if_not_null(target->value);
	if (value != NULL && *value != '\0' && value_length != 0) {
		if (rrr_nullsafe_str_new(&target->value, value, value_length) != 0) {
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

void rrr_http_field_collection_dump (
		struct rrr_http_field_collection *fields
) {
	char *urlencoded_tmp = NULL;
	rrr_length urlencoded_size = 0;

	RRR_MSG_3 ("== DUMP FIELD COLLECTION ====================================\n");
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, node->name);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(content_type, node->content_type);

		RRR_MSG_3 ("%s=>", name);

		if (rrr_nullsafe_str_isset(node->value)) {
			RRR_FREE_IF_NOT_NULL(urlencoded_tmp);
			if ((urlencoded_tmp = rrr_http_util_encode_uri (
					&urlencoded_size,
					node->value
			)) == NULL) {
				RRR_MSG_0("Warning: Error while encoding value in rrr_http_field_collection_dump\n");
				RRR_LL_ITERATE_NEXT();
			}
			RRR_MSG_PLAIN("=(%" PRIrrrl " bytes of type '%s') ", node->value->len, content_type);
			RRR_MSG_PLAIN_N(urlencoded_tmp, urlencoded_size);
		}

		RRR_MSG_PLAIN("\n");
	RRR_LL_ITERATE_END();
	RRR_MSG_3 ("== DUMP FIELD COLLECTION END ================================\n");

	RRR_FREE_IF_NOT_NULL(urlencoded_tmp);
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
		rrr_length content_type_length
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
		if (rrr_nullsafe_str_new(&field->name, name, name_length) != 0) {
			RRR_MSG_0("Could not allocate memory for name in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (content_type != NULL && content_type_length != 0) {
		if (rrr_nullsafe_str_new(&field->content_type, content_type, content_type_length) != 0) {
			RRR_MSG_0("Could not allocate memory for content_type in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (value != NULL && value_length != 0) {
		if (rrr_nullsafe_str_new(&field->value, value, value_length) != 0) {
			RRR_MSG_0("Could not allocate memory for value in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
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
		RRR_TYPES_CHECKED_LENGTH_COUNTER_ADD(ret, (node->name != NULL ? node->name->len : 0));
		RRR_TYPES_CHECKED_LENGTH_COUNTER_ADD(ret, (node->value != NULL ? node->value->len : 0));
	RRR_LL_ITERATE_END();

	return ret;
}

static char *__rrr_http_field_collection_to_form_data (
		rrr_length *output_size_final,
		struct rrr_http_field_collection *fields,
		int no_urlencoding
) {
	int err = 0;

	char *result = NULL;
	char *tmp = NULL;

	*output_size_final = 0;

	rrr_biglength result_max_length =
			rrr_http_field_collection_get_total_length(fields) * 3 +
			RRR_LL_COUNT(fields) * 2 +
			1
	;

	if (result_max_length > RRR_LENGTH_MAX) {
		RRR_MSG_0("Worst case length of %" PRIu64 " exceeds safe value of %" PRIrrrl,
				result_max_length, RRR_LENGTH_MAX);
	}

	if ((result = malloc(result_max_length)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_fields_to_form_data\n");
		err = 1;
		goto out;
	}

	char *wpos = result;
	const char * const wpos_max = result + result_max_length;

	int count = 0;
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		if (++count > 1) {
			*wpos = '&';
			wpos++;
		}

		int has_name = 0;
		if (no_urlencoding == 0) {
			RRR_FREE_IF_NOT_NULL(tmp);
			rrr_length output_size_tmp = 0;
			if ((tmp = rrr_http_util_encode_uri(&output_size_tmp, node->name)) == NULL) {
				err = 1;
				goto out;
			}

			if (output_size_tmp > 0) {
				memcpy(wpos, tmp, output_size_tmp);
				wpos += output_size_tmp;
				has_name = 1;
			}
		}
		else if (rrr_nullsafe_str_isset(node->name)) {
			rrr_length written_size = 0;
			rrr_nullsafe_str_copyto(&written_size, wpos, wpos_max - wpos, node->name);
			if (written_size > 0) {
				wpos += written_size;
				has_name = 1;
			}
		}

		if (rrr_nullsafe_str_isset(node->value)) {
			if (has_name) {
				*wpos = '=';
				wpos++;
			}

			if (no_urlencoding == 0) {
				RRR_FREE_IF_NOT_NULL(tmp);
				rrr_length output_size_tmp = 0;
				if ((tmp = rrr_http_util_encode_uri(&output_size_tmp, node->value)) == NULL) {
					err = 1;
					goto out;
				}

				if (output_size_tmp > 0) {
					memcpy(wpos, tmp, output_size_tmp);
					wpos += output_size_tmp;
				}
			}
			else {
				rrr_length written_size = 0;
				rrr_nullsafe_str_copyto(&written_size, wpos, wpos_max - wpos, node->value);
				if (written_size > 0) {
					wpos += written_size;
				}
			}
		}
	RRR_LL_ITERATE_END();

	if (wpos > wpos_max) {
		RRR_BUG("BUG: Result buffer write out of bounds in __rrr_http_fields_to_form_data\n");
	}

	*output_size_final = wpos - result;

	out:
	if (err) {
		RRR_FREE_IF_NOT_NULL(result);
		result = NULL;
	}
	RRR_FREE_IF_NOT_NULL(tmp);
	return result;
}

char *rrr_http_field_collection_to_urlencoded_form_data (
		rrr_length *output_size,
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_field_collection_to_form_data(output_size, fields, 0);
}

char *rrr_http_field_collection_to_raw_form_data (
		rrr_length *output_size,
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_field_collection_to_form_data(output_size, fields, 1);
}
