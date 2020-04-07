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
#include "linked_list.h"
#include "http_fields.h"
#include "http_util.h"

static void __rrr_http_field_destroy(struct rrr_http_field *field) {
	RRR_FREE_IF_NOT_NULL(field->name);
	RRR_FREE_IF_NOT_NULL(field->value);
	free(field);
}

void rrr_http_fields_collection_clear (struct rrr_http_field_collection *fields) {
	RRR_LL_DESTROY(fields, struct rrr_http_field, __rrr_http_field_destroy(node));
}

static int __rrr_http_fields_collection_add_field_raw (
		struct rrr_http_field_collection *fields,
		const char *name,
		const void *value,
		ssize_t size,
		int is_binary
) {
	int ret = 0;

	struct rrr_http_field *field = malloc(sizeof(*field));
	if (field == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_http_fields_collection_add_field_raw A\n");
		ret = 1;
		goto out;
	}
	memset (field, '\0', sizeof(*field));

	if (name != NULL && strlen(name) > 0) {
		field->name = strdup(name);
		if (field->name == NULL) {
			RRR_MSG_ERR("Could not allocate memory for name in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (value != NULL && size > 0) {
		field->value = malloc(size);
		if (field->value == NULL) {
			RRR_MSG_ERR("Could not allocate memory for value in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
		memcpy(field->value, value, size);
	}

	field->is_binary = (is_binary != 0 ? 1 : 0);

	RRR_LL_APPEND(fields, field);
	field = NULL;

	out:
	if (field != NULL) {
		__rrr_http_field_destroy(field);
	}

	return ret;
}

int rrr_http_fields_collection_add_field (
		struct rrr_http_field_collection *fields,
		const char *name,
		const char *value
) {
	return __rrr_http_fields_collection_add_field_raw(fields, name, value, strlen(value) + 1, 0);
}

int rrr_http_fields_collection_add_field_binary (
		struct rrr_http_field_collection *fields,
		const char *name,
		void *value,
		ssize_t size
) {
	return __rrr_http_fields_collection_add_field_raw(fields, name, value, size, 1);
}

int rrr_http_fields_get_total_length (
		struct rrr_http_field_collection *fields
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		ret += (node->name != NULL ? strlen(node->name) : 0);
		ret += (node->value != NULL ? strlen(node->value) : 0);
	RRR_LL_ITERATE_END();

	return ret;
}

const struct rrr_http_field *rrr_http_fields_get_field (
		struct rrr_http_field_collection *fields,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		if (strcmp(node->name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}


static char *__rrr_http_fields_to_form_data (
		struct rrr_http_field_collection *fields,
		int no_urlencoding
) {
	char *result = NULL;
	char *name = NULL;
	char *value = NULL;
	int err = 0;

	ssize_t result_max_length =
			rrr_http_fields_get_total_length(fields) * 3 +
			RRR_LL_COUNT(fields) * 2 +
			1
	;

	if ((result = malloc(result_max_length)) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_http_fields_to_form_data\n");
		err = 1;
		goto out;
	}

	memset(result, '\0', result_max_length);

	char *wpos = result;
	char *wpos_max = result + result_max_length;

	int count = 0;
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		if (++count > 1) {
			*wpos = '&';
			wpos++;
		}

		RRR_FREE_IF_NOT_NULL(name);
		if (node->name != NULL) {
			if (no_urlencoding == 0) {
				name = rrr_http_util_encode_uri(node->name);

				if (name == NULL) {
					RRR_MSG_ERR("Could not encode parameter '%s' name '%s' in __rrr_http_fields_to_form_data\n",
							node->name, node->value);
					err = 1;
					goto out;
				}

				strcpy(wpos, name);
				wpos += strlen(name);
			}
			else {
				strcpy(wpos, node->name);
				wpos += strlen(node->name);
			}
		}

		if (node->value != NULL) {
			if (no_urlencoding == 0) {
				RRR_FREE_IF_NOT_NULL(value);
				value = rrr_http_util_encode_uri(node->value);

				if (value == NULL) {
					RRR_MSG_ERR("Could not encode parameter '%s' value '%s' in __rrr_http_fields_to_form_data\n",
							node->name, node->value);
					err = 1;
					goto out;
				}
				*wpos = '=';
				wpos++;

				strcpy (wpos, value);
				wpos += strlen(value);
			}
			else {
				strcpy (wpos, node->value);
				wpos += strlen(node->value);
			}
		}
	RRR_LL_ITERATE_END();

	if (wpos > wpos_max) {
		RRR_BUG("Result buffer write out of bounds in __rrr_http_fields_to_form_data\n");
	}

	out:
	if (err) {
		RRR_FREE_IF_NOT_NULL(result);
		result = NULL;
	}
	RRR_FREE_IF_NOT_NULL(name);
	RRR_FREE_IF_NOT_NULL(value);
	return result;
}

char *rrr_http_fields_to_urlencoded_form_data (
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_fields_to_form_data(fields, 0);
}

char *rrr_http_fields_to_raw_form_data (
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_fields_to_form_data(fields, 1);
}
