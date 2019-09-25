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
	RRR_LINKED_LIST_DESTROY(fields, struct rrr_http_field, __rrr_http_field_destroy(node));
}

int rrr_http_fields_collection_add_field (
		struct rrr_http_field_collection *fields,
		const char *name,
		const char *value
) {
	int ret = 0;

	struct rrr_http_field *field = malloc(sizeof(*field));
	if (field == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_http_fields_add A\n");
		ret = 1;
		goto out;
	}
	memset (field, '\0', sizeof(*field));

	field->name = strdup(name);
	field->value = strdup(value);

	if (field->name == NULL || field->value == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_http_fields_add B\n");
		ret = 1;
		goto out;
	}

	RRR_LINKED_LIST_APPEND(fields, field);
	field = NULL;

	out:
	if (field != NULL) {
		__rrr_http_field_destroy(field);
	}

	return ret;
}

static int __rrr_http_fields_get_total_length (
		struct rrr_http_field_collection *fields
) {
	int ret = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(fields, struct rrr_http_field);
		ret += strlen(node->name);
		ret += strlen(node->value);
	RRR_LINKED_LIST_ITERATE_END(fields);

	return ret;
}

char *rrr_http_fields_to_urlencoded_form_data (
		struct rrr_http_field_collection *fields
) {
	char *result = NULL;
	char *name = NULL;
	char *value = NULL;
	int err = 0;

	ssize_t result_max_length =
			__rrr_http_fields_get_total_length(fields) * 3 +
			RRR_LINKED_LIST_COUNT(fields) * 2 +
			1
	;

	if ((result = malloc(result_max_length)) == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_http_fields_to_urlencoded_form_data\n");
		err = 1;
		goto out;
	}

	memset(result, '\0', result_max_length);

	char *wpos = result;
	char *wpos_max = result + result_max_length;

	int count = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(fields, struct rrr_http_field);
		if (++count > 1) {
			*wpos = '&';
			wpos++;
		}

		RRR_FREE_IF_NOT_NULL(name);
		RRR_FREE_IF_NOT_NULL(value);

		name = rrr_http_util_encode_uri(node->name);
		value = rrr_http_util_encode_uri(node->value);

		if (name == NULL || value == NULL) {
			VL_MSG_ERR("Could not encode parameter '%s' value '%s' in rrr_http_fields_to_urlencoded_form_data\n",
					node->name, node->value);
			err = 1;
			goto out;
		}

		strcpy(wpos, name);
		wpos += strlen(name);

		*wpos = '=';
		wpos++;

		strcpy (wpos, value);
		wpos += strlen(value);
	RRR_LINKED_LIST_ITERATE_END(fields);

	if (wpos > wpos_max) {
		VL_BUG("Result buffer write out of bounds in rrr_http_fields_to_urlencoded_form_data\n");
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
