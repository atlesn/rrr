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

#include "http_fields.h"
#include "http_util.h"

#include "../log.h"
#include "../linked_list.h"

void rrr_http_field_destroy(struct rrr_http_field *field) {
	RRR_FREE_IF_NOT_NULL(field->name);
	RRR_FREE_IF_NOT_NULL(field->value);
	RRR_FREE_IF_NOT_NULL(field->content_type);
	free(field);
}

int rrr_http_field_new_no_value (
		struct rrr_http_field **target,
		const char *name,
		ssize_t name_length
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

	if ((field->name = malloc(name_length + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_field_new_no_value\n");
		ret = 1;
		goto out;
	}

	memcpy (field->name, name, name_length);
	field->name[name_length] = '\0';

	*target = field;
	field = NULL;

	out:
	if (field != NULL) {
		rrr_http_field_destroy(field);
	}
	return ret;
}

int rrr_http_field_set_value (
		struct rrr_http_field *target,
		const char *value,
		ssize_t value_size
) {
	int ret = 0;

	char *value_tmp = malloc(value_size);
	if (value_tmp == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_field_set_value\n");
		ret = 1;
		goto out;
	}

	memcpy(value_tmp, value, value_size);

	RRR_FREE_IF_NOT_NULL(target->value);
	target->value = value_tmp;
	target->value_size = value_size;

	value_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(value_tmp);
	return ret;
}

void rrr_http_field_collection_dump (
		struct rrr_http_field_collection *fields
) {
	char *urlencoded_tmp = NULL;
	ssize_t urlencoded_size = 0;

	RRR_MSG_3 ("== DUMP FIELD COLLECTION ====================================\n");
	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		RRR_MSG_3 ("%s", node->name, node->value);

		if (node->value != NULL && node->value_size > 0) {
			RRR_FREE_IF_NOT_NULL(urlencoded_tmp);
			if ((urlencoded_tmp = rrr_http_util_encode_uri(&urlencoded_size, node->value, node->value_size)) == NULL) {
				RRR_MSG_0("Warning: Error while encoding value in rrr_http_field_collection_dump\n");
				RRR_LL_ITERATE_NEXT();
			}
			RRR_MSG_PLAIN("=(%lu bytes) ", node->value_size);
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

static int __rrr_http_field_collection_add_field_raw (
		struct rrr_http_field_collection *fields,
		const char *name,
		const void *value,
		ssize_t value_size,
		const char *content_type
) {
	int ret = 0;

	struct rrr_http_field *field = malloc(sizeof(*field));
	if (field == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_fields_collection_add_field_raw A\n");
		ret = 1;
		goto out;
	}
	memset (field, '\0', sizeof(*field));

	if (name != NULL && strlen(name) > 0) {
		field->name = strdup(name);
		if (field->name == NULL) {
			RRR_MSG_0("Could not allocate memory for name in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
	}

	if (content_type != NULL && strlen(content_type) > 0) {
		field->content_type = strdup(content_type);
		if (field->content_type == NULL) {
			RRR_MSG_0("Could not allocate memory for content_type in __rrr_http_fields_collection_add_field_raw\n");
			ret = 1;
			goto out;
		}
	}

	if (value != NULL && value_size > 0) {
		field->value = malloc(value_size);
		if (field->value == NULL) {
			RRR_MSG_0("Could not allocate memory for value in __rrr_http_fields_collection_add_field_raw B\n");
			ret = 1;
			goto out;
		}
		memcpy(field->value, value, value_size);
		field->value_size = value_size;
	}

	RRR_LL_APPEND(fields, field);
	field = NULL;

	out:
	if (field != NULL) {
		rrr_http_field_destroy(field);
	}

	return ret;
}

int rrr_http_field_collection_add (
		struct rrr_http_field_collection *fields,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
) {
	return __rrr_http_field_collection_add_field_raw (
			fields,
			name,
			value,
			value_size,
			content_type
	);
}

ssize_t rrr_http_field_collection_get_total_length (
		struct rrr_http_field_collection *fields
) {
	ssize_t ret = 0;

	RRR_LL_ITERATE_BEGIN(fields, struct rrr_http_field);
		ret += (node->name != NULL ? strlen(node->name) : 0);
		ret += node->value_size;
	RRR_LL_ITERATE_END();

	return ret;
}

const struct rrr_http_field *rrr_http_field_collection_get_field (
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


static char *__rrr_http_field_collection_to_form_data (
		ssize_t *output_size,
		struct rrr_http_field_collection *fields,
		int no_urlencoding
) {
	char *result = NULL;
	char *name = NULL;
	char *value = NULL;
	int err = 0;

	*output_size = 0;

	ssize_t result_max_length =
			rrr_http_field_collection_get_total_length(fields) * 3 +
			RRR_LL_COUNT(fields) * 2 +
			1
	;

	if ((result = malloc(result_max_length)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_fields_to_form_data\n");
		err = 1;
		goto out;
	}

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
				ssize_t output_size = 0;
				name = rrr_http_util_encode_uri(&output_size, node->name, strlen(node->name));

				if (name == NULL) {
					RRR_MSG_0("Could not encode parameter '%s' in __rrr_http_fields_to_form_data\n",
							node->name);
					err = 1;
					goto out;
				}

				memcpy(wpos, name, output_size);
				wpos += output_size;
			}
			else {
				strcpy(wpos, node->name);
				wpos += strlen(node->name);
			}
		}

		if (node->value != NULL) {
			if (no_urlencoding == 0) {
				RRR_FREE_IF_NOT_NULL(value);
				ssize_t output_size = 0;
				value = rrr_http_util_encode_uri(&output_size, node->value, node->value_size);

				if (value == NULL) {
					RRR_MSG_0("Could not encode parameter '%s' with value length %lu in __rrr_http_fields_to_form_data\n",
							node->name, node->value_size);
					err = 1;
					goto out;
				}

				if (node->name != NULL) {
					*wpos = '=';
					wpos++;
				}

				memcpy(wpos, value, output_size);
				wpos += output_size;
			}
			else {
				memcpy (wpos, node->value, node->value_size);
				wpos += node->value_size;
			}
		}
	RRR_LL_ITERATE_END();

	if (wpos > wpos_max) {
		RRR_BUG("Result buffer write out of bounds in __rrr_http_fields_to_form_data\n");
	}

	*output_size = wpos - result;

	out:
	if (err) {
		RRR_FREE_IF_NOT_NULL(result);
		result = NULL;
	}
	RRR_FREE_IF_NOT_NULL(name);
	RRR_FREE_IF_NOT_NULL(value);
	return result;
}

char *rrr_http_field_collection_to_urlencoded_form_data (
		ssize_t *output_size,
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_field_collection_to_form_data(output_size, fields, 0);
}

char *rrr_http_field_collection_to_raw_form_data (
		ssize_t *output_size,
		struct rrr_http_field_collection *fields
) {
	return __rrr_http_field_collection_to_form_data(output_size, fields, 1);
}
