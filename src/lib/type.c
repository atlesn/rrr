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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <inttypes.h>

#include "../global.h"
#include "type.h"

#define PASTER(x,y) x ## _ ## y

#define RRR_TYPES_MATCH_RETURN(str,name) \
	if (strcmp(str,PASTER(RRR_TYPE_NAME,name)) == 0){return PASTER(RRR_TYPE,name);}

static int __rrr_type_convert_integer_10(char **end, long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoll(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

static int __rrr_type_convert_unsigned_integer_10(char **end, unsigned long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoull(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

#define CHECK_END_AND_RETURN(length)		\
	if (start + length > end) {				\
		return RRR_TYPE_PARSE_INCOMPLETE;	\
	}

static int __rrr_type_import_le (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	if (node->length > (rrr_type_length) sizeof(rrr_type_le)) {
		VL_BUG("BUG: import_le received length > %lu", sizeof(rrr_type_le));
	}
	if (node->data != NULL) {
		VL_BUG("data was not NULL in import_le\n");
	}

	CHECK_END_AND_RETURN(node->length * node->array_size);

	node->data = malloc(sizeof(rrr_type_le) * node->array_size);
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_le\n");
		return RRR_TYPE_PARSE_ERR;
	}

	char *target_wpos = node->data;
	const char *data_rpos = start;

	rrr_type_array_size array_size = node->array_size;
	while (array_size-- > 0) {
		union leunion {
			rrr_type_le temp_f;
			char temp_b[sizeof(rrr_type_le)];
		};

		union leunion temp;

		temp.temp_f = 0;

		/* Little endian:
		 * (0x01 0x00 0x00)le = 1
		 * (0x01 0x00 0x00 0x00 0x00 0x00)le = 1
		 */

		rrr_type_length pos = 0;
		while (pos < node->length) {
			temp.temp_b[pos] = data_rpos[pos];
			pos++;
		}

		temp.temp_f = le64toh(temp.temp_f);

		memcpy(target_wpos, &temp.temp_f, sizeof(temp.temp_f));

		VL_DEBUG_MSG_3("Imported a le64: 0x%" PRIx64 "\n", le64toh(temp.temp_f));

		data_rpos += node->length;
		target_wpos += sizeof(temp.temp_f);
	}

	*parsed_bytes = node->length * node->array_size;

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->length = sizeof(rrr_type_h);

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_be (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	if (node->length > (rrr_type_length) sizeof(rrr_type_be)) {
		VL_BUG("BUG: convert_be received length > %lu", sizeof(rrr_type_be));
	}
	if (node->data != NULL) {
		VL_BUG("data was not NULL in import_be\n");
	}

	CHECK_END_AND_RETURN(node->length * node->array_size);

	node->data = malloc(sizeof(rrr_type_be) * node->array_size);
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_be\n");
		return RRR_TYPE_PARSE_ERR;
	}

	char *target_wpos = node->data;
	const char *data_rpos = start;

	rrr_type_array_size array_size = node->array_size;
	while (array_size-- > 0) {
		union beunion {
			rrr_type_be temp_f;
			char temp_b[sizeof(rrr_type_be)];
		};

		union beunion temp;

		temp.temp_f = 0;

		rrr_type_length wpos = sizeof(temp.temp_f) - 1;
		rrr_type_length rpos = node->length - 1;

		// VL_DEBUG_MSG_3("rpos: %d, wpos: %d\n", rpos, wpos);

		/* Big endian:
		 * (0x00 0x00 0x01)be = 1
		 * (0x00 0x00 0x00 0x00 0x00 0x01)be = 1
		 */

		while (1) {
			temp.temp_b[wpos] = data_rpos[rpos];

			if (rpos == 0) {
				break;
			}

			wpos--;
			rpos--;
		}

		temp.temp_f = be64toh(temp.temp_f);

		memcpy(target_wpos, &temp.temp_f, sizeof(temp.temp_f));

		VL_DEBUG_MSG_3("Imported a be64: 0x%" PRIx64 "\n", be64toh(temp.temp_f));

		data_rpos += node->length;
		target_wpos += sizeof(temp.temp_f);
	}

	*parsed_bytes = node->length * node->array_size;

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->length = sizeof(rrr_type_h);

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_host (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	return (RRR_TYPE_SYSTEM_ENDIAN_IS_LE ?
			__rrr_type_import_le(node, parsed_bytes, start, end) :
			__rrr_type_import_be(node, parsed_bytes, start, end)
	);
}

static int __rrr_type_import_blob (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	if (node->data != NULL) {
		VL_BUG("data was not NULL in import_blob\n");
	}

	CHECK_END_AND_RETURN(node->length * node->array_size);

	node->data = malloc(node->length * node->array_size);
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_blob\n");
		return 1;
	}
	memcpy(node->data, start, node->length * node->array_size);

	*parsed_bytes = node->length;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_ustr (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	if (node->data != NULL) {
		VL_BUG("data was not NULL in import_ustr\n");
	}
	if (node->array_size != 1) {
		VL_BUG("array size was not 1 in import_ustr\n");
	}
	if (node->length != 0) {
		VL_BUG("length was not 0 in import_ustr\n");
	}

	CHECK_END_AND_RETURN(1);

	ssize_t max = end - start;
	if (max > 30) {
		max = 30;
	}
	char tmp[max];
	memset(tmp, '\0', sizeof(tmp));
	strncpy(tmp, start, max - 1);

	int found_end_char = 0;
	for (const char *pos = tmp; pos < tmp + sizeof(tmp); pos++) {
		if (*pos >= '0' && *pos <= '9') {
			continue;
		}
		else {
			found_end_char = 1;
			break;
		}
	}

	if (found_end_char == 0) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	char *convert_end = NULL;
	unsigned long long int result = 0;

	if (__rrr_type_convert_unsigned_integer_10(&convert_end, &result, tmp)) {
		VL_MSG_ERR("Error while converting unsigned integer in import_ustr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	node->data = malloc(sizeof(rrr_type_ustr));
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_ustr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	memcpy(node->data, &result, sizeof(rrr_type_ustr));

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->length = sizeof(rrr_type_h);

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_istr (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	if (node->data != NULL) {
		VL_BUG("data was not NULL in import_istr\n");
	}
	if (node->array_size != 1) {
		VL_BUG("array size was not 1 in import_istr\n");
	}
	if (node->length != 0) {
		VL_BUG("length was not -1 in import_istr\n");
	}

	CHECK_END_AND_RETURN(1);

	ssize_t max = end - start;
	if (max > 30) {
		max = 30;
	}
	char tmp[max];
	memset(tmp, '\0', sizeof(tmp));
	strncpy(tmp, start, max - 1);

	int found_end_char = 0;
	for (const char *pos = tmp + (tmp[0] == '-' || tmp[0] == '+' ? 1 : 0); pos < tmp + sizeof(tmp); pos++) {
		if (*pos >= '0' && *pos <= '9') {
			continue;
		}
		else {
			found_end_char = 1;
			break;
		}
	}

	if (found_end_char == 0) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	char *convert_end = NULL;
	long long int result = 0;

	if (__rrr_type_convert_integer_10(&convert_end, &result, tmp)) {
		VL_MSG_ERR("Error while converting unsigned integer in import_istr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	node->data = malloc(sizeof(rrr_type_istr));
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_istr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	memcpy(node->data, &result, sizeof(rrr_type_istr));

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->length = sizeof(rrr_type_h);

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}


static int __rrr_type_import_sep (
		struct rrr_type_value *node,
		ssize_t *parsed_bytes,
		const char *start_orig,
		const char *end
) {
	if (node->data != NULL) {
		VL_BUG("data was not NULL in import_sep\n");
	}

	ssize_t found = 0;
	for (const char *start = start; start < end && found < node->length * node->array_size; start++) {
		CHECK_END_AND_RETURN(1);

		unsigned char c = *start;

		if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
		}
		else if (c >= 33 && c <= 47) {
			// ! " # $ % & ' ( ) * + , - . /
		}
		else if (c >= 58 && c <= 64) {
			// : ; < = > ? @
		}
		else if (c >= 91 && c <= 96) {
			// [ \ ] ^ _ `
		}
		else if (c >= 123 && c <= 126) {
			// { | } ~
		}
		else {
			VL_MSG_ERR("Invalid separator character %c\n", c);
			return 1;
		}
		found++;
	}

	if (found != node->length * node->array_size) {
		VL_MSG_ERR("Not enough separator characters found\n");
		return 1;
	}

	node->data = malloc(found);
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_sep\n");
		return 1;
	}
	memcpy (node->data, start_orig, found);

	*parsed_bytes = found;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_convert_be_64_to_host(struct rrr_type_value *node) {
	if (node->length != sizeof(rrr_type_be)) {
		VL_MSG_ERR("Size of 64 type was not 8 bytes in __rrr_array_convert_be_64_to_host\n");
		return 1;
	}
	if (node->array_size == 0) {
		VL_MSG_ERR("Array of be64 type was 0 in __rrr_array_convert_be_64_to_host\n");
		return 1;
	}

	const char *pos = node->data;
	for (unsigned int i = 0; i < node->array_size; i++) {
		*((rrr_type_be *) pos) = be64toh(*((rrr_type_be *) pos));
		pos += node->length;
	}

	return 0;
}

static int __rrr_type_convert_blob_to_host(struct rrr_type_value *node) {
	if (node->length == 0 || node->array_size == 0) {
		VL_MSG_ERR("Length or array of blob type was 0 in __rrr_array_convert_blob_to_host\n");
		return 1;
	}
	return 0;
}

// If there are types which begin with the same letters, the longest names must be first in the array
static const struct rrr_type_definition type_templates[] = {
		{RRR_TYPE_BE,		RRR_TYPE_MAX_BE,	__rrr_type_import_be,	__rrr_type_convert_be_64_to_host,	RRR_TYPE_NAME_BE},
		{RRR_TYPE_H,		RRR_TYPE_MAX_H,		__rrr_type_import_host,	NULL,								RRR_TYPE_NAME_H},
		{RRR_TYPE_LE,		RRR_TYPE_MAX_LE,	__rrr_type_import_le,	NULL,								RRR_TYPE_NAME_LE},
		{RRR_TYPE_BLOB,		RRR_TYPE_MAX_BLOB,	__rrr_type_import_blob,	__rrr_type_convert_blob_to_host,	RRR_TYPE_NAME_BLOB},
		{RRR_TYPE_USTR,		RRR_TYPE_MAX_USTR,	__rrr_type_import_ustr,	NULL,								RRR_TYPE_NAME_USTR},
		{RRR_TYPE_ISTR,		RRR_TYPE_MAX_ISTR,	__rrr_type_import_istr,	NULL,								RRR_TYPE_NAME_ISTR},
		{RRR_TYPE_SEP,		RRR_TYPE_MAX_SEP,	__rrr_type_import_sep,	__rrr_type_convert_blob_to_host,	RRR_TYPE_NAME_SEP},
		{RRR_TYPE_ARRAY,	RRR_TYPE_MAX_ARRAY,	NULL,					NULL,								RRR_TYPE_NAME_ARRAY},
		{0,					0,					NULL,					NULL,								NULL}
};

const struct rrr_type_definition *rrr_type_parse_from_string (
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	*parsed_bytes = 0;

	for (unsigned int i = 0; i < sizeof(type_templates) / sizeof(type_templates[0]) - 1; i++) {
		const struct rrr_type_definition *type = &type_templates[i];
		ssize_t len = strlen(type->identifier);
		if (start + len > end) {
			continue;
		}
		if (strncmp(type->identifier, start, len) == 0) {
			*parsed_bytes = len;
			return type;
		}
	}

	return NULL;
}


const struct rrr_type_definition *rrr_type_get_from_id (
		uint8_t type_in
) {
	for (unsigned int i = 0; i < sizeof(type_templates) / sizeof(type_templates[0]) - 1; i++) {
		const struct rrr_type_definition *type = &type_templates[i];
		if (type->type == type_in) {
			return type;
		}
	}

	return NULL;
}

void rrr_type_value_destroy (
		struct rrr_type_value *template
) {
	RRR_FREE_IF_NOT_NULL(template->data);
	free(template);
}

int rrr_type_value_new (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_length length,
		rrr_type_array_size array_size
) {
	int ret = 0;

	struct rrr_type_value *value = malloc(sizeof(*value));
	if (value == NULL) {
		VL_MSG_ERR("Could not allocate template in rrr_type_value_new\n");
		ret = 1;
		goto out;
	}

	memset(value, '\0', sizeof(*value));

	value->array_size = array_size;
	value->length = length;
	value->definition = type;

	*result = value;
	value = NULL;

	out:
	if (value != NULL) {
		rrr_type_value_destroy(value);
	}

	return ret;
}
