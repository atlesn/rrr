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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>

#include "cmdlineparser/cmdline.h"
#include "types.h"
#include "settings.h"
#include "instance_config.h"
#include "messages.h"
#include "../global.h"

#define PASTER(x,y) x ## _ ## y

#define RRR_TYPES_MATCH_RETURN(str,name) \
	if (strcmp(str,PASTER(RRR_TYPE_NAME,name)) == 0){return PASTER(RRR_TYPE,name);}

int convert_integer_10(char **end, long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoll(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

int convert_unsigned_integer_10(char **end, unsigned long long int *result, const char *value) {
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

static int import_le (
		struct rrr_type_template *node,
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

	rrr_array_size array_size = node->array_size;
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

		memcpy(target_wpos, &temp.temp_f, sizeof(temp.temp_f));

		VL_DEBUG_MSG_3("Imported a le64: 0x%" PRIx64 "\n", le64toh(temp.temp_f));

		data_rpos += node->length;
		target_wpos += sizeof(temp.temp_f);
	}

	*parsed_bytes = node->length * node->array_size;

	return RRR_TYPE_PARSE_OK;
}

static int import_be (
		struct rrr_type_template *node,
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

	rrr_array_size array_size = node->array_size;
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

		memcpy(target_wpos, &temp.temp_f, sizeof(temp.temp_f));

		VL_DEBUG_MSG_3("Imported a be64: 0x%" PRIx64 "\n", be64toh(temp.temp_f));

		data_rpos += node->length;
		target_wpos += sizeof(temp.temp_f);
	}

	*parsed_bytes = node->length * node->array_size;

	return RRR_TYPE_PARSE_OK;
}

static int import_h (
		struct rrr_type_template *node,
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	return (RRR_TYPE_SYSTEM_ENDIAN_IS_LE ?
			import_le(node, parsed_bytes, start, end) :
			import_be(node, parsed_bytes, start, end)
	);
}

static int import_blob (
		struct rrr_type_template *node,
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

static int import_ustr (
		struct rrr_type_template *node,
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

	if (convert_unsigned_integer_10(&convert_end, &result, tmp)) {
		VL_MSG_ERR("Error while converting unsigned integer in import_ustr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	node->data = malloc(sizeof(rrr_type_ustr));
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_ustr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	memcpy(node->data, &result, sizeof(rrr_type_ustr));

	node->length = sizeof(rrr_type_ustr);

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}

static int import_istr (
		struct rrr_type_template *node,
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

	if (convert_integer_10(&convert_end, &result, tmp)) {
		VL_MSG_ERR("Error while converting unsigned integer in import_istr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	node->data = malloc(sizeof(rrr_type_istr));
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in import_istr\n");
		return RRR_TYPE_PARSE_ERR;
	}

	memcpy(node->data, &result, sizeof(rrr_type_istr));

	node->length = sizeof(rrr_type_ustr);

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}


static int import_sep (
		struct rrr_type_template *node,
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

int convert_le_64_to_host(void *data, rrr_type_length length) {
	if (length != sizeof(uint64_t)) {
		VL_MSG_ERR("Size of 64 type was not 4 bytes in convert_le_64_to_host\n");
		return 1;
	}
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = le64toh(temp);
	return 0;
}

int convert_be_64_to_host(void *data, rrr_type_length length) {
	if (length != sizeof(uint64_t)) {
		VL_MSG_ERR("Size of 64 type was not 4 bytes in convert_be_64_to_host\n");
		return 1;
	}
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = be64toh(temp);
	return 0;
}

int convert_h_64_to_host(void *data, rrr_type_length length) {
	if (length != sizeof(uint64_t)) {
		VL_MSG_ERR("Size of 64 type was not 4 bytes in convert_h_64_to_host\n");
		return 1;
	}
	uint64_t num = *((uint64_t*) data);
	VL_DEBUG_MSG_4("convert_h_64_to_host dummy convert of 0x%" PRIx64 "\n", num);
	return 0;
}

int convert_blob_to_host(void *target, rrr_type_length length) {
	if (length == 0) {
		VL_MSG_ERR("Length of blob type was 0 in convert_blob_to_host\n");
		return 1;
	}
	VL_DEBUG_MSG_4("convert_blob_to_host dummy convert first byte is %02x\n", *((char*)target));
	return 0;
}

// If there are types which begin with the same letters, the longest names must be first in the array
static const struct rrr_type_definition type_templates[] = {
		{RRR_TYPE_LE,		RRR_TYPE_MAX_LE,	import_le,		convert_le_64_to_host,	RRR_TYPE_NAME_LE},
		{RRR_TYPE_BE,		RRR_TYPE_MAX_BE,	import_be,		convert_be_64_to_host,	RRR_TYPE_NAME_BE},
		{RRR_TYPE_H,		RRR_TYPE_MAX_H,		import_h,		convert_h_64_to_host,	RRR_TYPE_NAME_H},
		{RRR_TYPE_BLOB,		RRR_TYPE_MAX_BLOB,	import_blob,	convert_blob_to_host,	RRR_TYPE_NAME_BLOB},
		{RRR_TYPE_USTR,		RRR_TYPE_MAX_USTR,	import_ustr,	convert_h_64_to_host,	RRR_TYPE_NAME_USTR},
		{RRR_TYPE_ISTR,		RRR_TYPE_MAX_ISTR,	import_istr,	convert_h_64_to_host,	RRR_TYPE_NAME_ISTR},
		{RRR_TYPE_SEP,		RRR_TYPE_MAX_SEP,	import_sep,		convert_blob_to_host,	RRR_TYPE_NAME_SEP},
		{RRR_TYPE_ARRAY,	RRR_TYPE_MAX_ARRAY,	NULL,			NULL,					RRR_TYPE_NAME_ARRAY},
		{0,					0,					NULL,			NULL,					NULL}
};

static const struct rrr_type_definition *__rrr_type_get_from_identifier (
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

static const struct rrr_type_definition *__rrr_type_get_from_type (uint8_t type_in) {
	for (unsigned int i = 0; i < sizeof(type_templates) / sizeof(type_templates[0]) - 1; i++) {
		const struct rrr_type_definition *type = &type_templates[i];
		if (type->type == type_in) {
			return type;
		}
	}

	return NULL;
}

static int __rrr_types_parse_identifier_and_size (
		const struct rrr_type_definition **type_return,
		unsigned int *length_return,
		ssize_t *bytes_parsed_return,
		const char *start,
		const char *end
) {
	int ret = 0;
	ssize_t parsed_bytes;

	*type_return = NULL;
	*length_return = 0;
	*bytes_parsed_return = 0;

	const struct rrr_type_definition *type = __rrr_type_get_from_identifier(&parsed_bytes, start, end);
	if (type == NULL) {
		VL_MSG_ERR("Unknown type identifier in type definition here --> '%s'\n", start);
		ret = 1;
		goto out;
	}
	start += parsed_bytes;

	unsigned long long int length = 0;
	if (type->max_length > 0) {
		if (*start == '\0' || start >= end) {
			VL_MSG_ERR("Missing size for type '%s' in type definition\n", type->identifier);
			ret = 1;
			goto out;
		}

		char *integer_end = NULL;
		if (convert_unsigned_integer_10(&integer_end, &length, start) != 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' was not a valid number\n",
					start, type->identifier);
			ret = 1;
			goto out;
		}

		if (length > 0xffffffff) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' was too long, max is 0xffffffff\n",
					start, type->identifier);
			ret = 1;
			goto out;
		}

		parsed_bytes += integer_end - start;

		if (length <= 0) {
			VL_MSG_ERR("Size argument '%lli' in type definition '%s' must be >0\n",
					length, type->identifier);
			ret = 1;
			goto out;
		}
	}

	*type_return = type;
	*length_return = length;
	*bytes_parsed_return = parsed_bytes;

	out:
	return ret;

}

int rrr_type_parse_definition (
		struct rrr_type_template_collection *target,
		struct rrr_instance_config *config,
		const char *cmd_key
) {
	int ret = 0;
	struct rrr_settings_list *list = NULL;

	memset (target, '\0', sizeof(*target));

	if (rrr_instance_config_split_commas_to_array (&list, config, cmd_key) != 0) {
		VL_MSG_ERR("Error while splitting comma list to array for instance %s setting %s\n", config->name, cmd_key);
		ret = 1;
		goto out_nofree;
	}

	ssize_t parsed_bytes = 0;
	for (unsigned int i = 0; i < list->length; i++) {
		const char *start = list->list[i];
		const char *end = start + strlen(start);
		rrr_array_size array_size = 1;

		if (*start == '\0' || start >= end) {
			break;
		}

		const struct rrr_type_definition *type = NULL;
		unsigned int length = 0;

		if ((ret = __rrr_types_parse_identifier_and_size (
				&type,
				&length,
				&parsed_bytes,
				start,
				end
		)) != 0) {
			VL_MSG_ERR("Error while parsing type identifier and size\n");
			goto out;
		}

		start += parsed_bytes;

		if (*start != '\0') {
			VL_MSG_ERR("Extra data after type definition here --> '%s'\n", start);
			ret = 1;
			goto out;
		}

		if (type->type == RRR_TYPE_ARRAY) {
			if (++i == list->length) {
				VL_MSG_ERR("Missing type definition after array\n");
			}

			array_size = length;
			if (array_size > RRR_TYPE_MAX_ARRAY) {
				VL_MSG_ERR("Array size in type definition exceeded maximum of %i (%i given)\n",
						RRR_TYPE_MAX_ARRAY, array_size);
			}

			if ((ret = __rrr_types_parse_identifier_and_size (
					&type,
					&length,
					&parsed_bytes,
					start,
					end
			)) != 0) {
				VL_MSG_ERR("Error while parsing type identifier and size after array\n");
				goto out;
			}
		}

		if (length > type->max_length) {
			VL_MSG_ERR("Size argument '%i' in type definition '%s' in '%s' is too large, max is '%u'\n",
					i, type->identifier, cmd_key, type->max_length);
			ret = 1;
			goto out;
		}

		if (i + 1 == list->length && type->max_length == 0) {
			VL_MSG_ERR("Type %s has dynamic size and cannot be at the end of a definition\n",
					type->identifier);
			return 1;
		}

		struct rrr_type_template *template = malloc(sizeof(*template));
		if (template == NULL) {
			VL_MSG_ERR("Could not allocate template in rrr_types_parse_definition\n");
			ret = 1;
			goto out;
		}

		memset(template, '\0', sizeof(*template));

		template->array_size = array_size;
		template->length = length;
		template->definition = type;

		RRR_LINKED_LIST_APPEND(target,template);
	}

	out:
		rrr_settings_list_destroy(list);
	out_nofree:
		return ret;
}

int rrr_type_parse_data_from_definition (
		struct rrr_type_template_collection *target,
		const char *data,
		const rrr_type_length length
) {
	int ret = RRR_TYPE_PARSE_OK;

	const char *pos = data;
	const char *end = data + length;

	if (length == 0) {
		VL_BUG("BUG: Length was 0 in rrr_types_parse_data\n");
	}

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("rrr_types_parse_data input: 0x");
		for (rrr_type_length i = 0; i < length; i++) {
			char c = data[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	int i = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(target,struct rrr_type_template);
		VL_DEBUG_MSG_3("Parsing type index %u of type %d, %d copies\n", i, node->definition->type, node->array_size);

		if (node->definition->import == NULL) {
			VL_BUG("BUG: No convert function found for type %d\n", node->definition->type);
		}

		ssize_t parsed_bytes = 0;

		if ((ret = node->definition->import(node, &parsed_bytes, pos, end)) != 0) {
			if (ret == RRR_TYPE_PARSE_INCOMPLETE) {
				goto out;
			}
			VL_MSG_ERR("Invalid data in type conversion\n");
			goto out;
		}

		if (parsed_bytes == 0) {
			VL_BUG("Parsed bytes was zero in rrr_types_parse_data\n");
		}

		if (node->data != NULL) {
			VL_BUG("node->data was not NULL in rrr_types_parse_data\n");
		}

		pos += parsed_bytes;
		i++;
	RRR_LINKED_LIST_ITERATE_END(definitions);

	out:
	return ret;
}

int rrr_type_definition_collection_clone (
		struct rrr_type_template_collection *target,
		const struct rrr_type_template_collection *source
) {
	memset(target, '\0', sizeof(*target));

	RRR_LINKED_LIST_ITERATE_BEGIN(source, const struct rrr_type_template);
		struct rrr_type_template *template = malloc(sizeof(*template));
		if (template == NULL) {
			VL_MSG_ERR("Could not allocate memory in rrr_type_definition_collection_clone\n");
			goto out_err;
		}
		memcpy(template, node, sizeof(*template));

		template->data = NULL;

		RRR_LINKED_LIST_APPEND(target,template);
	RRR_LINKED_LIST_ITERATE_END(source);

	return 0;

	out_err:
		RRR_LINKED_LIST_DESTROY(target, struct rrr_type_template, free(node));
		memset(target, '\0', sizeof(*target));
		return 1;
}


static void __rrr_type_template_destroy (struct rrr_type_template *template) {
	RRR_FREE_IF_NOT_NULL(template->data);
	free(template);
}

void rrr_type_template_collection_clear (struct rrr_type_template_collection *collection) {
	RRR_LINKED_LIST_DESTROY(collection,struct rrr_type_template,__rrr_type_template_destroy(node));
}

struct rrr_type_template *rrr_type_template_collection_get_by_idx (
		struct rrr_type_template_collection *definition,
		int idx
) {
	int i = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(definition, struct rrr_type_template);
		if (i == idx) {
			return node;
		}
		i++;
	RRR_LINKED_LIST_ITERATE_END(definition);

	return NULL;
}

static ssize_t __rrr_type_get_packet_length (const struct rrr_type_template_collection *definition) {
	ssize_t result = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_template);
		result += node->array_size * node->length + sizeof(struct rrr_type_data_packed) - 1;
	RRR_LINKED_LIST_ITERATE_END(definition);
	return result;
}

int rrr_type_new_message (
		struct vl_message **final_message,
		const struct rrr_type_template_collection *definition,
		uint64_t time
) {
	rrr_type_length total_data_length = __rrr_type_get_packet_length(definition);

	*final_message = NULL;

	struct vl_message_array *message = message_new_array(time, total_data_length);
	if (message == NULL) {
		VL_MSG_ERR("Could not create message for data collection\n");
		return 1;
	}

	message->type_head.endian_two = RRR_TYPE_ENDIAN_BYTES;
	message->type_head.version = RRR_TYPE_VERSION;

	char *pos = message->type_head.data_;

	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_template);
		struct rrr_type_data_packed head = {0};

		head.type = node->definition->type;
		head.length = node->length;
		head.array_size = node->array_size;

		if (node->data == NULL) {
			VL_BUG("Data not set for node in __rrr_type_pack_message\n");
		}

		memcpy(pos, &head, sizeof(head) - 1);
		pos += sizeof(head) - 1;
		memcpy(pos, node->data, node->length * node->array_size);
		pos += node->length * node->array_size;
	RRR_LINKED_LIST_ITERATE_END(definition);

	*final_message = (struct vl_message *) message;

	return 0;
}

int rrr_types_message_to_collection (
		struct rrr_type_template_collection *target,
		const struct vl_message *message_orig
) {
	memset(target, '\0', sizeof(*target));

	if (message_orig->class != MSG_CLASS_ARRAY) {
		VL_BUG("Message was not array in rrr_types_message_to_collection\n");
	}

	const struct vl_message_array *array = (struct vl_message_array *) message_orig;

	int is_be = 0;

	uint16_t version = (array->type_head.version);

	if (RRR_TYPE_DEF_IS_BE(&array->type_head)) {
		version = be16toh(version);
		is_be = 1;
	}
	else {
		version = le16toh(version);
	}

	if (version != RRR_TYPE_VERSION) {
		VL_MSG_ERR("Array message version mismatch in rrr_types_message_to_collection. Need V%i but got V%u.\n",
				RRR_TYPE_VERSION, array->type_head.version);
		goto out_free_data;
	}

	const char *pos = array->type_head.data_;
	const char *end = array->type_head.data_ + array->length - sizeof(array->type_head) - 1;

	int i = 0;
	while (pos < end) {
		struct rrr_type_data_packed *data_packed = (struct rrr_type_data_packed *) pos;
		pos += sizeof(struct rrr_type_data_packed);

		if (pos > end) {
			VL_MSG_ERR("Data type with index %i was too short in array\n", i);
			goto out_free_data;
		}

		rrr_type type = data_packed->type;
		rrr_type_length length = data_packed->length;
		rrr_array_size array_size = data_packed->array_size;

		if (is_be != 0) {
			length = be32toh(length);
			array_size = be32toh(array_size);
		}
		else {
			length = le32toh(length);
			array_size = le32toh(array_size);
		}

		if (pos + length > end) {
			VL_MSG_ERR("Length of type %u index %i in array message exceeds total length\n", type, i);
			goto out_free_data;
		}

		const struct rrr_type_definition *def = __rrr_type_get_from_type(type);
		if (def == NULL) {
			VL_MSG_ERR("Unknown type %u in type index %i of array message\n", type, i);
			goto out_free_data;
		}

		struct rrr_type_template *template = malloc(sizeof(*template));
		if (template == NULL) {
			VL_MSG_ERR("Could not allocate memory for template in rrr_types_message_to_collection\n");
			goto out_free_data;
		}
		memset (template, '\0', sizeof(*template));

		RRR_LINKED_LIST_APPEND(target,template);

		template->data = malloc(length);
		if (template->data == NULL) {
			VL_MSG_ERR("Could no allocate memory for template data in rrr_types_message_to_collection\n");
			goto out_free_data;
		}

		template->array_size = array_size;
		template->length = length;
		template->definition = def;
		memcpy (template->data, pos, template->length);

		pos += template->length;

		if (template->definition->to_host(template->data, template->length) != 0) {
			VL_MSG_ERR("Error while converting endianess for type %u index %i of array message\n", type, i);
			goto out_free_data;
		}

		i++;
	}

	return 0;

	out_free_data:
		rrr_type_template_collection_clear(target);
		return 1;
}
