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
#include <inttypes.h>

#include "array.h"
#include "rrr_endian.h"
#include "cmdlineparser/cmdline.h"
#include "settings.h"
#include "instance_config.h"
#include "messages.h"
#include "../global.h"
#include "type.h"

static int __rrr_array_convert_unsigned_integer_10(char **end, unsigned long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoull(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

static int __rrr_array_parse_identifier_and_size (
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

	const struct rrr_type_definition *type = rrr_type_parse_from_string(&parsed_bytes, start, end);
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
		if (__rrr_array_convert_unsigned_integer_10(&integer_end, &length, start) != 0) {
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

int rrr_array_parse_definition (
		struct rrr_array *target,
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
		rrr_type_array_size array_size = 1;

		if (*start == '\0' || start >= end) {
			break;
		}

		const struct rrr_type_definition *type = NULL;
		unsigned int length = 0;

		if ((ret = __rrr_array_parse_identifier_and_size (
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

		if (type->type == RRR_TYPE_ARRAY) {
			if (*start == '\0') {
				VL_MSG_ERR("Missing type definition after array\n");

			}
			if (*start != '@') {
				VL_MSG_ERR("Expected @ followed by type after array definition\n");

			}

			start++;

			array_size = length;
			if (array_size > RRR_TYPE_MAX_ARRAY) {
				VL_MSG_ERR("Array size in type definition exceeded maximum of %i (%i given)\n",
						RRR_TYPE_MAX_ARRAY, array_size);
			}

			if ((ret = __rrr_array_parse_identifier_and_size (
					&type,
					&length,
					&parsed_bytes,
					start,
					end
			)) != 0) {
				VL_MSG_ERR("Error while parsing type identifier and size after array\n");
				goto out;
			}

			start += parsed_bytes;
		}

		if (*start != '\0') {
			VL_MSG_ERR("Extra data after type definition here --> '%s'\n", start);
			ret = 1;
			goto out;
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

		struct rrr_type_value *template = NULL;

		if (rrr_type_value_new(&template, type, length, array_size) != 0) {
			VL_MSG_ERR("Could not create value in rrr_array_parse_definition\n");
			ret = 1;
			goto out;
		}

		RRR_LINKED_LIST_APPEND(target,template);
	}

	out:
		rrr_settings_list_destroy(list);
	out_nofree:
		return ret;
}

int rrr_array_parse_data_from_definition (
		struct rrr_array *target,
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
	RRR_LINKED_LIST_ITERATE_BEGIN(target,struct rrr_type_value);
		VL_DEBUG_MSG_3("Parsing type index %u of type %d, %d copies\n", i, node->definition->type, node->array_size);

		if (node->definition->import == NULL) {
			VL_BUG("BUG: No convert function found for type %d\n", node->definition->type);
		}

		ssize_t parsed_bytes = 0;

		if (node->data != NULL) {
			VL_BUG("node->data was not NULL in rrr_types_parse_data\n");
		}

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

		pos += parsed_bytes;
		i++;
	RRR_LINKED_LIST_ITERATE_END(definitions);

	out:
	return ret;
}

int rrr_array_definition_collection_clone (
		struct rrr_array *target,
		const struct rrr_array *source
) {
	memset(target, '\0', sizeof(*target));

	RRR_LINKED_LIST_ITERATE_BEGIN(source, const struct rrr_type_value);
		struct rrr_type_value *template = malloc(sizeof(*template));
		if (template == NULL) {
			VL_MSG_ERR("Could not allocate memory in rrr_array_definition_collection_clone\n");
			goto out_err;
		}
		memcpy(template, node, sizeof(*template));

		template->data = NULL;

		RRR_LINKED_LIST_APPEND(target,template);
	RRR_LINKED_LIST_ITERATE_END(source);

	return 0;

	out_err:
		RRR_LINKED_LIST_DESTROY(target, struct rrr_type_value, free(node));
		memset(target, '\0', sizeof(*target));
		return 1;
}

void rrr_array_clear (struct rrr_array *collection) {
	RRR_LINKED_LIST_DESTROY(collection,struct rrr_type_value,rrr_type_value_destroy(node));
}

struct rrr_type_value *rrr_array_value_get_by_index (
		struct rrr_array *definition,
		int idx
) {
	int i = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(definition, struct rrr_type_value);
		if (i == idx) {
			return node;
		}
		i++;
	RRR_LINKED_LIST_ITERATE_END(definition);

	return NULL;
}

static ssize_t __rrr_array_get_packed_length (
		const struct rrr_array *definition
) {
	ssize_t result = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_value);
		result += node->array_size * node->length + sizeof(struct rrr_array_value_packed) - 1;
	RRR_LINKED_LIST_ITERATE_END(definition);
	return result;
}

int rrr_array_new_message (
		struct vl_message **final_message,
		const struct rrr_array *definition,
		uint64_t time
) {
	rrr_type_length total_data_length = __rrr_array_get_packed_length(definition);

	*final_message = NULL;

	struct vl_message *message = message_new_array(time, total_data_length);
	if (message == NULL) {
		VL_MSG_ERR("Could not create message for data collection\n");
		return 1;
	}

	message->version = RRR_ARRAY_VERSION;

	char *pos = message->data_;
	char tmp_data[sizeof(rrr_type_be)];

	ssize_t written_bytes = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_value);
		struct rrr_array_value_packed head = {0};

		if (node->data == NULL) {
			VL_BUG("Data not set for node in rrr_array_new_message\n");
		}

		uint8_t type = node->definition->type;
		const char *data = node->data;

		if (type == RRR_TYPE_H) {
			type = RRR_TYPE_BE;
			*((rrr_type_be *) tmp_data) = htobe64(*((rrr_type_be *) node->data));
			data = tmp_data;
		}
		else if (
			type != RRR_TYPE_BLOB &&
			type != RRR_TYPE_SEP
		) {
			VL_BUG("Illegal type %u in rrr_array_new_message\n", type);
		}

		head.type = type;
		head.length = htobe32(node->length);
		head.array_size = htobe32(node->array_size);

		memcpy(pos, &head, sizeof(head) - 1);
		pos += sizeof(head) - 1;
		memcpy(pos, data, node->length * node->array_size);
		pos += node->length * node->array_size;

		written_bytes += sizeof(head) - 1 + node->length * node->array_size;
	RRR_LINKED_LIST_ITERATE_END(definition);

	if (written_bytes != message->length) {
		VL_BUG("Length mismatch after assembling message in rrr_array_new_message %li<>%" PRIu32 "\n",
				written_bytes, message->length);
	}

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("rrr_array_new_message output (data of message only): 0x");
		for (rrr_type_length i = 0; i < message->length; i++) {
			char c = message->data_[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	*final_message = (struct vl_message *) message;

	return 0;
}

int rrr_array_message_to_collection (
		struct rrr_array *target,
		const struct vl_message *message_orig
) {
	memset(target, '\0', sizeof(*target));

	if (message_orig->class != MSG_CLASS_ARRAY) {
		VL_BUG("Message was not array in rrr_array_message_to_collection\n");
	}

	const struct vl_message *array = (struct vl_message *) message_orig;

	uint16_t version = array->version;

	if (version != RRR_ARRAY_VERSION) {
		VL_MSG_ERR("Array message version mismatch in rrr_array_message_to_collection. Need V%i but got V%u.\n",
				RRR_ARRAY_VERSION, array->version);
		goto out_free_data;
	}

	const char *pos = array->data_;
	const char *end = array->data_ + array->length;

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("rrr_array_message_to_collection input (data of message only): 0x");
		for (rrr_type_length i = 0; i < array->length; i++) {
			char c = array->data_[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	int i = 0;
	while (pos < end) {
		struct rrr_array_value_packed *data_packed = (struct rrr_array_value_packed *) pos;
		pos += sizeof(struct rrr_array_value_packed) - 1;

		if (pos > end) {
			VL_MSG_ERR("Data type with index %i was too short in array\n", i);
			goto out_free_data;
		}

		rrr_type type = data_packed->type;
		rrr_type_length length = be32toh(data_packed->length);
		rrr_type_array_size array_size = be32toh(data_packed->array_size);

		if (pos + length * array_size > end) {
			VL_MSG_ERR("Length of type %u index %i in array message exceeds total length (%u > %li)\n",
					type, i, length * array_size, end - pos);
			goto out_free_data;
		}

		const struct rrr_type_definition *def = rrr_type_get_from_id(type);
		if (def == NULL) {
			VL_MSG_ERR("Unknown type %u in type index %i of array message\n", type, i);
			goto out_free_data;
		}

		if (def->to_host == NULL) {
			VL_MSG_ERR("Illegal type in array message %u/%s\n",
					def->type, def->identifier);
			goto out_free_data;
		}

		struct rrr_type_value *template = malloc(sizeof(*template));
		if (template == NULL) {
			VL_MSG_ERR("Could not allocate memory for template in rrr_array_message_to_collection\n");
			goto out_free_data;
		}
		memset (template, '\0', sizeof(*template));

		RRR_LINKED_LIST_APPEND(target,template);

		template->data = malloc(length * array_size);
		if (template->data == NULL) {
			VL_MSG_ERR("Could no allocate memory for template data in rrr_array_message_to_collection\n");
			goto out_free_data;
		}

		memcpy (template->data, pos, length * array_size);

		template->array_size = array_size;
		template->length = length;
		template->definition = def;

		if (template->definition->to_host(template) != 0) {
			VL_MSG_ERR("Error while converting endianess for type %u index %i of array message\n", type, i);
			goto out_free_data;
		}

		pos += length * array_size;
		i++;
	}

	return 0;

	out_free_data:
		rrr_array_clear(target);
		return 1;
}
