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

#include "../global.h"
#include "array.h"
#include "rrr_endian.h"
#include "cmdlineparser/cmdline.h"
#include "settings.h"
#include "instance_config.h"
#include "messages.h"
#include "type.h"
#include "vl_time.h"

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
	else {
		if (*start != '\0' && *start != '#') {
			VL_MSG_ERR("Extra data or size argument after type definition '%s' which has automatic size\n",
					type->identifier);
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

int rrr_array_parse_single_definition (
		struct rrr_array *target,
		const char *start,
		const char *end
) {
	int ret = 0;

	ssize_t parsed_bytes = 0;
	rrr_type_array_size array_size = 1;
	const struct rrr_type_definition *type = NULL;
	unsigned int length = 0;
	const char *tag_start = NULL;
	unsigned int tag_length = 0;

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

	if (*start == '#') {
		start++;
		tag_start = start;

		while (*start != '\0') {
			tag_length++;
			start++;
		}

		if (tag_length == 0) {
			VL_MSG_ERR("Missing tag name after #\n");
			ret = 1;
			goto out;
		}
	}

	if (*start != '\0') {
		VL_MSG_ERR("Extra data after type definition here --> '%s'\n", start);
		ret = 1;
		goto out;
	}

	if (length > type->max_length) {
		VL_MSG_ERR("Size argument in type definition '%s' is too large, max is '%u'\n",
				type->identifier, type->max_length);
		ret = 1;
		goto out;
	}

	struct rrr_type_value *template = NULL;

	if (rrr_type_value_new (
			&template,
			type,
			tag_length,
			tag_start,
			length,
			array_size,
			0
	) != 0) {
		VL_MSG_ERR("Could not create value in rrr_array_parse_definition\n");
		ret = 1;
		goto out;
	}

	RRR_LINKED_LIST_APPEND(target,template);

	out:
	return ret;
}

int rrr_array_parse_single_definition_callback (
		const char *value,
		void *arg
) {
	struct rrr_array_parse_single_definition_callback_data *data = arg;
	if (rrr_array_parse_single_definition(data->target, value, value + strlen(value)) != 0) {
		data->parse_ret = 1;
		return 1;
	}
	return 0;
}

int rrr_array_validate_definition (
		const struct rrr_array *target
) {
	int ret = 0;

	struct rrr_type_value *node = RRR_LINKED_LIST_LAST(target);

	if (node == NULL) {
		goto out;
	}

	if (node->definition->max_length == 0 && node->definition->type != RRR_TYPE_MSG && node->definition->type != RRR_TYPE_STR) {
		VL_MSG_ERR("Type %s has dynamic size and cannot be at the end of a definition\n",
				node->definition->identifier);
		return 1;
	}

	out:
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
		VL_BUG("BUG: Length was 0 in rrr_array_parse_data_from_definition\n");
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
		VL_DEBUG_MSG_3("Parsing type index %u of type %d, %d copies\n", i, node->definition->type, node->element_count);

		if (node->definition->import == NULL) {
			VL_BUG("BUG: No convert function found for type %d\n", node->definition->type);
		}

		ssize_t parsed_bytes = 0;

		if (node->data != NULL) {
			VL_BUG("node->data was not NULL in rrr_array_parse_data_from_definition\n");
		}

		if ((ret = node->definition->import(node, &parsed_bytes, pos, end)) != 0) {
			if (ret == RRR_TYPE_PARSE_INCOMPLETE) {
				goto out;
			}
			VL_MSG_ERR("Invalid data in type conversion\n");
			goto out;
		}

		if (parsed_bytes == 0) {
			VL_BUG("Parsed bytes was zero in rrr_array_parse_data_from_definition\n");
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

		if (template->tag_length > 0) {
			template->tag = malloc(template->tag_length);
			if (template->tag == NULL) {
				VL_MSG_ERR("Could not allocate memory for tag in rrr_array_definition_collection_clone\n");
				goto out_err;
			}
			memcpy(template->tag, node->tag, template->tag_length);
		}
		else if (template->tag != NULL) {
			VL_BUG("tag was not NULL but tag length was >0 in rrr_array_definition_collection_clone\n");
		}

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


struct rrr_type_value *rrr_array_value_get_by_tag (
		struct rrr_array *definition,
		const char *tag
) {
	RRR_LINKED_LIST_ITERATE_BEGIN(definition, struct rrr_type_value);
		if (node->tag != NULL) {
			if (strcmp(node->tag, tag) == 0) {
				return node;
			}
		}
	RRR_LINKED_LIST_ITERATE_END(definition);

	return NULL;
}

int rrr_array_get_packed_length_from_buffer (
		ssize_t *import_length,
		const struct rrr_array *definition,
		const char *buf,
		ssize_t buf_length
) {
	int ret = RRR_TYPE_PARSE_OK;

	*import_length = 0;

	const char *pos = buf;
	ssize_t remaining_buf_length = buf_length;
	ssize_t result_final = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_value);
		if (remaining_buf_length <= 0) {
			return RRR_TYPE_PARSE_INCOMPLETE;
		}

		ssize_t result = 0;
		if ((ret = node->definition->get_import_length (
				&result,
				node,
				pos,
				remaining_buf_length
		)) != RRR_TYPE_PARSE_OK) {
			return ret;
		}

		pos += result;
		remaining_buf_length -= result;
		result_final += result;
	RRR_LINKED_LIST_ITERATE_END(definition);

	*import_length = result_final;

	return ret;
}

static ssize_t __rrr_array_get_packed_length (
		const struct rrr_array *definition
) {
	ssize_t result = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_value);
		result += node->total_stored_length + sizeof(struct rrr_array_value_packed) - 1;
		result += node->tag_length;
	RRR_LINKED_LIST_ITERATE_END(definition);
	return result;
}

int rrr_array_new_message_from_buffer (
		const char *buf,
		ssize_t buf_len,
		const struct rrr_array *definition,
		int (*callback)(struct vl_message *message, void *arg),
		void *callback_arg
) {
	struct vl_message *message = NULL;
	int ret = 0;

	if (rrr_array_validate_definition(definition) != 0) {
		VL_BUG("Definition was not valid in rrr_array_definition_collection_clone\n");
	}

	struct rrr_array definitions;

	if (rrr_array_definition_collection_clone(&definitions, definition) != 0) {
		VL_MSG_ERR("Could not clone definitions in rrr_array_new_message_from_buffer\n");
		return 1;
	}

	if (rrr_array_parse_data_from_definition(&definitions, buf, buf_len) != 0) {
		VL_MSG_ERR("Invalid packet in rrr_array_new_message_from_buffer\n");
		ret = 0;
		goto out_destroy;
	}

	if ((ret = rrr_array_new_message(&message, &definitions, time_get_64())) != 0) {
		VL_MSG_ERR("Could not create message in rrr_array_new_message_from_buffer\n");
		goto out_destroy;
	}

	if (message != NULL) {
		ret = callback(message, callback_arg);
		message = NULL;
	}

	out_destroy:
	rrr_array_clear(&definitions);
	RRR_FREE_IF_NOT_NULL(message);

	return ret;
}

int rrr_array_new_message (
		struct vl_message **final_message,
		const struct rrr_array *definition,
		uint64_t time
) {
	int ret = 0;

	*final_message = NULL;

	rrr_type_length total_data_length = __rrr_array_get_packed_length(definition);

	struct vl_message *message = message_new_array(time, 0, total_data_length);
	if (message == NULL) {
		VL_MSG_ERR("Could not create message for data collection\n");
		ret = 1;
		goto out;
	}

	message->version = RRR_ARRAY_VERSION;

	char *pos = MSG_DATA_PTR(message);
	ssize_t written_bytes_total = 0;

	RRR_LINKED_LIST_ITERATE_BEGIN(definition, const struct rrr_type_value);
		if (node->data == NULL) {
			VL_BUG("Data not set for node in rrr_array_new_message\n");
		}

		uint8_t type = node->definition->type;

		if (node->definition->pack == NULL) {
			VL_BUG("No pack function defined for type %u\n", type);
		}

		struct rrr_array_value_packed *head = (struct rrr_array_value_packed *) pos;

		head->type = type;
		head->tag_length = htobe32(node->tag_length);
		head->elements = htobe32(node->element_count);
		head->total_length = htobe32(node->total_stored_length);

		pos += sizeof(*head) - 1;
		written_bytes_total += sizeof(*head) - 1;

		if (node->tag_length > 0) {
			memcpy(pos, node->tag, node->tag_length);
			pos += node->tag_length;
			written_bytes_total += node->tag_length;
		}

		uint8_t new_type = 0;
		ssize_t written_bytes = 0;

		if (node->definition->pack(pos, &written_bytes, &new_type, node) != 0) {
			VL_MSG_ERR("Error while packing data of type %u in rrr_array_new_message\n", node->definition->type);
			ret = 1;
			goto out;
		}

		if (new_type != head->type) {
			head->type = new_type;
		}

		if (written_bytes != node->total_stored_length) {
			VL_BUG("Size mismatch in rrr_array_new_message\n");
		}

		pos += written_bytes;
		written_bytes_total += written_bytes;
	RRR_LINKED_LIST_ITERATE_END(definition);

	if (written_bytes_total != total_data_length) {
		VL_BUG("Length mismatch after assembling message in rrr_array_new_message %li<>%lu\n",
				written_bytes_total, MSG_DATA_LENGTH(message));
	}

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("rrr_array_new_message output (data of message only): 0x");
		for (rrr_type_length i = 0; i < MSG_DATA_LENGTH(message); i++) {
			char c = MSG_DATA_PTR(message)[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	*final_message = (struct vl_message *) message;
	message = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
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

	const char *pos = MSG_DATA_PTR(array);
	const char *end = MSG_DATA_PTR(array) + MSG_DATA_LENGTH(array);

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("rrr_array_message_to_collection input (data of message only): 0x");
		for (rrr_type_length i = 0; i < MSG_DATA_LENGTH(array); i++) {
			char c = MSG_DATA_PTR(array)[i];
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
		rrr_type_length tag_length = be32toh(data_packed->tag_length);
		rrr_type_length total_length = be32toh(data_packed->total_length);
		rrr_type_length elements = be32toh(data_packed->elements);

		if (pos + tag_length + total_length > end) {
			VL_MSG_ERR("Length of type %u index %i in array message exceeds total length (%u > %li)\n",
					type, i, total_length, end - pos);
			goto out_free_data;
		}

		const struct rrr_type_definition *def = rrr_type_get_from_id(type);
		if (def == NULL) {
			VL_MSG_ERR("Unknown type %u in type index %i of array message\n", type, i);
			goto out_free_data;
		}

		if (def->unpack == NULL) {
			VL_MSG_ERR("Illegal type in array message %u/%s\n",
					def->type, def->identifier);
			goto out_free_data;
		}

		struct rrr_type_value *template = NULL;
		if (rrr_type_value_new (
				&template,
				def,
				tag_length,
				pos,
				total_length,
				elements,
				total_length
		) != 0) {
			VL_MSG_ERR("Could not allocate value in rrr_array_message_to_collection\n");
			goto out_free_data;
		}
		RRR_LINKED_LIST_APPEND(target,template);

		pos += tag_length;

		memcpy (template->data, pos, total_length);

		if (template->definition->unpack(template) != 0) {
			VL_MSG_ERR("Error while converting endianess for type %u index %i of array message\n", type, i);
			goto out_free_data;
		}

		pos += total_length;
		i++;
	}

	return 0;

	out_free_data:
		rrr_array_clear(target);
		return 1;
}
