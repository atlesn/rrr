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

static int __rrr_array_convert_unsigned_integer_10(const char **end, unsigned long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoull(value, (char **) end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

static int __rrr_array_parse_identifier_and_size (
		const struct rrr_type_definition **type_return,
		unsigned int *length_return,
		unsigned int *item_count_return,
		rrr_type_flags *flags_return,
		ssize_t *bytes_parsed_return,
		const char *start,
		const char *end
) {
	ssize_t parsed_bytes = 0;
	rrr_type_flags flags = 0;
	const struct rrr_type_definition *type = NULL;
	unsigned long long int length = 0;
	unsigned long long int item_count = 1;

	const char *integer_end = NULL;

	*type_return = NULL;
	*length_return = 0;
	*item_count_return = 0;
	*bytes_parsed_return = 0;
	*flags_return = 0;

	type = rrr_type_parse_from_string(&parsed_bytes, start, end);
	if (type == NULL) {
		RRR_MSG_ERR("Unknown type identifier in type definition here --> '%s'\n", start);
		goto out_err;
	}
	start += parsed_bytes;

	if (type->max_length > 0) {
		if (start >= end || *start == '\0') {
			RRR_MSG_ERR("Missing size for type '%s' in type definition\n", type->identifier);
			goto out_err;
		}

		if (__rrr_array_convert_unsigned_integer_10(&integer_end, &length, start) != 0) {
			RRR_MSG_ERR("Size argument '%s' in type definition '%s' was not a valid number\n",
					start, type->identifier);
			goto out_err;
		}

		if (length > 0xffffffff) {
			RRR_MSG_ERR("Size argument '%s' in type definition '%s' was too long, max is 0xffffffff\n",
					start, type->identifier);
			goto out_err;
		}

		parsed_bytes += integer_end - start;
		start = integer_end;

		if (length <= 0) {
			RRR_MSG_ERR("Size argument '%lli' in type definition '%s' must be >0\n",
					length, type->identifier);
			goto out_err;
		}

		if (start >= end || *start == '\0') {
			goto out_ok;
		}

		if (*start == 's' || *start == 'S' || *start == 'u' || *start == 'U') {
			if (!RRR_TYPE_ALLOWS_SIGN(type->type)) {
				RRR_MSG_ERR("Sign indicator '%c' found in type definition for type '%s' which does not support being signed\n",
						*start, type->identifier);
				goto out_err;
			}

			if (*start == 's' || *start == 'S') {
				RRR_TYPE_FLAG_SET_SIGNED(flags);
			}

			start++;
			parsed_bytes++;
		}
		else if (RRR_TYPE_ALLOWS_SIGN(type->type)) {
			RRR_TYPE_FLAG_SET_UNSIGNED(flags);
		}
	}
	else {
		if (*start != '\0' && *start != '#' && *start != '@') {
			RRR_MSG_ERR("Extra data or size argument after type definition '%s' which has automatic size\n",
					type->identifier);
			goto out_err;
		}
	}

	if (start >= end || *start == '\0') {
		goto out_ok;
	}

	if (*start == '@') {
		start++;
		parsed_bytes++;

		if (start >= end || *start == '\0') {
			RRR_MSG_ERR("Item count missing after item count definition @ in type %s\n", type->identifier);
			goto out_err;
		}

		if (__rrr_array_convert_unsigned_integer_10(&integer_end, &item_count, start) != 0) {
			RRR_MSG_ERR("Item count argument '%s' in type definition '%s' was not a valid number\n",
					start, type->identifier);
			goto out_err;
		}

		parsed_bytes += integer_end - start;
		start = integer_end;

		if (item_count == 0) {
			RRR_MSG_ERR("Item count definition @ was zero after type '%s', must be in the range 1-65535\n",
					type->identifier);
			goto out_err;
		}
		if (item_count > 0xffffffff) {
			RRR_MSG_ERR("Item count definition @ was too big after type '%s', must be in the range 1-65535\n",
					type->identifier);
			goto out_err;
		}
		/*
		 *  XXX  : It is not possible to allow multiple values for these types as multiple values
		 *         in a node must have equal lengths
		 *         && type->type != RRR_TYPE_STR && type->type != RRR_TYPE_MSG
		 */
		if (item_count > 1 && type->max_length == 0) {
			RRR_MSG_ERR("Item count definition @ found after type '%s' which cannot have multiple values\n",
					type->identifier);
			goto out_err;
		}
	}

	out_ok:
		*type_return = type;
		*length_return = length;
		*item_count_return = item_count;
		*flags_return = flags;
		*bytes_parsed_return = parsed_bytes;
		return 0;

	out_err:
		return 1;
}

int rrr_array_parse_single_definition (
		struct rrr_array *target,
		const char *start,
		const char *end
) {
	int ret = 0;

	ssize_t parsed_bytes = 0;
	const struct rrr_type_definition *type = NULL;
	unsigned int length = 0;
	unsigned int item_count = 0;
	rrr_type_flags flags = 0;
	const char *tag_start = NULL;
	unsigned int tag_length = 0;

	if ((ret = __rrr_array_parse_identifier_and_size (
			&type,
			&length,
			&item_count,
			&flags,
			&parsed_bytes,
			start,
			end
	)) != 0) {
		RRR_MSG_ERR("Error while parsing type identifier and size\n");
		goto out;
	}

	start += parsed_bytes;

	if (*start == '#') {
		start++;
		tag_start = start;

		while (*start != '\0') {
			tag_length++;
			start++;
		}

		if (tag_length == 0) {
			RRR_MSG_ERR("Missing tag name after #\n");
			ret = 1;
			goto out;
		}
	}

	if (*start != '\0') {
		RRR_MSG_ERR("Extra data after type definition here --> '%s'\n", start);
		ret = 1;
		goto out;
	}

	if (length > type->max_length) {
		RRR_MSG_ERR("Size argument in type definition '%s' is too large, max is '%u'\n",
				type->identifier, type->max_length);
		ret = 1;
		goto out;
	}

	struct rrr_type_value *template = NULL;

	if (rrr_type_value_new (
			&template,
			type,
			flags,
			tag_length,
			tag_start,
			length,
			item_count,
			0
	) != 0) {
		RRR_MSG_ERR("Could not create value in rrr_array_parse_definition\n");
		ret = 1;
		goto out;
	}

	RRR_LL_APPEND(target,template);

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

	struct rrr_type_value *node = RRR_LL_LAST(target);

	if (node == NULL) {
		goto out;
	}

	if (node->definition->max_length == 0 &&
		node->definition->type != RRR_TYPE_MSG &&
		node->definition->type != RRR_TYPE_STR &&
		node->definition->type != RRR_TYPE_NSEP
	) {
		RRR_MSG_ERR("Type %s has dynamic size and cannot be at the end of a definition\n",
				node->definition->identifier);
		ret = 1;
	}

	RRR_LL_ITERATE_BEGIN(target, const struct rrr_type_value);
		if (prev != NULL) {
			if (prev->definition->max_length == 0 &&
				prev->definition->type != RRR_TYPE_STR &&
				prev->definition->type != RRR_TYPE_NSEP &&
				node->definition->max_length == 0 &&
				node->definition->type != RRR_TYPE_STR
			) {
				RRR_MSG_ERR("Type %s cannot be followed type %s in array definition as we cannot know where the first ends, use a separator in between\n",
						prev->definition->identifier, node->definition->identifier);
				ret = 1;
			}
		}
		prev = node;
	RRR_LL_ITERATE_END(target);

	out:
	return ret;
}

int rrr_array_parse_data_from_definition (
		struct rrr_array *target,
		ssize_t *parsed_bytes_final,
		const char *data,
		const rrr_type_length length
) {
	int ret = RRR_TYPE_PARSE_OK;

	const char *pos = data;
	const char *end = data + length;

	if (length == 0) {
		RRR_BUG("BUG: Length was 0 in rrr_array_parse_data_from_definition\n");
	}

	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG("rrr_types_parse_data input: 0x");
		for (rrr_type_length i = 0; i < length; i++) {
			char c = data[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
	}

	int i = 0;
	RRR_LL_ITERATE_BEGIN(target,struct rrr_type_value);
		RRR_DBG_3("Parsing type index %u of type %d, %d copies\n", i, node->definition->type, node->element_count);

		if (node->definition->import == NULL) {
			RRR_BUG("BUG: No convert function found for type %d\n", node->definition->type);
		}

		ssize_t parsed_bytes = 0;

		if (node->data != NULL) {
			RRR_BUG("node->data was not NULL in rrr_array_parse_data_from_definition\n");
		}

		if ((ret = node->definition->import(node, &parsed_bytes, pos, end)) != 0) {
			if (ret == RRR_TYPE_PARSE_INCOMPLETE) {
				goto out;
			}
			else if (ret == RRR_TYPE_PARSE_SOFT_ERR) {
				RRR_MSG_ERR("Invalid data in type conversion\n");
			}
			else {
				RRR_MSG_ERR("Hard error while importing data in rrr_array_parse_data_from_definition, return was %i\n", ret);
				ret = RRR_TYPE_PARSE_HARD_ERR;
			}
			goto out;
		}

		if (parsed_bytes == 0) {
			RRR_BUG("Parsed bytes was zero in rrr_array_parse_data_from_definition\n");
		}

		pos += parsed_bytes;
		i++;
	RRR_LL_ITERATE_END(definitions);

	*parsed_bytes_final = pos - data;

	out:
	return ret;
}

int rrr_array_definition_collection_clone (
		struct rrr_array *target,
		const struct rrr_array *source
) {
	memset(target, '\0', sizeof(*target));

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_type_value);
		struct rrr_type_value *template = malloc(sizeof(*template));
		if (template == NULL) {
			RRR_MSG_ERR("Could not allocate memory in rrr_array_definition_collection_clone\n");
			goto out_err;
		}
		memcpy(template, node, sizeof(*template));

		template->data = NULL;

		if (template->tag_length > 0) {
			template->tag = malloc(template->tag_length);
			if (template->tag == NULL) {
				RRR_MSG_ERR("Could not allocate memory for tag in rrr_array_definition_collection_clone\n");
				goto out_err;
			}
			memcpy(template->tag, node->tag, template->tag_length);
		}
		else if (template->tag != NULL) {
			RRR_BUG("tag was not NULL but tag length was >0 in rrr_array_definition_collection_clone\n");
		}

		RRR_LL_APPEND(target,template);
	RRR_LL_ITERATE_END(source);

	target->version = source->version;

	return 0;

	out_err:
		RRR_LL_DESTROY(target, struct rrr_type_value, free(node));
		memset(target, '\0', sizeof(*target));
		return 1;
}

void rrr_array_clear (struct rrr_array *collection) {
	RRR_LL_DESTROY(collection,struct rrr_type_value,rrr_type_value_destroy(node));
}

struct rrr_type_value *rrr_array_value_get_by_index (
		struct rrr_array *definition,
		int idx
) {
	int i = 0;

	RRR_LL_ITERATE_BEGIN(definition, struct rrr_type_value);
		if (i == idx) {
			return node;
		}
		i++;
	RRR_LL_ITERATE_END(definition);

	return NULL;
}


struct rrr_type_value *rrr_array_value_get_by_tag (
		struct rrr_array *definition,
		const char *tag
) {
	RRR_LL_ITERATE_BEGIN(definition, struct rrr_type_value);
		if (node->tag != NULL) {
			if (strcmp(node->tag, tag) == 0) {
				return node;
			}
		}
	RRR_LL_ITERATE_END(definition);

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
	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
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
	RRR_LL_ITERATE_END(definition);

	*import_length = result_final;

	return ret;
}

static ssize_t __rrr_array_get_packed_length (
		const struct rrr_array *definition
) {
	ssize_t result = 0;
	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
		result += node->total_stored_length + sizeof(struct rrr_array_value_packed) - 1;
		result += node->tag_length;
	RRR_LL_ITERATE_END(definition);
	return result;
}

static int __rrr_array_parse_from_buffer (
		struct rrr_array *target,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t buf_len,
		const struct rrr_array *definition
) {
	int ret = 0;

	if (rrr_array_validate_definition(definition) != 0) {
		RRR_BUG("Definition was not valid in __rrr_array_parse_from_buffer\n");
	}

	if (rrr_array_definition_collection_clone(target, definition) != 0) {
		RRR_MSG_ERR("Could not clone definitions in __rrr_array_parse_from_buffer\n");
		ret = RRR_ARRAY_PARSE_HARD_ERR;
		goto out;
	}

	if ((ret = rrr_array_parse_data_from_definition(target, parsed_bytes, buf, buf_len)) != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			RRR_MSG_ERR("Invalid packet in __rrr_array_parse_from_buffer\n");
			ret = RRR_ARRAY_PARSE_SOFT_ERR;
		}
		else if (ret == RRR_ARRAY_PARSE_INCOMPLETE) {
			// OK
		}
		else {
			ret = RRR_ARRAY_PARSE_HARD_ERR;
		}
		goto out;
	}

	out:
	return ret;
}

int rrr_array_parse_and_unpack_from_buffer (
		struct rrr_array *target,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t buf_len,
		const struct rrr_array *definition
) {
	int ret = 0;

	if ((ret = __rrr_array_parse_from_buffer(target, parsed_bytes, buf, buf_len, definition)) != 0) {
		goto out;
	}

	int i = 0;
	RRR_LL_ITERATE_BEGIN(target, struct rrr_type_value);
		if (node->definition->unpack == NULL) {
			RRR_MSG_ERR("Illegal type in array %u/%s index %i\n",
					node->definition->type, node->definition->identifier, i);
			ret = 1;
			goto out;
		}
		if (node->definition->unpack(node) != 0) {
			RRR_MSG_ERR("Error while converting endianess for type %u index %i of array message\n",
					node->definition->type, i);
			ret = 1;
			goto out;
		}
		i++;
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_array_parse_and_unpack_from_buffer_with_callback (
		const char *buf,
		ssize_t buf_len,
		const struct rrr_array *definition,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
) {
	int ret = 0;
	struct rrr_array array = {0};

	ssize_t parsed_bytes = 0;
	if ((ret = rrr_array_parse_and_unpack_from_buffer (
			&array,
			&parsed_bytes,
			buf,
			buf_len,
			definition
	)) != 0) {
		RRR_MSG_ERR("Could not parse array in rrr_array_parse_from_buffer_with_callback\n");
		ret = 1;
		goto out;
	}

	ret = callback(&array, callback_arg);

	out:
	rrr_array_clear(&array);

	return ret;
}

int rrr_array_new_message_from_buffer (
		struct rrr_message **target,
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t buf_len,
		const char *topic,
		ssize_t topic_length,
		const struct rrr_array *definition
) {
	struct rrr_message *message = NULL;
	struct rrr_array definitions;
	int ret = 0;

	if ((ret = __rrr_array_parse_from_buffer(&definitions, parsed_bytes, buf, buf_len, definition)) != 0) {
		goto out_destroy;
	}

	if ((ret = rrr_array_new_message_from_collection(
			&message,
			&definitions,
			rrr_time_get_64(),
			topic,
			topic_length
	)) != 0) {
		RRR_MSG_ERR("Could not create message in rrr_array_new_message_from_buffer\n");
		return RRR_ARRAY_PARSE_HARD_ERR;
		goto out_destroy;
	}

	*target = message;
	message = NULL;

	out_destroy:
	rrr_array_clear(&definitions);
	RRR_FREE_IF_NOT_NULL(message);

	return ret;
}

int rrr_array_new_message_from_buffer_with_callback (
		const char *buf,
		ssize_t buf_len,
		const char *topic,
		ssize_t topic_length,
		const struct rrr_array *definition,
		int (*callback)(struct rrr_message *message, void *arg),
		void *callback_arg
) {
	int ret = 0;

	ssize_t parsed_bytes = 0;
	struct rrr_message *message = NULL;
	if ((ret = rrr_array_new_message_from_buffer(
			&message,
			&parsed_bytes,
			buf,
			buf_len,
			topic,
			topic_length,
			definition
	)) != 0) {
		return ret;
	}

	return callback(message, callback_arg);
}

static int __rrr_array_collection_to_raw (
		char *target,
		ssize_t target_size,
		ssize_t *written_bytes_final,
		const struct rrr_array *definition,
		const struct rrr_linked_list *tags,
		int data_only
) {
	ssize_t written_bytes_total = 0;

	int ret = 0;

	char *max = target + target_size;
	char *pos = target;
	*written_bytes_final = 0;

	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
		if (node->data == NULL) {
			RRR_BUG("Data not set for node in rrr_array_new_message\n");
		}
		if (pos > max) {
			RRR_BUG("pos was > max in __rrr_array_collection_to_raw\n");
		}

		if (tags != NULL) {
			int found = 0;
			if (node->tag != NULL) {
				const char *tag = node->tag;
				RRR_LL_ITERATE_BEGIN(tags, const struct rrr_linked_list_node);
					printf ("Match tag %s vs %s\n", tag, (char *) node->data);
					if (strcmp (tag, node->data) == 0) {
						found = 1;
						RRR_LL_ITERATE_LAST();
					}
				RRR_LL_ITERATE_END(tags);
			}
			if (found == 0) {
				RRR_LL_ITERATE_NEXT();
			}
		}

		uint8_t type = node->definition->type;

		if (node->definition->pack == NULL) {
			RRR_BUG("No pack function defined for type %u\n", type);
		}

		struct rrr_array_value_packed *head = (struct rrr_array_value_packed *) pos;

		if (data_only == 0) {
			head->type = type;
			head->flags = node->flags;
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
		}

		uint8_t new_type = 0;
		ssize_t written_bytes = 0;

		if (node->definition->pack(pos, &written_bytes, &new_type, node) != 0) {
			RRR_MSG_ERR("Error while packing data of type %u in rrr_array_new_message\n", node->definition->type);
			ret = 1;
			goto out;
		}

		if (data_only == 0) {
			if (new_type != head->type) {
				head->type = new_type;
			}
		}

		if (written_bytes != node->total_stored_length) {
			RRR_BUG("Size mismatch in rrr_array_new_message\n");
		}

		pos += written_bytes;
		written_bytes_total += written_bytes;
	RRR_LL_ITERATE_END(definition);

	*written_bytes_final = written_bytes_total;

	out:
	return ret;
}

int rrr_array_selected_tags_to_raw (
		char **target,
		ssize_t *target_size,
		const struct rrr_array *definition,
		const struct rrr_linked_list *tags
) {
	int ret = 0;

	// We over-allocate here if not all tags are used
	rrr_type_length total_data_length = __rrr_array_get_packed_length(definition);

	*target = NULL;
	*target_size = 0;

	char *result = malloc(total_data_length);
	if (result == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_array_selected_tags_to_raw\n");
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_array_collection_to_raw (
			result,
			total_data_length,
			target_size,
			definition,
			tags,
			1
	)) != 0) {
		RRR_MSG_ERR("Error while converting array in rrr_array_selected_tags_to_raw\n");
		goto out;
	}

	*target = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

int rrr_array_new_message_from_collection (
		struct rrr_message **final_message,
		const struct rrr_array *definition,
		uint64_t time,
		const char *topic,
		ssize_t topic_length
) {
	int ret = 0;

	*final_message = NULL;

	rrr_type_length total_data_length = __rrr_array_get_packed_length(definition);

	struct rrr_message *message = rrr_message_new_array(time, topic_length, total_data_length);
	if (message == NULL) {
		RRR_MSG_ERR("Could not create message for data collection\n");
		ret = 1;
		goto out;
	}

	message->version = RRR_ARRAY_VERSION;

	if (topic_length > 0) {
		char *topic_pos = MSG_TOPIC_PTR(message);
		memcpy(topic_pos, topic, topic_length);
	}

	ssize_t written_bytes_total = 0;

	if ((ret = __rrr_array_collection_to_raw (
			MSG_DATA_PTR(message),
			MSG_DATA_LENGTH(message),
			&written_bytes_total,
			definition,
			NULL,
			0
	)) != 0) {
		RRR_MSG_ERR("Error while converting array in rrr_array_new_message_from_collection\n");
		goto out;
	}

	if (written_bytes_total != total_data_length) {
		RRR_BUG("Length mismatch after assembling message in rrr_array_new_message %li<>%lu\n",
				written_bytes_total, MSG_DATA_LENGTH(message));
	}

	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG("rrr_array_new_message output (data of message only): 0x");
		for (rrr_type_length i = 0; i < MSG_DATA_LENGTH(message); i++) {
			char c = MSG_DATA_PTR(message)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
	}

	*final_message = (struct rrr_message *) message;
	message = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int rrr_array_message_to_collection (
		struct rrr_array *target,
		const struct rrr_message *message_orig
) {
	memset(target, '\0', sizeof(*target));

	if (message_orig->class != MSG_CLASS_ARRAY) {
		RRR_BUG("Message was not array in rrr_array_message_to_collection\n");
	}

	const struct rrr_message *array = (struct rrr_message *) message_orig;

	// Modules should also check for array version to make sure they support any recent changes.
	uint16_t version = array->version;
	if (version != RRR_ARRAY_VERSION) {
		RRR_MSG_ERR("Array message version mismatch in rrr_array_message_to_collection. Need V%i but got V%u.\n",
				RRR_ARRAY_VERSION, array->version);
		goto out_free_data;
	}
	target->version = version;

	const char *pos = MSG_DATA_PTR(array);
	const char *end = MSG_DATA_PTR(array) + MSG_DATA_LENGTH(array);

	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG("rrr_array_message_to_collection input (data of message only): 0x");
		for (rrr_type_length i = 0; i < MSG_DATA_LENGTH(array); i++) {
			char c = MSG_DATA_PTR(array)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
	}

	int i = 0;
	while (pos < end) {
		struct rrr_array_value_packed *data_packed = (struct rrr_array_value_packed *) pos;
		pos += sizeof(struct rrr_array_value_packed) - 1;

		if (pos > end) {
			RRR_MSG_ERR("Data type with index %i was too short in array\n", i);
			goto out_free_data;
		}

		rrr_type type = data_packed->type;
		rrr_type_flags flags = data_packed->flags;
		rrr_type_length tag_length = be32toh(data_packed->tag_length);
		rrr_type_length total_length = be32toh(data_packed->total_length);
		rrr_type_length elements = be32toh(data_packed->elements);

		if (pos + tag_length + total_length > end) {
			RRR_MSG_ERR("Length of type %u index %i in array message exceeds total length (%u > %li)\n",
					type, i, total_length, end - pos);
			goto out_free_data;
		}

		const struct rrr_type_definition *def = rrr_type_get_from_id(type);
		if (def == NULL) {
			RRR_MSG_ERR("Unknown type %u in type index %i of array message\n", type, i);
			goto out_free_data;
		}

		if (def->unpack == NULL) {
			RRR_MSG_ERR("Illegal type in array message %u/%s\n",
					def->type, def->identifier);
			goto out_free_data;
		}

		struct rrr_type_value *template = NULL;
		if (rrr_type_value_new (
				&template,
				def,
				flags,
				tag_length,
				pos,
				total_length,
				elements,
				total_length
		) != 0) {
			RRR_MSG_ERR("Could not allocate value in rrr_array_message_to_collection\n");
			goto out_free_data;
		}
		RRR_LL_APPEND(target,template);

		pos += tag_length;

		memcpy (template->data, pos, total_length);

		if (template->definition->unpack(template) != 0) {
			RRR_MSG_ERR("Error while converting endianess for type %u index %i of array message\n", type, i);
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
