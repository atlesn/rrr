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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "log.h"
#include "array.h"
#include "rrr_endian.h"
#include "cmdlineparser/cmdline.h"
#include "settings.h"
#include "instance_config.h"
#include "messages.h"
#include "type.h"
#include "vl_time.h"
#include "map.h"
#include "gnu.h"

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
		RRR_MSG_0("Unknown type identifier in type definition here --> '%s'\n", start);
		goto out_err;
	}
	start += parsed_bytes;

	if (type->max_length > 0) {
		if (start >= end || *start == '\0') {
			RRR_MSG_0("Missing size for type '%s' in type definition\n", type->identifier);
			goto out_err;
		}

		if (__rrr_array_convert_unsigned_integer_10(&integer_end, &length, start) != 0) {
			RRR_MSG_0("Size argument '%s' in type definition '%s' was not a valid number\n",
					start, type->identifier);
			goto out_err;
		}

		if (length > 0xffffffff) {
			RRR_MSG_0("Size argument '%s' in type definition '%s' was too long, max is 0xffffffff\n",
					start, type->identifier);
			goto out_err;
		}

		parsed_bytes += integer_end - start;
		start = integer_end;

		if (length <= 0) {
			RRR_MSG_0("Size argument '%lli' in type definition '%s' must be >0\n",
					length, type->identifier);
			goto out_err;
		}

		if (start >= end || *start == '\0') {
			goto out_ok;
		}

		if (*start == 's' || *start == 'S' || *start == 'u' || *start == 'U') {
			if (!RRR_TYPE_ALLOWS_SIGN(type->type)) {
				RRR_MSG_0("Sign indicator '%c' found in type definition for type '%s' which does not support being signed\n",
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
			RRR_MSG_0("Extra data or size argument after type definition '%s' which has automatic size\n",
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
			RRR_MSG_0("Item count missing after item count definition @ in type %s\n", type->identifier);
			goto out_err;
		}

		if (__rrr_array_convert_unsigned_integer_10(&integer_end, &item_count, start) != 0) {
			RRR_MSG_0("Item count argument '%s' in type definition '%s' was not a valid number\n",
					start, type->identifier);
			goto out_err;
		}

		parsed_bytes += integer_end - start;
		start = integer_end;

		if (item_count == 0) {
			RRR_MSG_0("Item count definition @ was zero after type '%s', must be in the range 1-65535\n",
					type->identifier);
			goto out_err;
		}
		if (item_count > 0xffffffff) {
			RRR_MSG_0("Item count definition @ was too big after type '%s', must be in the range 1-65535\n",
					type->identifier);
			goto out_err;
		}
		/*
		 *  XXX  : It is not possible to allow multiple values for these types as multiple values
		 *         in a node must have equal lengths
		 *         && type->type != RRR_TYPE_STR && type->type != RRR_TYPE_MSG
		 */
		if (item_count > 1 && type->max_length == 0) {
			RRR_MSG_0("Item count definition @ found after type '%s' which cannot have multiple values\n",
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
		RRR_MSG_0("Error while parsing type identifier and size\n");
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
			RRR_MSG_0("Missing tag name after #\n");
			ret = 1;
			goto out;
		}
	}

	if (*start != '\0') {
		RRR_MSG_0("Extra data after type definition here --> '%s'\n", start);
		ret = 1;
		goto out;
	}

	if (length > type->max_length) {
		RRR_MSG_0("Size argument in type definition '%s' is too large, max is '%u'\n",
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
		RRR_MSG_0("Could not create value in rrr_array_parse_definition\n");
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
		RRR_MSG_0("Type %s has dynamic size and cannot be at the end of a definition\n",
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
				RRR_MSG_0("Type %s cannot be followed type %s in array definition as we cannot know where the first ends, use a separator in between\n",
						prev->definition->identifier, node->definition->identifier);
				ret = 1;
			}
		}
		prev = node;
	RRR_LL_ITERATE_END();

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
		// TODO : This needs to be put into a buffer then written out
/*		RRR_DBG("rrr_types_parse_data input: 0x");
		for (rrr_type_length i = 0; i < length; i++) {
			char c = data[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");*/
	}

	int i = 0;
	RRR_LL_ITERATE_BEGIN(target,struct rrr_type_value);
		RRR_DBG_3("Parsing type index %u of type %s, %d copies\n", i, node->definition->identifier, node->element_count);

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
				RRR_MSG_0("Invalid data in type conversion\n");
			}
			else {
				RRR_MSG_0("Hard error while importing data in rrr_array_parse_data_from_definition, return was %i\n", ret);
				ret = RRR_TYPE_PARSE_HARD_ERR;
			}
			goto out;
		}

		if (parsed_bytes == 0) {
			RRR_BUG("Parsed bytes was zero in rrr_array_parse_data_from_definition\n");
		}

		pos += parsed_bytes;
		i++;
	RRR_LL_ITERATE_END();

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
			RRR_MSG_0("Could not allocate memory in rrr_array_definition_collection_clone\n");
			goto out_err;
		}
		memcpy(template, node, sizeof(*template));

		template->data = NULL;

		if (template->tag_length > 0) {
			template->tag = malloc(template->tag_length);
			if (template->tag == NULL) {
				RRR_MSG_0("Could not allocate memory for tag in rrr_array_definition_collection_clone\n");
				goto out_err;
			}
			memcpy(template->tag, node->tag, template->tag_length);
		}
		else if (template->tag != NULL) {
			RRR_BUG("tag was not NULL but tag length was >0 in rrr_array_definition_collection_clone\n");
		}

		RRR_LL_APPEND(target,template);
	RRR_LL_ITERATE_END();

	target->version = source->version;

	return 0;

	out_err:
		RRR_LL_DESTROY(target, struct rrr_type_value, free(node));
		memset(target, '\0', sizeof(*target));
		return 1;
}

static int __rrr_array_push_value_64_with_tag (
		struct rrr_array *collection,
		const char *tag,
		uint64_t value,
		int is_signed
) {
	struct rrr_type_value *new_value = NULL;

	if (rrr_type_value_new (
			&new_value,
			&rrr_type_definition_h,
			(is_signed ? RRR_TYPE_FLAG_SIGNED : 0),
			strlen(tag),
			tag,
			sizeof(uint64_t),
			1,
			0 // <!-- Don't send store length, import function will allocate
	) != 0) {
		RRR_MSG_0("Could not create value in rrr_array_push_value_64_with_tag\n");
		return 1;
	}

	RRR_LL_APPEND(collection, new_value);

	ssize_t parsed_bytes = 0;
	if (new_value->definition->import(new_value, &parsed_bytes, (const char *) &value, ((const char *) &value + sizeof(value))) != 0) {
		RRR_MSG_0("Error while importing in rrr_array_push_value_64_with_tag\n");
		return 1;
	}

	return 0;
}

int rrr_array_push_value_u64_with_tag (
		struct rrr_array *collection,
		const char *tag,
		uint64_t value
) {
	return __rrr_array_push_value_64_with_tag(collection, tag, value, 0);
}

int rrr_array_push_value_i64_with_tag (
		struct rrr_array *collection,
		const char *tag,
		int64_t value
) {
	return __rrr_array_push_value_64_with_tag(collection, tag, (uint64_t) value, 1);
}

static int __rrr_array_push_value_x_with_tag_with_size (
		struct rrr_array *collection,
		const char *tag,
		const char *value,
		size_t value_size,
		const struct rrr_type_definition *type
) {
	struct rrr_type_value *new_value = NULL;
	if (rrr_type_value_new (
			&new_value,
			type,
			0,
			strlen(tag),
			tag,
			value_size,
			1,
			value_size
	) != 0) {
		RRR_MSG_0("Could not create value in rrr_array_push_value_str_with_tag_with_size\n");
		return 1;
	}

	RRR_LL_APPEND(collection, new_value);

	// Don't use the import function, it reads strings with quotes around it
	memcpy(new_value->data, value, value_size);

	return 0;
}

int rrr_array_push_value_str_with_tag_with_size (
		struct rrr_array *collection,
		const char *tag,
		const char *value,
		size_t value_size
) {
	return __rrr_array_push_value_x_with_tag_with_size (
			collection,
			tag,
			value,
			value_size,
			&rrr_type_definition_str
	);
}

int rrr_array_push_value_blob_with_tag_with_size (
		struct rrr_array *collection,
		const char *tag,
		const char *value,
		size_t value_size
) {
	return __rrr_array_push_value_x_with_tag_with_size (
			collection,
			tag,
			value,
			value_size,
			&rrr_type_definition_blob
	);
}

int rrr_array_push_value_str_with_tag (
		struct rrr_array *collection,
		const char *tag,
		const char *value
) {
	size_t value_size = strlen(value) + 1;

	return rrr_array_push_value_str_with_tag_with_size(
			collection,
			tag,
			value,
			value_size
	);
}

int rrr_array_get_value_unsigned_64_by_tag (
		uint64_t *result,
		struct rrr_array *array,
		const char *tag,
		int index
) {
	int ret = 0;

	struct rrr_type_value *value = NULL;

	if ((value = rrr_array_value_get_by_tag(array, tag)) == NULL) {
		RRR_MSG_0("Could not find value '%s' in array while getting 64-value\n", tag);
		ret = 1;
		goto out;
	}

	if (RRR_TYPE_FLAG_IS_SIGNED(value->flags)) {
		RRR_MSG_0("Value '%s' in array was signed but unsigned value was expected\n", tag);
		ret = 1;
		goto out;
	}

	if (index < 0) {
		RRR_BUG("Negative index given to rrr_array_get_value_unsigned_64_by_tag\n");
	}

	if (index - 1 > (int) value->element_count) {
		RRR_MSG_0("Array value '%s' index %i was requested but there are only %i elements in the value",
				tag, index, value->element_count);
		ret = 1;
		goto out;
	}

	*result = *((uint64_t*) value->data + (sizeof(uint64_t) * index));

	out:
	return ret;
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
	RRR_LL_ITERATE_END();

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
	RRR_LL_ITERATE_END();

	return NULL;
}

const struct rrr_type_value *rrr_array_value_get_by_tag_const (
		const struct rrr_array *definition,
		const char *tag
) {
	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
		if (node->tag != NULL) {
			if (strcmp(node->tag, tag) == 0) {
				return node;
			}
		}
	RRR_LL_ITERATE_END();

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
	RRR_LL_ITERATE_END();

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
	RRR_LL_ITERATE_END();
	return result;
}

static ssize_t __rrr_array_get_exported_length (
		const struct rrr_array *definition
) {
	ssize_t result = 0;
	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
		result += rrr_type_value_get_export_length(node);
	RRR_LL_ITERATE_END();
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
		RRR_MSG_0("Could not clone definitions in __rrr_array_parse_from_buffer\n");
		ret = RRR_ARRAY_PARSE_HARD_ERR;
		goto out;
	}

	if ((ret = rrr_array_parse_data_from_definition(target, parsed_bytes, buf, buf_len)) != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			RRR_MSG_0("Invalid packet in __rrr_array_parse_from_buffer\n");
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

int rrr_array_parse_from_buffer (
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

	out:
	return ret;
}

int rrr_array_parse_from_buffer_with_callback (
		const char *buf,
		ssize_t buf_len,
		const struct rrr_array *definition,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
) {
	int ret = 0;
	struct rrr_array array = {0};

	ssize_t parsed_bytes = 0;
	if ((ret = rrr_array_parse_from_buffer (
			&array,
			&parsed_bytes,
			buf,
			buf_len,
			definition
	)) != 0) {
		RRR_MSG_0("Could not parse array in rrr_array_parse_from_buffer_with_callback\n");
		// Usually errors are caused by senders sending wrong data,
		// don't let them make the program crash
		ret = RRR_ARRAY_PARSE_SOFT_ERR;
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
		RRR_MSG_0("Could not create message in rrr_array_new_message_from_buffer return was %i\n", ret);
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

static int __rrr_array_collection_iterate_chosen_tags (
		int *found_tags,
		const struct rrr_array *definition,
		const struct rrr_map *tags,
		int (*callback)(const struct rrr_type_value *node, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*found_tags = 0;

	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
		int found = 0;

		if (tags == NULL) {
			found = 1;
		}
		else {
			if (node->tag != NULL) {
				const char *tag = node->tag;
				RRR_MAP_ITERATE_BEGIN_CONST(tags);
//					printf ("Match tag %s vs %s\n", tag, (char *) node->value_primary_);
					if (strcmp (tag, node_tag) == 0) {
						found = 1;
						RRR_LL_ITERATE_LAST();
					}
				RRR_MAP_ITERATE_END();
			}
		}

		if (found == 1) {
			(*found_tags)++;
			if ((ret = callback(node, callback_arg)) != 0) {
				RRR_MSG_0("Error from callback in __rrr_array_collection_iterate_chosen_tags\n");
				ret = 1;
				goto out;
			}
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

struct pack_callback_data {
	ssize_t written_bytes_total;
	char *write_pos;
};

static int __rrr_array_collection_pack_callback (const struct rrr_type_value *node, void *arg) {
	int ret = 0;

	struct pack_callback_data *data = arg;

	uint8_t type = node->definition->type;

	if (node->definition->pack == NULL) {
		RRR_BUG("No pack function defined for type %u in __rrr_array_collection_pack_callback\n", type);
	}

	struct rrr_array_value_packed *head = (struct rrr_array_value_packed *) data->write_pos;

	data->write_pos += sizeof(*head) - 1;
	data->written_bytes_total += sizeof(*head) - 1;

	if (node->tag_length > 0) {
		memcpy(data->write_pos, node->tag, node->tag_length);
		data->write_pos += node->tag_length;
		data->written_bytes_total += node->tag_length;
	}

	uint8_t new_type = 0;
	ssize_t written_bytes = 0;
	if (node->definition->pack(data->write_pos, &written_bytes, &new_type, node) != 0) {
		RRR_MSG_0("Error while packing data of type %u in __rrr_array_collection_pack_callback\n", node->definition->type);
		ret = RRR_ARRAY_PARSE_SOFT_ERR;
		goto out;
	}
	data->write_pos += written_bytes;
	data->written_bytes_total += written_bytes;

	head->type = new_type;
	head->flags = node->flags;
	head->tag_length = rrr_htobe32(node->tag_length);
	head->elements = rrr_htobe32(node->element_count);
	head->total_length = rrr_htobe32(written_bytes);

	if (written_bytes < node->total_stored_length) {
		RRR_BUG("Size mismatch in __rrr_array_collection_pack_callback, too few bytes written\n");
	}

	out:
	return ret;
}

static int __rrr_array_collection_export_callback (const struct rrr_type_value *node, void *arg) {
	int ret = 0;

	struct pack_callback_data *data = arg;

	if (node->definition->export == NULL) {
		RRR_BUG("No export function defined for type %u in __rrr_array_collection_export_callback\n", node->definition->type);
	}

	ssize_t written_bytes = 0;
	if (node->definition->export(data->write_pos, &written_bytes, node) != 0) {
		RRR_MSG_0("Error while exporting data of type %u in __rrr_array_collection_export_callback\n", node->definition->type);
		ret = RRR_ARRAY_PARSE_SOFT_ERR;
		goto out;
	}
	data->write_pos += written_bytes;
	data->written_bytes_total += written_bytes;

	RRR_DBG_3("array export type %s size %li total size %li\n",
			node->definition->identifier, written_bytes, data->written_bytes_total);

	if (written_bytes < node->total_stored_length) {
		RRR_BUG("Size mismatch in __rrr_array_collection_export_callback, too few bytes written\n");
	}

	out:
	return ret;
}

static int __rrr_array_collection_pack_or_export (
		char *target,
		int *found_tags,
		ssize_t *written_bytes_final,
		ssize_t target_size,
		const struct rrr_array *definition,
		const struct rrr_map *tags,
		int (*method)(const struct rrr_type_value *node, void *arg)
) {
	int ret = 0;

	*found_tags = 0;
	*written_bytes_final = 0;

	struct pack_callback_data callback_data = {0};

	callback_data.write_pos = target;

	if ((ret = __rrr_array_collection_iterate_chosen_tags (
			found_tags,
			definition,
			tags,
			method,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error %i from iterator in __rrr_array_collection_pack_or_export\n", ret);
		goto out;
	}

	*written_bytes_final = callback_data.written_bytes_total;

	if (callback_data.write_pos > target + target_size) {
		RRR_BUG("Buffer write outside bounds in __rrr_array_collection_pack_or_export\n");
	}

	out:
	return ret;
}

int rrr_array_selected_tags_export (
		char **target,
		ssize_t *target_size,
		int *found_tags,
		const struct rrr_array *definition,
		const struct rrr_map *tags
) {
	int ret = 0;

	// We over-allocate here if not all tags are used
	rrr_type_length total_data_length = __rrr_array_get_exported_length(definition);

	*target = NULL;
	*target_size = 0;

	char *result = malloc(total_data_length);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_array_selected_tags_to_raw\n");
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_array_collection_pack_or_export (
			result,
			found_tags,
			target_size,
			total_data_length,
			definition,
			tags,
			__rrr_array_collection_export_callback
	)) != 0) {
		RRR_MSG_0("Error while converting array in rrr_array_selected_tags_export return was %i\n", ret);
		goto out;
	}

	*target = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

ssize_t rrr_array_new_message_estimate_size (
		const struct rrr_array *definition
) {
	rrr_type_length total_data_length = __rrr_array_get_packed_length(definition);

	return total_data_length + sizeof(struct rrr_message) - 1;
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
		RRR_MSG_0("Could not create message for data collection\n");
		ret = RRR_ARRAY_PARSE_HARD_ERR;
		goto out;
	}

	message->version = RRR_ARRAY_VERSION;

	if (topic_length > 0) {
		char *topic_pos = MSG_TOPIC_PTR(message);
		memcpy(topic_pos, topic, topic_length);
	}

	ssize_t written_bytes_total = 0;
	int found_tags = 0;

	if ((ret = __rrr_array_collection_pack_or_export (
			MSG_DATA_PTR(message),
			&found_tags,
			&written_bytes_total,
			MSG_DATA_LENGTH(message),
			definition,
			NULL, // Process all elements
			__rrr_array_collection_pack_callback
	)) != 0) {
		RRR_MSG_0("Error while converting array in rrr_array_new_message_from_collection return was %i\n", ret);
		goto out;
	}

	if (written_bytes_total != total_data_length) {
		RRR_BUG("Length mismatch after assembling message in rrr_array_new_message %li<>%lu\n",
				written_bytes_total, MSG_DATA_LENGTH(message));
	}

	if (RRR_DEBUGLEVEL_3) {
		// TODO : Data must be put in a buffer and then printed
/*		RRR_DBG("rrr_array_new_message output (data of message only): 0x");
		for (rrr_type_length i = 0; i < MSG_DATA_LENGTH(message); i++) {
			char c = MSG_DATA_PTR(message)[i];
			if (c < 0x10) {
				RRR_DBG_NOPREFIX("0");
			}
			RRR_DBG_NOPREFIX("%x", c);
		}
		RRR_DBG_NOPREFIX("\n");*/
	}

	*final_message = (struct rrr_message *) message;
	message = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int rrr_array_message_append_to_collection (
		struct rrr_array *target,
		const struct rrr_message *message_orig
) {
	if (MSG_CLASS(message_orig) != MSG_CLASS_ARRAY) {
		RRR_BUG("Message was not array in rrr_array_message_to_collection\n");
	}

	// Modules should also check for array version to make sure they support any recent changes.
	uint16_t version = message_orig->version;
	if (version != RRR_ARRAY_VERSION) {
		RRR_MSG_0("Array message version mismatch in rrr_array_message_to_collection. Need V%i but got V%u.\n",
				RRR_ARRAY_VERSION, message_orig->version);
		goto out_free_data;
	}
	target->version = version;

	const char *pos = MSG_DATA_PTR(message_orig);
	const char *end = MSG_DATA_PTR(message_orig) + MSG_DATA_LENGTH(message_orig);

	if (RRR_DEBUGLEVEL_3) {
		/* TODO : This needs to be put in a buffer then written out
		RRR_DBG("rrr_array_message_to_collection input (data of message only): 0x");
		for (rrr_type_length i = 0; i < MSG_DATA_LENGTH(array); i++) {
			char c = MSG_DATA_PTR(array)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
		*/
	}

	int i = 0;
	while (pos < end) {
		struct rrr_array_value_packed *data_packed = (struct rrr_array_value_packed *) pos;
		pos += sizeof(struct rrr_array_value_packed) - 1;

		if (pos > end) {
			RRR_MSG_0("Data type with index %i was too short in array\n", i);
			goto out_free_data;
		}

		rrr_type type = data_packed->type;
		rrr_type_flags flags = data_packed->flags;
		rrr_type_length tag_length = rrr_be32toh(data_packed->tag_length);
		rrr_type_length total_length = rrr_be32toh(data_packed->total_length);
		rrr_type_length elements = rrr_be32toh(data_packed->elements);

		if (pos + tag_length + total_length > end) {
			RRR_MSG_0("Length of type %u index %i in array message exceeds total length (%u > %li)\n",
					type, i, total_length, end - pos);
			goto out_free_data;
		}

		const struct rrr_type_definition *def = rrr_type_get_from_id(type);
		if (def == NULL) {
			RRR_MSG_0("Unknown type %u in type index %i of array message\n", type, i);
			goto out_free_data;
		}

		if (def->unpack == NULL) {
			RRR_MSG_0("Illegal type in array message %u/%s\n",
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
			RRR_MSG_0("Could not allocate value in rrr_array_message_to_collection\n");
			goto out_free_data;
		}
		RRR_LL_APPEND(target,template);

		pos += tag_length;

		memcpy (template->data, pos, total_length);

		if (template->definition->unpack(template) != 0) {
			RRR_MSG_0("Error while converting endianess for type %u index %i of array message\n", type, i);
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

int rrr_array_dump (
		const struct rrr_array *definition
) {
	int ret = 0;
	char *tmp = NULL;

	// Use high debuglevel to force suppression of messages in journal module

	RRR_DBG_2 ("== ARRAY DUMP ========================================================\n");

	// TODO : Each line must be written to a buffer then printed

	int i = 0;
	RRR_LL_ITERATE_BEGIN(definition, const struct rrr_type_value);
		const char *tag = "-";
		const char *to_str = "-";

		if (node->tag != NULL && *(node->tag) != '\0') {
			tag = node->tag;
		}

		if (node->definition->to_str != NULL) {
			RRR_FREE_IF_NOT_NULL(tmp);
			if (node->definition->to_str(&tmp, node) != 0) {
				RRR_MSG_0("Error when stringifying value in rrr_array_dump\n");
				ret = 1;
				goto out;
			}
			to_str = tmp;
		}

		RRR_DBG_2 ("%i - %s - %s - (%i/%i = %i) - %s\n",
				i,
				node->definition->identifier,
				tag,
				node->total_stored_length,
				node->element_count,
				node->total_stored_length / node->element_count,
				to_str
		);

		i++;
	RRR_LL_ITERATE_END();


	RRR_DBG_2 ("== ARRAY DUMP END ====================================================\n");

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	return ret;
}
