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
#include "cmdlineparser/cmdline.h"
#include "settings.h"
#include "instance_config.h"
#include "messages/msg_msg_struct.h"
#include "messages/msg_msg.h"
#include "type.h"
#include "map.h"
#include "util/rrr_time.h"
#include "util/gnu.h"
#include "util/rrr_endian.h"
#include "helpers/nullsafe_str.h"
#include "parse.h"

static int __rrr_array_clone (
		struct rrr_array *target,
		const struct rrr_array *source,
		int do_clone_data
) {
	int ret = 0;

	if (target->node_count != 0) {
		RRR_BUG("BUG: Target was not empty in rrr_array_clone\n");
	}

	memset(target, '\0', sizeof(*target));

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_type_value);
		struct rrr_type_value *new_value = NULL;
		if (rrr_type_value_clone(&new_value, node, do_clone_data) != 0) {
			goto out_err;
		}
		RRR_LL_PUSH(target, new_value);
	RRR_LL_ITERATE_END();

	target->version = source->version;

	goto out;
	out_err:
		RRR_LL_DESTROY(target, struct rrr_type_value, rrr_type_value_destroy(node));
		memset(target, '\0', sizeof(*target));
		ret = 1;
	out:
		return ret;
}

int rrr_array_clone_without_data (
		struct rrr_array *target,
		const struct rrr_array *source
) {
	return __rrr_array_clone(target, source, 0);
}

int rrr_array_append_from (
		struct rrr_array *target,
		const struct rrr_array *source
) {
	int ret = 0;

	struct rrr_array tmp = {0};

	if ((ret = __rrr_array_clone(&tmp, source, 1)) != 0) {
		RRR_MSG_0("Could not clone array in rrr_array_append_from\n");
		goto out;
	}

	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(target, &tmp);

	out:
	rrr_array_clear(&tmp);
	return ret;
}

static int __rrr_array_push_value_64_with_tag (
		struct rrr_array *collection,
		const char *tag,
		uint64_t value,
		const struct rrr_type_definition *definition,
		int flags
) {
	struct rrr_type_value *new_value = NULL;

	int ret = 0;

	if ((ret = rrr_type_value_new (
			&new_value,
			definition,
			flags,
			strlen(tag),
			tag,
			sizeof(uint64_t),
			NULL,
			1,
			NULL,
			0 // <!-- Don't send store length, import function will allocate
	)) != 0) {
		RRR_MSG_0("Could not create value in rrr_array_push_value_64_with_tag return was %i\n", ret);
		ret = 1;
		goto out;
	}

	rrr_length parsed_bytes = 0;
	if ((ret = new_value->definition->import (
			new_value,
			&parsed_bytes,
			(const char *) &value,
			((const char *) &value + sizeof(value))
	)) != 0) {
		RRR_MSG_0("Error while importing in rrr_array_push_value_64_with_tag return was %i\n", ret);
		ret = 1;
		goto out;
	}

	RRR_LL_APPEND(collection, new_value);
	new_value = NULL;

	out:
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
	return ret;
}

int rrr_array_push_value_u64_with_tag (
		struct rrr_array *collection,
		const char *tag,
		uint64_t value
) {
	return __rrr_array_push_value_64_with_tag(
			collection,
			tag,
			value,
			&rrr_type_definition_h,
			0
	);
}

int rrr_array_push_value_i64_with_tag (
		struct rrr_array *collection,
		const char *tag,
		int64_t value
) {
	return __rrr_array_push_value_64_with_tag(
			collection,
			tag,
			(uint64_t ) value,
			&rrr_type_definition_h,
			1
	);
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
			NULL,
			1,
			NULL,
			value_size
	) != 0) {
		RRR_MSG_0("Could not create value in __rrr_array_push_value_x_with_tag_with_size\n");
		return 1;
	}

	RRR_LL_APPEND(collection, new_value);

	memcpy(new_value->data, value, value_size);

	return 0;
}

int rrr_array_push_value_fixp_with_tag (
		struct rrr_array *collection,
		const char *tag,
		rrr_fixp value
) {
	return __rrr_array_push_value_x_with_tag_with_size (
			collection,
			tag,
			(const char *) &value,
			sizeof(value),
			&rrr_type_definition_fixp
	);
}

int rrr_array_push_value_str_with_tag_with_size (
		struct rrr_array *collection,
		const char *tag,
		const char *value,
		size_t value_size
) {
	// Don't use the import function, it reads strings with quotes around it

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

struct rrr_array_push_value_blob_with_tag_nullsafe_callback_data {
	struct rrr_array *collection;
	const char *tag;
	const struct rrr_type_definition *definition;
};

static int __rrr_array_push_value_x_with_tag_nullsafe_callback (
		const void *str,
		rrr_length len,
		void *arg
) {
	struct rrr_array_push_value_blob_with_tag_nullsafe_callback_data *callback_data = arg;

	return __rrr_array_push_value_x_with_tag_with_size (
			callback_data->collection,
			callback_data->tag,
			str,
			len,
			callback_data->definition
	);
}

int rrr_array_push_value_blob_with_tag_nullsafe (
		struct rrr_array *collection,
		const char *tag,
		const struct rrr_nullsafe_str *str
) {
	struct rrr_array_push_value_blob_with_tag_nullsafe_callback_data callback_data = {
			collection,
			tag,
			&rrr_type_definition_blob
	};

	return rrr_nullsafe_str_with_raw_do_const(
			str,
			__rrr_array_push_value_x_with_tag_nullsafe_callback,
			&callback_data
	);
}

int rrr_array_push_value_str_with_tag_nullsafe (
		struct rrr_array *collection,
		const char *tag,
		const struct rrr_nullsafe_str *str
) {
	struct rrr_array_push_value_blob_with_tag_nullsafe_callback_data callback_data = {
			collection,
			tag,
			&rrr_type_definition_str
	};

	return rrr_nullsafe_str_with_raw_do_const(
			str,
			__rrr_array_push_value_x_with_tag_nullsafe_callback,
			&callback_data
	);
}

int rrr_array_push_value_str_with_tag (
		struct rrr_array *collection,
		const char *tag,
		const char *value
) {
	size_t value_size = strlen(value);

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

void rrr_array_clear_void (void *collection) {
	rrr_array_clear(collection);
}

void rrr_array_clear_by_tag (struct rrr_array *collection, const char *tag) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_type_value);
		if (node->tag == NULL) {
			RRR_LL_ITERATE_NEXT();
		}
		if (strcmp(node->tag, tag) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; rrr_type_value_destroy(node));
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

ssize_t rrr_array_get_packed_length (
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
				const rrr_length tag_length = node->tag_length;
				RRR_MAP_ITERATE_BEGIN_CONST(tags);
					if (strncmp (tag, node_tag, tag_length) == 0) {
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
	rrr_length written_bytes = 0;
	if (node->definition->pack(data->write_pos, &written_bytes, &new_type, node) != 0) {
		RRR_MSG_0("Error while packing data of type %u in __rrr_array_collection_pack_callback\n", node->definition->type);
		ret = RRR_ARRAY_SOFT_ERROR;
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

	rrr_length written_bytes = 0;
	if (node->definition->export(data->write_pos, &written_bytes, node) != 0) {
		RRR_MSG_0("Error while exporting data of type %u in __rrr_array_collection_export_callback\n", node->definition->type);
		ret = RRR_ARRAY_SOFT_ERROR;
		goto out;
	}
	data->write_pos += written_bytes;
	data->written_bytes_total += written_bytes;

	RRR_DBG_3("array export type %s size %" PRIrrrl " total size %li\n",
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
	rrr_length total_data_length = __rrr_array_get_exported_length(definition);

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

int rrr_array_new_message_from_collection (
		struct rrr_msg_msg **final_message,
		const struct rrr_array *definition,
		uint64_t time,
		const char *topic,
		rrr_u16 topic_length
) {
	int ret = 0;

	*final_message = NULL;

	rrr_length total_data_length = rrr_array_get_packed_length(definition);

	struct rrr_msg_msg *message = rrr_msg_msg_new_array(time, topic_length, total_data_length);
	if (message == NULL) {
		RRR_MSG_0("Could not create message for data collection\n");
		ret = RRR_ARRAY_HARD_ERROR;
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

	if (written_bytes_total != (ssize_t) total_data_length) {
		RRR_BUG("Length mismatch after assembling message in rrr_array_new_message %li<>%lu\n",
				written_bytes_total, MSG_DATA_LENGTH(message));
	}

	*final_message = (struct rrr_msg_msg *) message;
	message = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int rrr_array_message_iterate (
		const struct rrr_msg_msg *message_orig,
		int (*callback)(
				const char *data_start,
				const struct rrr_type_definition *type,
				rrr_type_flags flags,
				rrr_length tag_length,
				rrr_length total_length,
				rrr_length element_count,
				void *arg
		),
		void *callback_arg
) {
	if (MSG_CLASS(message_orig) != MSG_CLASS_ARRAY) {
		RRR_BUG("Message was not array in rrr_array_message_iterate\n");
	}

	int ret = 0;

	// Modules should also check for array version to make sure they support any recent changes.
	uint16_t version = message_orig->version;
	if (version != RRR_ARRAY_VERSION) {
		RRR_MSG_0("Array message version mismatch in rrr_array_message_iterate. Need V%i but got V%u.\n",
				RRR_ARRAY_VERSION, message_orig->version);
		ret = 1;
		goto out;
	}

	const char *pos = MSG_DATA_PTR(message_orig);
	const char *end = MSG_DATA_PTR(message_orig) + MSG_DATA_LENGTH(message_orig);

	int i = 0;
	while (pos < end) {
		struct rrr_array_value_packed *data_packed = (struct rrr_array_value_packed *) pos;
		pos += sizeof(struct rrr_array_value_packed) - 1;

		if (pos > end) {
			RRR_MSG_0("Data type with index %i was too short in array\n", i);
			ret = 1;
			goto out;
		}

		rrr_type type = data_packed->type;
		rrr_type_flags flags = data_packed->flags;
		rrr_length tag_length = rrr_be32toh(data_packed->tag_length);
		rrr_length total_length = rrr_be32toh(data_packed->total_length);
		rrr_length elements = rrr_be32toh(data_packed->elements);

		if (pos + tag_length + total_length > end) {
			RRR_MSG_0("Length of type %u index %i in array message exceeds total length (%u > %li)\n",
					type, i, total_length, end - pos);
			ret = 1;
			goto out;
		}

		const struct rrr_type_definition *def = rrr_type_get_from_id(type);
		if (def == NULL) {
			RRR_MSG_0("Unknown type %u in type index %i of array message\n", type, i);
			ret = 1;
			goto out;
		}

		if (def->unpack == NULL) {
			RRR_MSG_0("Illegal type in array message %u/%s\n",
					def->type, def->identifier);
			ret = 1;
			goto out;
		}

		if ((ret = callback (
				pos,
				def,
				flags,
				tag_length,
				total_length,
				elements,
				callback_arg
		)) != 0) {
			goto out;
		}

		pos += tag_length + total_length;
		i++;
	}

	out:
	return ret;
}

struct rrr_array_message_append_to_collection_callback_data {
	struct rrr_array *target_tmp;
};

static int __rrr_array_message_append_to_collection_callback (
		const char *data_start,
		const struct rrr_type_definition *type,
		rrr_type_flags flags,
		rrr_length tag_length,
		rrr_length total_length,
		rrr_length element_count,
		void *arg
) {
	struct rrr_array_message_append_to_collection_callback_data *callback_data = arg;
	int ret = 0;

	struct rrr_type_value *template = NULL;
	if ((ret = rrr_type_value_new (
			&template,
			type,
			flags,
			tag_length,
			data_start,
			total_length,
			NULL,
			element_count,
			NULL,
			total_length
	)) != 0) {
		RRR_MSG_0("Could not allocate value in __rrr_array_message_append_to_collection_callbackn\n");
		goto out;
	}

	// Append immediately to array to manage memory
	RRR_LL_APPEND(callback_data->target_tmp, template);

	memcpy (template->data, data_start + tag_length, total_length);

	if (template->definition->unpack(template) != 0) {
		RRR_MSG_0("Error while converting endianess for type '%s' index %i of array message\n", type->identifier, RRR_LL_COUNT(callback_data->target_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_array_message_append_to_collection (
		uint16_t *array_version,
		struct rrr_array *target,
		const struct rrr_msg_msg *message_orig
) {
	int ret = 0;

	struct rrr_array target_tmp = {0};

	struct rrr_array_message_append_to_collection_callback_data callback_data = {
			&target_tmp
	};

	if ((ret =  rrr_array_message_iterate (
			message_orig,
			__rrr_array_message_append_to_collection_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	*array_version = message_orig->version;
	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(target, &target_tmp);

	out:
	rrr_array_clear(&target_tmp);
	return ret;
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
