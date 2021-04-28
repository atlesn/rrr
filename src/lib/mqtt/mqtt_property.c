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

#include "../log.h"
#include "../allocator.h"

#include "mqtt_property.h"

#include "../util/linked_list.h"
#include "../util/macro_utils.h"

const struct rrr_mqtt_property_definition property_definitions[] = {
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x01, "Payload format indicator"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x02, "Message expiry interval"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x03, "Content type"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x08, "Response topic"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_BLOB,	0x09, "Correlation data"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_VINT,	0x0B, "Subscription identifier"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x11, "Session expiry interval"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x12, "Assigned client identifier"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x13, "Server keep-alive"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x15, "Authentication method"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_BLOB,	0x16, "Authentication data"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x17, "Request problem information"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x18, "Will delay interval"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x19, "Request response information"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x1A, "Response information"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x1C, "Server reference"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x1F, "Reason string"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x21, "Receive maximum"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x22, "Topic alias maximum"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x23, "Topic alias"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x24, "Maximum QoS"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x25, "Retain available"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8,	0x26, "User property"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x27, "Maximum packet size"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x28, "Wildcard subscription available"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x29, "Subscription identifier available"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x2A, "Shared subscription available"},
		{0, 0, NULL}
};

const struct rrr_mqtt_property_definition *rrr_mqtt_property_get_definition(uint8_t id) {
	for (int i = 0; property_definitions[i].internal_data_type != 0; i++) {
		if (property_definitions[i].identifier == id) {
			return &property_definitions[i];
		}
	}

	return NULL;
}

void rrr_mqtt_property_destroy (
		struct rrr_mqtt_property *property
) {
	if (property == NULL) {
		return;
	}
	if (property->sibling != NULL) {
		rrr_mqtt_property_destroy(property->sibling);
	}

	RRR_FREE_IF_NOT_NULL(property->data);
	rrr_free(property);
}

int rrr_mqtt_property_new (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property_definition *definition
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_property *res = rrr_allocate(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_property_new\n");
		ret = 1;
		goto out;
	}

	memset(res, '\0', sizeof(*res));

	res->definition = definition;

	*target = res;

	out:
	return ret;
}

int rrr_mqtt_property_clone (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property *source
) {
	int ret = 0;

	struct rrr_mqtt_property *result = NULL;

	if (*target != NULL) {
		RRR_BUG("Target was not NULL in rr_mqtt_property_clone\n");
	}

	if (source == NULL) {
		goto out_final;
	}

	result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_property_clone A\n");
		ret = 1;
		goto out_final;
	}

	memcpy(result, source, sizeof(*result));

	// These pointers should be reset. The pointer to definition should be OK.
	RRR_LL_NODE_INIT(result);
	result->sibling = NULL;

	if (result->length <= 0) {
		RRR_BUG("Length was <= 0 in rrr_mqtt_property_clone\n");
	}

	if ((result->data = rrr_allocate(result->length)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_property_clone B\n");
		ret = 1;
		goto out_free;
	}

	memcpy(result->data, source->data, result->length);
	result->order = 0;

	if (source->sibling != NULL) {
		if ((ret = rrr_mqtt_property_clone(&result->sibling, source->sibling)) != 0) {
			RRR_MSG_0("Could not clone sibling in rrr_mqtt_property_clone\n");
			ret = 1;
			goto out_free;
		}
	}

	*target = result;
	result = NULL;

	goto out_final;
	out_free:
		rrr_mqtt_property_destroy(result);
	out_final:
		return ret;
}

int rrr_mqtt_property_save_blob (
		struct rrr_mqtt_property *target,
		const char *value,
		uint16_t size,
		int add_zero_if_needed
) {
	uint32_t size_padded = size;
	if (add_zero_if_needed != 0 && value[size - 1] != '\0') {
		size_padded++;
	}

	target->data = rrr_allocate(size_padded);
	if (target->data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_property_parse_integer\n");
		return 1;
	}

	target->internal_data_type = RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB;
	target->length = size;
	memcpy (target->data, value, size);

	if (size_padded > size) {
		memset(target->data + size, '\0', size_padded - size);
	}

	return 0;
}

int rrr_mqtt_property_save_uint32 (struct rrr_mqtt_property *target, uint32_t value) {
	// Keep on separate line to suppress warning from static code analysis
	size_t allocation_size = sizeof(value);

	if ((target->data = (char *) rrr_allocate(allocation_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_property_parse_integer\n");
		return 1;
	}

	target->internal_data_type = RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32;
	target->length = sizeof(value);
	memcpy (target->data, &value, sizeof(value));

	return 0;
}

uint32_t rrr_mqtt_property_get_uint32 (
		const struct rrr_mqtt_property *property
) {
	if (property->internal_data_type != RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32) {
		RRR_BUG("Property was not UINT32 in rrr_mqtt_property_get_uint32\n");
	}
	if (property->length < (ssize_t) sizeof(uint32_t)) {
		RRR_BUG("Length of property was <4 in rrr_mqtt_property_get_uint32\n");
	}
	return *((uint32_t*) property->data);
}

const char *rrr_mqtt_property_get_blob (
		const struct rrr_mqtt_property *property,
		ssize_t *length
) {
	if (property->internal_data_type != RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB) {
		RRR_BUG("Property was not BLOB in rrr_mqtt_property_get_blob\n");
	}
	if (property->length < 1) {
		RRR_BUG("Length of property was <1 in rrr_mqtt_property_get_blob\n");
	}
	*length = property->length;
	return property->data;
}

int rrr_mqtt_property_get_blob_as_str (
		char **result,
		const struct rrr_mqtt_property *property
) {
	*result = NULL;

	int ret = 0;

	char *tmp = NULL;

	ssize_t length;
	const char *data = rrr_mqtt_property_get_blob(property, &length);

	if ((tmp = rrr_allocate(length + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_propert_get_blob_as_str\n");
		ret = 1;
		goto out;
	}

	memcpy(tmp, data, length);
	tmp[length] = '\0';

	*result = tmp;
	tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	return ret;
}

static int __rrr_mqtt_property_clone (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property *source
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_property *result = NULL;

	if ((ret = rrr_mqtt_property_new(&result, source->definition)) != 0) {
		RRR_MSG_0("Could not create new property in __rrr_mqtt_property_clone\n");
		goto out;
	}

	if (source->sibling != NULL) {
		if ((ret = __rrr_mqtt_property_clone(&result->sibling, source->sibling)) != 0) {
			RRR_MSG_0("Could not clone sibling in __rrr_mqtt_property_clone\n");
			goto out_destroy;
		}
	}

	result->order = source->order;
	result->internal_data_type = source->internal_data_type;

	if (source->length > 0) {
		result->length = source->length;
		if ((result->data = rrr_allocate(result->length)) == NULL) {
			RRR_MSG_0("Could not allocate memory for data in __rrr_mqtt_property_clone\n");
			ret = 1;
			goto out_destroy;
		}
		memcpy(result->data, source->data, result->length);
	}

	*target = result;

	goto out;
	out_destroy:
		rrr_mqtt_property_destroy(result);

	out:
	return ret;
}

int rrr_mqtt_property_collection_add_uint32 (
		struct rrr_mqtt_property_collection *collection,
		uint8_t id,
		uint32_t value
) {
	int ret = 0;

	struct rrr_mqtt_property *property = NULL;
	const struct rrr_mqtt_property_definition *definition = rrr_mqtt_property_get_definition(id);
	if (definition == NULL) {
		RRR_BUG("Property %u not found in rrr_mqtt_property_collection_add_uint32\n", id);
	}

	uint32_t max = 0;
	switch (definition->internal_data_type) {
		case RRR_MQTT_PROPERTY_DATA_TYPE_ONE:
			max = 0xff; break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_TWO:
			max = 0xffff; break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_FOUR:
			max = 0xffffffff; break; // Eight f's
		case RRR_MQTT_PROPERTY_DATA_TYPE_VINT:
			max = 0xfffffff; break; // Seven f's
		case RRR_MQTT_PROPERTY_DATA_TYPE_BLOB:
		case RRR_MQTT_PROPERTY_DATA_TYPE_UTF8:
		case RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8:
		default:
			RRR_BUG("Property %u was not an unsigned int value in rrr_mqtt_property_collection_add_uint32\n", id);
	};

	if (value > max) {
		RRR_MSG_0("Value %u was too long to be held by property 0x%02x in rrr_mqtt_property_collection_add_uint32, max is %" PRIu32"\n",
				value, id, max);
		goto out;
	}

	if ((ret = rrr_mqtt_property_new(&property, definition)) != 0) {
		RRR_MSG_0("Could not create property in rrr_mqtt_property_collection_add_uint32\n");
		goto out;
	}

	if ((ret = rrr_mqtt_property_save_uint32(property, value)) != 0) {
		RRR_MSG_0("Could not save property value in rrr_mqtt_property_collection_add_uint32\n");
		goto out_free_property;
	}

	rrr_mqtt_property_collection_add(collection, property);

	goto out;
	out_free_property:
		rrr_mqtt_property_destroy(property);
	out:
		return ret;
}

int rrr_mqtt_property_collection_add_blob_or_utf8 (
		struct rrr_mqtt_property_collection *collection,
		uint8_t id,
		const char *value,
		uint16_t size
) {
	int ret = 0;

	struct rrr_mqtt_property *property = NULL;
	const struct rrr_mqtt_property_definition *definition = rrr_mqtt_property_get_definition(id);
	if (definition == NULL) {
		RRR_BUG("Property %u not found in rrr_mqtt_property_collection_add_blob_or_utf8\n", id);
	}

	int add_zero_if_needed = 0;

	switch (definition->internal_data_type) {
		case RRR_MQTT_PROPERTY_DATA_TYPE_ONE:
		case RRR_MQTT_PROPERTY_DATA_TYPE_TWO:
		case RRR_MQTT_PROPERTY_DATA_TYPE_FOUR:
		case RRR_MQTT_PROPERTY_DATA_TYPE_VINT:
		case RRR_MQTT_PROPERTY_DATA_TYPE_BLOB:
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_UTF8:
			add_zero_if_needed = 1;
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8:
		default:
			RRR_BUG("Property %u was not a utf8/blob value in rrr_mqtt_property_collection_add_blob_or_utf8\n", id);
	};

	if ((ret = rrr_mqtt_property_new(&property, definition)) != 0) {
		RRR_MSG_0("Could not create property in rrr_mqtt_property_collection_add_blob_or_utf8\n");
		goto out;
	}

	if ((ret = rrr_mqtt_property_save_blob(property, value, size, add_zero_if_needed)) != 0) {
		RRR_MSG_0("Could not save property value in rrr_mqtt_property_collection_add_blob_or_utf8\n");
		goto out_free_property;
	}

	rrr_mqtt_property_collection_add(collection, property);

	goto out;
	out_free_property:
		rrr_mqtt_property_destroy(property);
	out:
		return ret;
}

void rrr_mqtt_property_collection_add (
		struct rrr_mqtt_property_collection *collection,
		struct rrr_mqtt_property *property
) {
	property->order = ++(collection->order_count);

	RRR_LL_APPEND(collection, property);
}

int rrr_mqtt_property_collection_add_cloned (
		struct rrr_mqtt_property_collection *collection,
		const struct rrr_mqtt_property *property
) {
	struct rrr_mqtt_property *new_property = NULL;

	if (property == NULL) {
		RRR_BUG("BUG: Propery was NULL in rrr_mqtt_property_collection_add_cloned\n");
	}

	int ret = 0;

	ret = rrr_mqtt_property_clone(&new_property, property);
	if (ret != 0) {
		RRR_MSG_0("Could not clone property in rrr_mqtt_property_collection_add_cloned\n");
		goto out;
	}

	new_property->order = ++(collection->order_count);

	RRR_LL_APPEND(collection, new_property);

	out:
	return ret;
}

int rrr_mqtt_property_collection_iterate (
	const struct rrr_mqtt_property_collection *collection,
	int (*callback)(const struct rrr_mqtt_property *property, void *arg),
	void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_mqtt_property);
		ret = callback(node, callback_arg);
		if (ret != 0) {
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

unsigned int rrr_mqtt_property_collection_count_duplicates (
		const struct rrr_mqtt_property_collection *collection,
		const struct rrr_mqtt_property *self
) {
	unsigned int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_mqtt_property);
		if (RRR_MQTT_PROPERTY_GET_ID(node) == RRR_MQTT_PROPERTY_GET_ID(self) && node != self) {
			ret += 1;
		}
	RRR_LL_ITERATE_END();

	return ret;

}

static void __rrr_mqtt_property_dump (
		const struct rrr_mqtt_property *property
) {
	char *tmp = NULL;

	printf("%s: ", property->definition->name);
	switch (property->internal_data_type) {
		case RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB:
			tmp = rrr_allocate(property->length + 1);
			memcpy(tmp, property->data, property->length);
			tmp[property->length] = '\0';
			printf("%s", tmp);
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32:
			printf ("%" PRIu32 "", *((uint32_t*) property->data));
			break;
		default:
			printf ("unknown internal type %u", property->internal_data_type);
			break;
	};
	printf("\n");

	if (property->sibling != NULL) {
		__rrr_mqtt_property_dump(property->sibling);
	}

	RRR_FREE_IF_NOT_NULL(tmp);
}

void rrr_mqtt_property_collection_dump (
		const struct rrr_mqtt_property_collection *collection
) {
	printf("--- DUMP PROPERTY COLLECTION ---------\n");
	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_mqtt_property);
		__rrr_mqtt_property_dump(node);
	RRR_LL_ITERATE_END();
	printf("--- DUMP PROPERTY COLLECTION END -----\n");
}

struct rrr_mqtt_property *rrr_mqtt_property_collection_get_property (
		struct rrr_mqtt_property_collection *collection,
		uint8_t identifier,
		ssize_t index
) {
	int match_count = 0;

	struct rrr_mqtt_property *ret = NULL;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_mqtt_property);
		if (node->definition->identifier == identifier) {
			if (match_count == index) {
				ret = node;
				RRR_LL_ITERATE_LAST();
			}
			match_count++;
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int rrr_mqtt_property_collection_calculate_size (
		ssize_t *size,
		ssize_t *count,
		const struct rrr_mqtt_property_collection *collection
) {
	int ret = 0;

	*count = 0;
	*size = 0;

	ssize_t result = 0;
	ssize_t result_count = 0;
	uint32_t tmp = 0;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_mqtt_property);
		switch (node->definition->internal_data_type) {
			case RRR_MQTT_PROPERTY_DATA_TYPE_ONE:
				result += 1; break;
			case RRR_MQTT_PROPERTY_DATA_TYPE_TWO:
				result += 2; break;
			case RRR_MQTT_PROPERTY_DATA_TYPE_FOUR:
				result += 4; break;
			case RRR_MQTT_PROPERTY_DATA_TYPE_VINT:
				tmp = *((uint32_t*)(node->data));
				if ((tmp & ~0xfffffff) != 0) {
					RRR_BUG("VINT was too long in rrr_mqtt_property_collection_calculate_size\n");
				}
				do {
					result += 1;
					tmp >>= 7;
				} while (tmp != 0);
				break;
			case RRR_MQTT_PROPERTY_DATA_TYPE_BLOB:
				result += 2 + node->length; break;
			case RRR_MQTT_PROPERTY_DATA_TYPE_UTF8:
				result += 2 + node->length; break;
			case RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8:
				result += 2 + node->length;
				if (node->sibling == NULL) {
					RRR_BUG("2UTF8 had no sibling in rrr_mqtt_property_collection_calculate_size\n");
				}
				result += 2 + node->sibling->length;
				break;
			default:
				RRR_BUG("Invalid type %u in rrr_mqtt_property_collection_calculate_size\n", node->definition->internal_data_type);
		};
		result_count++;
		if (result < 0) {
			RRR_MSG_0("Size overflow in rrr_mqtt_property_collection_calculate_size\n");
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	*size = result;
	*count = result_count;

	out:
	return ret;
}

void rrr_mqtt_property_collection_clear (
		struct rrr_mqtt_property_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_mqtt_property, rrr_mqtt_property_destroy(node));
}

int rrr_mqtt_property_collection_add_selected_from_collection (
		struct rrr_mqtt_property_collection *target,
		const struct rrr_mqtt_property_collection *source,
		uint8_t identifiers[],
		size_t identifiers_length
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_mqtt_property);
		int do_clone = 1;

		if (identifiers_length > 0) {
			do_clone = 0;
			for (size_t i = 0; i < identifiers_length; i++) {
				if (node->definition->identifier == identifiers[i]) {
					do_clone = 1;
					break;
				}
			}
		}

		if (do_clone) {
			struct rrr_mqtt_property *new_node = NULL;
			ret = __rrr_mqtt_property_clone(&new_node, node);
			if (ret != 0) {
				RRR_MSG_0("Could not clone property in rrr_mqtt_property_collection_clone\n");
				goto out_destroy;
			}
			rrr_mqtt_property_collection_add(target, new_node);
		}
	RRR_LL_ITERATE_END();

	goto out;
	out_destroy:
		rrr_mqtt_property_collection_clear(target);
	out:
		return ret;
}

int rrr_mqtt_property_collection_add_from_collection (
		struct rrr_mqtt_property_collection *target,
		const struct rrr_mqtt_property_collection *source
) {
	return rrr_mqtt_property_collection_add_selected_from_collection(
			target,
			source,
			NULL,
			0
	);
}
