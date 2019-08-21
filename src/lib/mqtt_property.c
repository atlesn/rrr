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
#include "mqtt_property.h"
#include "linked_list.h"

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
	for (int i = 0; property_definitions[i].type != 0; i++) {
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
	free(property);
}

int rrr_mqtt_property_new (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property_definition *definition
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_property *res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_property_new\n");
		ret = 1;
		goto out;
	}

	memset(res, '\0', sizeof(*res));

	res->definition = definition;

	*target = res;

	out:
	return ret;
}

static int __rrr_mqtt_property_clone (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property *source
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_property *result = NULL;

	ret = rrr_mqtt_property_new(&result, source->definition);
	if (ret != 0) {
		VL_MSG_ERR("Could not create new property in __rrr_mqtt_property_clone\n");
	}

	if (source->sibling != NULL) {
		ret = __rrr_mqtt_property_clone(&result->sibling, source->sibling);
		if (ret != 0) {
			VL_MSG_ERR("Could not clone sibling in __rrr_mqtt_property_clone\n");
			goto out_destroy;
		}
	}

	result->order = source->order;
	result->internal_data_type = source->internal_data_type;

	if (source->length > 0) {
		result->length = source->length;
		result->data = malloc(result->length);
		if (result->data == NULL) {
			VL_MSG_ERR("Could not allocate memory for data in __rrr_mqtt_property_clone\n");
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

void rrr_mqtt_property_collection_add (
		struct rrr_mqtt_property_collection *collection,
		struct rrr_mqtt_property *property
) {
	property->order = ++(collection->order_count);

	RRR_LINKED_LIST_APPEND(collection, property);
}

void rrr_mqtt_property_collection_destroy (
		struct rrr_mqtt_property_collection *collection
) {
	RRR_LINKED_LIST_DESTROY(collection, struct rrr_mqtt_property, rrr_mqtt_property_destroy(node));
}

int rrr_mqtt_property_collection_clone (
		struct rrr_mqtt_property_collection *target,
		const struct rrr_mqtt_property_collection *source
) {
	int ret = 0;

	memset(target, '\0', sizeof(*target));

	RRR_LINKED_LIST_ITERATE_BEGIN(source, const struct rrr_mqtt_property);
		struct rrr_mqtt_property *new_node = NULL;
		ret = __rrr_mqtt_property_clone(&new_node, node);
		if (ret != 0) {
			VL_MSG_ERR("Could not clone property in rrr_mqtt_property_collection_clone\n");
			goto out_destroy;
		}
		rrr_mqtt_property_collection_add(target, new_node);
	RRR_LINKED_LIST_ITERATE_END();

	goto out;
	out_destroy:
		rrr_mqtt_property_collection_destroy(target);
	out:
		return ret;
}

void rrr_mqtt_property_collection_init (
		struct rrr_mqtt_property_collection *collection
) {
	memset(collection, '\0', sizeof(*collection));
}
