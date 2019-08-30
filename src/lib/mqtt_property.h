/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not

*/

#ifndef RRR_MQTT_PROPERTY_H
#define RRR_MQTT_PROPERTY_H

#include <inttypes.h>

#include "linked_list.h"

#define RRR_MQTT_PROPERTY_DATA_TYPE_ONE 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_TWO 2
#define RRR_MQTT_PROPERTY_DATA_TYPE_FOUR 4
#define RRR_MQTT_PROPERTY_DATA_TYPE_VINT 5
#define RRR_MQTT_PROPERTY_DATA_TYPE_BLOB 6
#define RRR_MQTT_PROPERTY_DATA_TYPE_UTF8 7
#define RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8 8

#define RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB 2

#define RRR_MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR	0x01
#define RRR_MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL	0x02
#define RRR_MQTT_PROPERTY_CONTENT_TYPE				0x03
#define RRR_MQTT_PROPERTY_RESPONSE_TOPIC			0x08
#define RRR_MQTT_PROPERTY_CORRELATION_DATA			0x09
#define RRR_MQTT_PROPERTY_SUBSCRIPTION_ID			0x0B
#define RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL	0x11
#define RRR_MQTT_PROPERTY_ASSIGNED_CLIENT_ID		0x12
#define RRR_MQTT_PROPERTY_SERVER_KEEP_ALIVE			0x13
#define RRR_MQTT_PROPERTY_AUTH_METHOD				0x15
#define RRR_MQTT_PROPERTY_AUTH_DATA					0x16
#define RRR_MQTT_PROPERTY_REQUEST_PROBLEM_INFO		0x17
#define RRR_MQTT_PROPERTY_WILL_DELAY_INTERVAL		0x18
#define RRR_MQTT_PROPERTY_REQUEST_RESPONSE_INFO		0x19
#define RRR_MQTT_PROPERTY_RESPONSE_INFO				0x1A
#define RRR_MQTT_PROPERTY_SERVER_REFERENCE			0x1C
#define RRR_MQTT_PROPERTY_REASON_STRING				0x1F
#define RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM			0x21
#define RRR_MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM		0x22
#define RRR_MQTT_PROPERTY_TOPIC_ALIAS				0x23
#define RRR_MQTT_PROPERTY_MAXIMUM_QOS				0x24
#define RRR_MQTT_PROPERTY_RETAIN_AVAILABLE			0x25
#define RRR_MQTT_PROPERTY_USER_PROPERTY				0x26
#define RRR_MQTT_PROPERTY_MAXIMUM_PACKET_SIZE		0x27
#define RRR_MQTT_PROPERTY_WILDCARD_SUB_AVAILBABLE	0x28
#define RRR_MQTT_PROPERTY_SUBSCRIPTION_ID_AVAILABLE	0x29
#define RRR_MQTT_PROPERTY_SHARED_SUB_AVAILABLE		0x2A

const struct rrr_mqtt_property_definition *rrr_mqtt_property_get_definition(uint8_t id);

struct rrr_mqtt_p_properties_header {
	/* Data starts at .data[.length_decoded] */
	uint32_t length_decoded;
	union {
		uint8_t length[4];
		char data[5];
	};
};

struct rrr_mqtt_property_definition {
	int type;
	uint8_t identifier;

	/* Human readable name */
	const char *name;
};

struct rrr_mqtt_property {
	RRR_LINKED_LIST_NODE(struct rrr_mqtt_property);

	int order;

	/* Some properties have two values */
	struct rrr_mqtt_property *sibling;
	const struct rrr_mqtt_property_definition *definition;
	uint8_t internal_data_type;
	ssize_t length;
	ssize_t length_orig;
	char *data;
};

#define RRR_MQTT_PROPERTY_IS(property, id) \
	(property->definition->identifier == id)

#define RRR_MQTT_PROPERTY_GET_ID(property) \
	(property->definition->identifier)

#define RRR_MQTT_PROPERTY_GET_NAME(property) \
	(property->definition->name)

/* Properties are stored in the order of which they appear in the packets */
struct rrr_mqtt_property_collection {
	RRR_LINKED_LIST_HEAD(struct rrr_mqtt_property);
	int order_count;
};

void rrr_mqtt_property_destroy (
		struct rrr_mqtt_property *property
);
int rrr_mqtt_property_new (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property_definition *definition
);
int rrr_mqtt_property_clone (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property *source
);
int rrr_mqtt_property_save_blob (
		struct rrr_mqtt_property *target,
		const char *value,
		uint16_t size
);
int rrr_mqtt_property_save_uint32 (
		struct rrr_mqtt_property *target,
		uint32_t value
);
uint32_t rrr_mqtt_property_get_uint32 (
		const struct rrr_mqtt_property *property
);
const char *rrr_mqtt_property_get_blob (
		const struct rrr_mqtt_property *property,
		ssize_t *length
);
int rrr_mqtt_property_collection_add_uint32 (
		struct rrr_mqtt_property_collection *collection,
		uint8_t id,
		uint32_t value
);
int rrr_mqtt_property_collection_add_blob_or_utf8 (
		struct rrr_mqtt_property_collection *collection,
		uint8_t id,
		const char *value,
		uint16_t size
);
void rrr_mqtt_property_collection_add (
		struct rrr_mqtt_property_collection *collection,
		struct rrr_mqtt_property *property
);
int rrr_mqtt_property_collection_add_cloned (
		struct rrr_mqtt_property_collection *collection,
		const struct rrr_mqtt_property *property
);
int rrr_mqtt_property_collection_iterate (
	const struct rrr_mqtt_property_collection *collection,
	int (*callback)(const struct rrr_mqtt_property *property, void *arg),
	void *callback_arg
);
unsigned int rrr_mqtt_property_collection_count_duplicates (
		const struct rrr_mqtt_property_collection *collection,
		const struct rrr_mqtt_property *self
);
int rrr_mqtt_property_collection_calculate_size (
		ssize_t *size,
		ssize_t *count,
		const struct rrr_mqtt_property_collection *collection
);
void rrr_mqtt_property_collection_destroy (
		struct rrr_mqtt_property_collection *collection
);
int rrr_mqtt_property_collection_clone (
		struct rrr_mqtt_property_collection *target,
		const struct rrr_mqtt_property_collection *source
);


#endif /* RRR_MQTT_PROPERTY_H */
