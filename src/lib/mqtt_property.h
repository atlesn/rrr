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

#ifndef RRR_MQTT_PROPERTY_H
#define RRR_MQTT_PROPERTY_H

#include <inttypes.h>

#define RRR_MQTT_PROPERTY_DATA_TYPE_ONE 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_TWO 2
#define RRR_MQTT_PROPERTY_DATA_TYPE_FOUR 4
#define RRR_MQTT_PROPERTY_DATA_TYPE_VINT 5
#define RRR_MQTT_PROPERTY_DATA_TYPE_BLOB 6
#define RRR_MQTT_PROPERTY_DATA_TYPE_UTF8 7
#define RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8 8

#define RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB 2

const struct rrr_mqtt_p_property_definition *rrr_mqtt_p_get_property_definition(uint8_t id);

struct rrr_mqtt_p_properties_header {
	/* Data starts at .data[.length_decoded] */
	uint32_t length_decoded;
	union {
		uint8_t length[4];
		char data[5];
	};
};

struct rrr_mqtt_p_property_definition {
	int type;
	uint8_t identifier;

	/* Human readable name */
	const char *name;
};

struct rrr_mqtt_p_property {
	struct rrr_mqtt_p_property *next;

	int order;

	/* Some properties have two values */
	struct rrr_mqtt_p_property *sibling;
	const struct rrr_mqtt_p_property_definition *definition;
	uint8_t internal_data_type;
	ssize_t length;
	char *data;
};

/* Properties are stored in the order of which they appear in the packets */
struct rrr_mqtt_p_property_collection {
	struct rrr_mqtt_p_property *first;
	struct rrr_mqtt_p_property *last;
	int count;
};

void rrr_mqtt_packet_property_destroy (
		struct rrr_mqtt_p_property *property
);
int rrr_mqtt_packet_property_new (
		struct rrr_mqtt_p_property **target,
		const struct rrr_mqtt_p_property_definition *definition
);
void rrr_mqtt_packet_property_collection_add (
		struct rrr_mqtt_p_property_collection *collection,
		struct rrr_mqtt_p_property *property
);
void rrr_mqtt_packet_property_collection_destroy (
		struct rrr_mqtt_p_property_collection *collection
);
void rrr_mqtt_packet_property_collection_init (
		struct rrr_mqtt_p_property_collection *collection
);


#endif /* RRR_MQTT_PROPERTY_H */