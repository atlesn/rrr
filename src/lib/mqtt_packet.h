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

#ifndef RRR_MQTT_PACKET_H
#define RRR_MQTT_PACKET_H

#include <inttypes.h>
#include <stdio.h>

#include "buffer.h"

#define RRR_MQTT_MIN_RECEIVE_SIZE 2

#define RRR_MQTT_PROTOCOL_NAME "MQTT"
#define RRR_MQTT_PROTOCOL_NAME_LENGTH 4

#define RRR_MQTT_VERSION_5 5

struct rrr_mqtt_p_header {
	uint8_t type;
	uint8_t length[4];
} __attribute__((packed));

struct rrr_mqtt_properties_header {
	/* Data starts at .data[.length_decoded] */
	uint32_t length_decoded;
	union {
		uint8_t length[4];
		char data[5];
	};
};

#define RRR_MQTT_PROPERTY_DATA_TYPE_ONE 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_TWO 2
#define RRR_MQTT_PROPERTY_DATA_TYPE_FOUR 4
#define RRR_MQTT_PROPERTY_DATA_TYPE_VINT 5
#define RRR_MQTT_PROPERTY_DATA_TYPE_BLOB 6
#define RRR_MQTT_PROPERTY_DATA_TYPE_UTF8 7
#define RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8 8

struct rrr_mqtt_property_definition {
	int type;
	uint8_t identifier;

	/* Human readable name */
	const char *name;
};

static const struct rrr_mqtt_property_definition property_definitions[] = {
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

struct rrr_mqtt_property {
	struct rrr_mqtt_property *next;

	/* Some properties have two values */
	struct rrr_mqtt_property *sibling;
	const struct rrr_property_definition *definition;
	uint8_t data_type;
	ssize_t length;
	char *data;
};

struct rrr_mqtt_property_collection {
	struct rrr_mqtt_property *first;
	int count;
};

/* The total size of this struct is defined by receive_length */
struct rrr_mqtt_rx_data {
	/* The length of the fixed header. Data starts at .data[.header_length] */
	ssize_t header_length;

	/* The variable int receive length, decoded */
	ssize_t receive_length;

	union {
		struct rrr_mqtt_p_header header;
		char data[6];
	};

	/* The following fields are populated as the packet is parsed by the
	 * different handler functions. */
	struct rrr_mqtt_property_collection *properties;
};

struct mqtt_packet_internal {
	uint8_t type;
	ssize_t data_length;
	char *data;
};

struct rrr_mqtt_packet_queue {
	/* Must be first */
	struct fifo_buffer buffer;
};

struct rrr_mqtt_p_connect {
	uint16_t name_length;
	char name[RRR_MQTT_PROTOCOL_NAME_LENGTH];
	uint8_t version;
	uint8_t connect_flags;
	uint16_t keep_alive;
	uint8_t property_length;
	char properties[1];
} __attribute__((packed));

#define RRR_MQTT_P_TYPE_RESERVED	0
#define RRR_MQTT_P_TYPE_CONNECT		1
#define RRR_MQTT_P_TYPE_CONNACK		2
#define RRR_MQTT_P_TYPE_PUBLISH		3
#define RRR_MQTT_P_TYPE_PUBACK		4
#define RRR_MQTT_P_TYPE_PUBREC		5
#define RRR_MQTT_P_TYPE_PUBREL		6
#define RRR_MQTT_P_TYPE_PUBCOMP		7
#define RRR_MQTT_P_TYPE_SUBSCRIBE	8
#define RRR_MQTT_P_TYPE_SUBACK		9
#define RRR_MQTT_P_TYPE_UNSUBSCRIBE	10
#define RRR_MQTT_P_TYPE_UNSUBACK	11
#define RRR_MQTT_P_TYPE_PINGREQ		12
#define RRR_MQTT_P_TYPE_PINGRESP	13
#define RRR_MQTT_P_TYPE_DISCONNECT	14
#define RRR_MQTT_P_TYPE_AUTH		15

static const char *rrr_mqtt_packet_type_names[] = {
	"RESERVED",
	"CONNECT",
	"CONNACK",
	"PUBLISH",
	"PUBACK",
	"PUBREC",
	"PUBREL",
	"PUBCOMP",
	"SUBSCRIBE",
	"SUBACK",
	"UNSUBSCRIBE",
	"UNSUBACK",
	"PINGREQ",
	"PINGRESP",
	"DISCONNECT",
	"AUTH"
};

#define RRR_MQTT_P_GET_TYPE(p)			((p)->type & (0xF << 4))
#define RRR_MQTT_P_GET_TYPE_FLAGS(p)	((p)->type & (0xF))

#define RRR_MQTT_P_GET_TYPE_NAME(p)		(rrr_mqtt_packet_type_names[(p)->type])

#define RRR_MQTT_P_CONNECT_GET_FLAG_RESERVED(p)			((1<<0) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(p)		((1<<1) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_FLAG(p)		((1<<2) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(p)			(((1<<3)|(1<<4)) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(p)		((1<<5) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(p) 		((1<<6) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(p)		((1<<7) & (p)->connect_flags)



#endif /* RRR_MQTT_PACKET_H */
