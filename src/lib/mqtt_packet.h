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
#include "mqtt_property.h"

#define RRR_MQTT_MIN_RECEIVE_SIZE 2

#define RRR_MQTT_VERSION_3_1		3
#define RRR_MQTT_VERSION_3_1_1		4
#define RRR_MQTT_VERSION_5			5

struct rrr_mqtt_connection;
struct rrr_mqtt_p_type_properties;
struct rrr_mqtt_p_protocol_version;
struct rrr_mqtt_p_parse_session;
struct rrr_mqtt_payload_buf_session;
struct rrr_mqtt_p_packet;

#define RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION \
		const struct rrr_mqtt_p_type_properties *type_properties, \
		const struct rrr_mqtt_p_protocol_version *protocol_version

#define RRR_MQTT_P_TYPE_FREE_DEFINITION \
		struct rrr_mqtt_p_packet *packet

struct rrr_mqtt_p_protocol_version {
	uint8_t id;
	const char *name;
};

struct rrr_mqtt_p_header {
	uint8_t type;
	uint8_t length[4];
} __attribute__((packed));

struct rrr_mqtt_p_type_properties {
	/* If has_reserved_flags is non-zero, a packet must have the exact specified flags set to be valid */
	uint8_t type_id;
	uint8_t complementary_id; // Used for ACK packets. Zero means non-ack packet.
	const char *name;
	uint8_t has_reserved_flags;
	uint8_t flags;
	ssize_t packet_size;

	struct rrr_mqtt_p_packet *(*allocate)(RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION);

	// We do not use function argument macros for these two to avoid including the header files
	int (*parse)(struct rrr_mqtt_p_parse_session *session);
	int (*assemble)(char **target, ssize_t *size, struct rrr_mqtt_p_packet *packet);

	// DO NOT use the free-functions directly, ALWAYS use the RRR_MQTT_P_DECREF-macro
	void (*free)(RRR_MQTT_P_TYPE_FREE_DEFINITION);
};

// Assembled data is either generated when sending a newly created packet,
// or it is saved when reading from network (if the packet type parser requires it).

// When sending data, if the payload pointer is non-NULL, we append this directly after
// assembled_data. A packet type which does this should ensure that, after parsing, the
// assembled_data_size value is reduced to the length of the variable header if it also
// stores the payload data (will be the case for received packets). Payload data
// memory might however also be managed elsewhere for locally created packets.

#define RRR_MQTT_P_PACKET_HEADER								\
	int users;													\
	pthread_mutex_t lock;										\
	uint8_t type_flags;											\
	uint16_t packet_identifier;									\
	uint64_t create_time;										\
	uint64_t last_attempt;										\
	char *assembled_data;										\
	ssize_t assembled_data_size;								\
	const char *payload_pointer;								\
	ssize_t payload_size;										\
	const struct rrr_mqtt_p_protocol_version *protocol_version;	\
	const struct rrr_mqtt_p_type_properties *type_properties

struct rrr_mqtt_p_packet {
	RRR_MQTT_P_PACKET_HEADER;
};

#define RRR_MQTT_P_GET_TYPE(p)			((p)->type_properties->type_id)
#define RRR_MQTT_P_GET_TYPE_FLAGS(p)	((p)->type_flags)
#define RRR_MQTT_P_GET_IDENTIFIER(p)	((p)->packet_identifier)
#define RRR_MQTT_P_GET_TYPE_NAME(p)		((p)->type_properties->name)
#define RRR_MQTT_P_GET_SIZE(p)			((p)->type_properties->packet_size)
#define RRR_MQTT_P_GET_COMPLEMENTARY(p)	((p)->type_properties->complementary_id)
#define RRR_MQTT_P_GET_PROP_FLAGS(p)	((p)->type_properties->flags)
#define RRR_MQTT_P_GET_PARSER(p)		((p)->type_properties->parse)
#define RRR_MQTT_P_GET_ASSEMBLER(p)		((p)->type_properties->assemble)
#define RRR_MQTT_P_GET_FREE(p)			((p)->type_properties->free)
#define RRR_MQTT_P_IS_RESERVED_FLAGS(p)	((p)->type_properties->has_reserved_flags)
#define RRR_MQTT_P_IS_ACK(p)			((p)->type_properties->complementary_id == 0)
#define RRR_MQTT_P_IS_V5(p)				((p)->protocol_version->id == 5)

#define RRR_MQTT_P_INCREF(p)				\
	do {									\
		pthread_mutex_lock(&(p)->lock);		\
		(p)->users++;						\
		pthread_mutex_unlock(&(p)->lock);	\
	} while (0)

#define RRR_MQTT_P_DECREF(p)										\
	do {															\
		pthread_mutex_lock(&(p)->lock);								\
		--(p)->users;												\
		pthread_mutex_unlock(&(p)->lock);							\
		if ((p)->users == 0) {										\
			RRR_FREE_IF_NOT_NULL((p)->assembled_data);				\
			pthread_mutex_destroy(&(p)->lock);						\
			RRR_MQTT_P_GET_FREE(p)((struct rrr_mqtt_p_packet *)p);	\
			(p) = NULL;												\
		}															\
	} while (0)

#define RRR_MQTT_P_DECREF_IF_NOT_NULL(p)	\
	do {									\
		if ((p) != NULL) {					\
			RRR_MQTT_P_DECREF(p);			\
		}									\
	} while(0)

struct rrr_mqtt_p_packet_connect {
	RRR_MQTT_P_PACKET_HEADER;

	uint8_t connect_flags;
	uint16_t keep_alive;

	char *client_identifier;

	// For version 5
	struct rrr_mqtt_p_property_collection properties;
	struct rrr_mqtt_p_property_collection will_properties;

	char *will_topic;
	char *will_message;

	char *username;
	char *password;
};

#define RRR_MQTT_P_CONNECT_GET_FLAG_RESERVED(p)			((1<<0) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(p)		(((1<<1) & (p)->connect_flags) >> 1)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL(p)				(((1<<2) & (p)->connect_flags) >> 2)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(p)			((((1<<4)|(1<<3)) & (p)->connect_flags) >> 3)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(p)		(((1<<5) & (p)->connect_flags) >> 5)
#define RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(p) 		(((1<<6) & (p)->connect_flags) >> 6)
#define RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(p)		(((1<<7) & (p)->connect_flags) >> 7)

struct rrr_mqtt_p_packet_connack {
	RRR_MQTT_P_PACKET_HEADER;

	// Only least significant bit is used (session_present)
	uint8_t ack_flags;

	uint8_t connect_reason_code;

	// For version 5
	struct rrr_mqtt_p_property_collection properties;
};

struct rrr_mqtt_p_packet_publish {
	RRR_MQTT_P_PACKET_HEADER;

	/* These are also accessible through packet type flags but we cache them here */
	uint8_t dup;
	uint8_t qos;
	uint8_t retain;

	char *topic;

	// For version 5
	struct rrr_mqtt_p_property_collection properties;
};

#define RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(p)			(((1<<0) & (p)->type_flags))
#define RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(p)				((((1<<2)|(1<<1)) & (p)->type_flags) >> 2)
#define RRR_MQTT_P_PUBLISH_GET_FLAG_DUP(p)				(((1<<3) & (p)->type_flags) >> 3)

struct rrr_mqtt_p_packet_puback {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_pubrec {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_pubrel {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_pubcomp {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_subscribe {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_suback {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_unsubscribe {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_unsuback {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_pingreq {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_pingresp {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_disconnect {
	RRR_MQTT_P_PACKET_HEADER;

	uint8_t disconnect_reason_code;

	// For version 5
	struct rrr_mqtt_p_property_collection properties;
};
struct rrr_mqtt_p_packet_auth {
	RRR_MQTT_P_PACKET_HEADER;
};

struct rrr_mqtt_p_queue {
	struct fifo_buffer buffer;
};

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

const struct rrr_mqtt_p_protocol_version *rrr_mqtt_p_get_protocol_version (uint8_t id);

static inline void rrr_mqtt_p_incref (void *packet) {
	RRR_MQTT_P_INCREF((struct rrr_mqtt_p_packet *) packet);
}

static inline void rrr_mqtt_p_decref (void *_packet) {
	struct rrr_mqtt_p_packet *packet = _packet;
	RRR_MQTT_P_DECREF(packet);
}

static inline int rrr_mqtt_p_get_refcount (struct rrr_mqtt_p_packet *packet) {
	int ret = 0;
	pthread_mutex_lock(&packet->lock);
	ret = packet->users;
	pthread_mutex_unlock(&packet->lock);
	return ret;
}

extern const struct rrr_mqtt_p_type_properties rrr_mqtt_p_type_properties[];
static inline const struct rrr_mqtt_p_type_properties *rrr_mqtt_p_get_type_properties (uint8_t id) {
	if (id > 15 || id == 0) {
		VL_BUG("Invalid ID in rrr_mqtt_p_get_type_properties\n");
	}
	return &rrr_mqtt_p_type_properties[id];
}

static inline struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate (uint8_t id, const struct rrr_mqtt_p_protocol_version *protocol_version) {
	const struct rrr_mqtt_p_type_properties *properties = rrr_mqtt_p_get_type_properties(id);

	return properties->allocate(properties, protocol_version);
}

uint8_t rrr_mqtt_p_translate_connect_reason_from_v5 (uint8_t v5_reason);
uint8_t rrr_mqtt_p_translate_connect_reason_from_v31 (uint8_t v31_reason);

#endif /* RRR_MQTT_PACKET_H */
