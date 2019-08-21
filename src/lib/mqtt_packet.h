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

#define RRR_MQTT_P_31_REASON_OK							0
#define RRR_MQTT_P_31_REASON_BAD_PROTOCOL_VERSION		1
#define RRR_MQTT_P_31_REASON_CLIENT_ID_REJECTED		2
#define RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE			3
#define RRR_MQTT_P_31_REASON_BAD_CREDENTIALS			4
#define RRR_MQTT_P_31_REASON_NOT_AUTHORIZED				5
#define RRR_MQTT_P_31_REASON_MAX						5

// Used if a V5 reason cannot be understood with any V5 reasons. No
// CONNACK is sent for these reasons, the socket is simply closed.
#define RRR_MQTT_P_31_REASON_NO_CONNACK						254

// Used for DISCONNECT-only packets, they have no reason code in V3.1
#define RRR_MQTT_P_31_REASON_NA								255

#define RRR_MQTT_P_5_REASON_OK								0x00
#define RRR_MQTT_P_5_REASON_DISCONNECT_WITH_WILL			0x04

#define RRR_MQTT_P_5_REASON_NO_MATCHING_SUBSCRIBERS			0x10

#define RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR				0x80
#define RRR_MQTT_P_5_REASON_MALFORMED_PACKET				0x81
#define RRR_MQTT_P_5_REASON_PROTOCOL_ERROR					0x82
#define RRR_MQTT_P_5_REASON_IMPL_SPECIFIC_ERROR				0x83
#define RRR_MQTT_P_5_REASON_BAD_PROTOCOL_VERSION			0x84
#define RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED				0x85
#define RRR_MQTT_P_5_REASON_BAD_CREDENTIALS					0x86
#define RRR_MQTT_P_5_REASON_NOT_AUTHORIZED					0x87
#define RRR_MQTT_P_5_REASON_SERVER_UNAVAILABLE				0x88
#define RRR_MQTT_P_5_REASON_SERVER_BUSY						0x89
#define RRR_MQTT_P_5_REASON_BANNED							0x8A
#define RRR_MQTT_P_5_REASON_SERVER_SHUTTING_DOWN			0x8B
#define RRR_MQTT_P_5_REASON_BAD_AUTH_METHOD					0x8C
#define RRR_MQTT_P_5_REASON_KEEP_ALIVE_TIMEOUT				0x8D
#define RRR_MQTT_P_5_REASON_SESSION_TAKEN_OVER				0x8E
#define RRR_MQTT_P_5_REASON_TOPIC_FILTER_INVALID			0x8F

#define RRR_MQTT_P_5_REASON_TOPIC_NAME_INVALID				0x90
#define RRR_MQTT_P_5_REASON_PACKET_IDENTIFIER_IN_USE		0x91
#define RRR_MQTT_P_5_REASON_PACKET_IDENTIFIER_NOT_FOUND		0x92
#define RRR_MQTT_P_5_REASON_RECEIVE_MAX_EXCEEDED			0x93
#define RRR_MQTT_P_5_REASON_TOPIC_ALIAS_INVALID				0x94
#define RRR_MQTT_P_5_REASON_PACKET_TOO_LARGE				0x95
#define RRR_MQTT_P_5_REASON_MESSAGE_RATE_TOO_LARGE			0x96
#define RRR_MQTT_P_5_REASON_QUOTA_EXCEEDED					0x97
#define RRR_MQTT_P_5_REASON_ADMINISTRATIVE_ACTION			0x98
#define RRR_MQTT_P_5_REASON_PAYLOAD_FORMAT_INVALID			0x99
#define RRR_MQTT_P_5_REASON_RETAIN_NOT_SUPPORTED			0x9A
#define RRR_MQTT_P_5_REASON_QOS_NOT_SUPPORTED				0x9B
#define RRR_MQTT_P_5_REASON_USE_ANOTHER_SERVER				0x9C
#define RRR_MQTT_P_5_REASON_SERVER_MOVED					0x9D
#define RRR_MQTT_P_5_REASON_NO_SHARED_SUBSCRIPTIONS			0x9E
#define RRR_MQTT_P_5_REASON_CONNECTION_RATE_EXCEEDED		0x9F

#define RRR_MQTT_P_5_REASON_MAXIMUM_CONNECT_TIME			0xA0
#define RRR_MQTT_P_5_REASON_SUB_IDENTIFIERS_NOT_SUPPORTED	0xA1
#define RRR_MQTT_P_5_REASON_WILDCARD_SUBS_NOT_SUPPORTED		0xA2

struct rrr_mqtt_p;
struct rrr_mqtt_conn;
struct rrr_mqtt_p_type_properties;
struct rrr_mqtt_p_protocol_version;
struct rrr_mqtt_parse_session;
struct rrr_mqtt_payload_buf_session;
struct rrr_mqtt_subscription_collection;
struct rrr_mqtt_topic_token;

#define RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION \
		const struct rrr_mqtt_p_type_properties *type_properties, \
		const struct rrr_mqtt_p_protocol_version *protocol_version

#define RRR_MQTT_P_TYPE_CLONE_DEFINITION \
		const struct rrr_mqtt_p *source

#define RRR_MQTT_P_TYPE_FREE_DEFINITION \
		struct rrr_mqtt_p *packet

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

	struct rrr_mqtt_p *(*allocate)(RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION);
	struct rrr_mqtt_p *(*clone)(RRR_MQTT_P_TYPE_CLONE_DEFINITION);

	// We do not use function argument macros for these two to avoid including the header files
	int (*parse)(struct rrr_mqtt_parse_session *session);
	int (*assemble)(char **target, ssize_t *size, struct rrr_mqtt_p *packet);

	// DO NOT use the free-functions directly, ALWAYS use the RRR_MQTT_P_DECREF-macro
	void (*free)(RRR_MQTT_P_TYPE_FREE_DEFINITION);
};

#define RRR_MQTT_P_STANDARIZED_USERCOUNT_HEADER					\
	int users;													\
	pthread_mutex_t refcount_lock;								\
	void (*destroy)(void *arg)

struct rrr_mqtt_p_standarized_usercount {
	RRR_MQTT_P_STANDARIZED_USERCOUNT_HEADER;
};

struct rrr_mqtt_p_payload {
	RRR_MQTT_P_STANDARIZED_USERCOUNT_HEADER;
	pthread_mutex_t data_lock;

	// Pointer to full packet, used only by free()
	char *packet_data;

	// Pointer to where payload starts
	const char *payload_start;
	ssize_t payload_length;
};

// Assembled data is either generated when sending a newly created packet,
// or it is saved when reading from network (if the packet type parser requires it).

// When sending data, if the payload pointer is non-NULL, we append this directly after
// assembled_data. A packet type which does this should ensure that, after parsing, the
// assembled_data_size value is reduced to the length of the variable header if it also
// stores the payload data (will be the case for received packets). Payload data
// memory might however also be managed elsewhere for locally created packets. Packets
// may share the same payload data.

#define RRR_MQTT_P_PACKET_HEADER								\
	RRR_MQTT_P_STANDARIZED_USERCOUNT_HEADER;					\
	pthread_mutex_t data_lock;									\
	uint8_t type_flags;											\
	uint16_t packet_identifier;									\
	uint64_t create_time;										\
	uint64_t last_attempt;										\
	char *_assembled_data;										\
	ssize_t assembled_data_size;								\
	struct rrr_mqtt_p_payload *payload;							\
	const struct rrr_mqtt_p_protocol_version *protocol_version;	\
	const struct rrr_mqtt_p_type_properties *type_properties

struct rrr_mqtt_p {
	RRR_MQTT_P_PACKET_HEADER;
};

#define RRR_MQTT_P_GET_TYPE(p)				((p)->type_properties->type_id)
#define RRR_MQTT_P_GET_TYPE_FLAGS(p)		((p)->type_flags)
#define RRR_MQTT_P_GET_TYPE_AND_FLAGS(p)	((p)->type_properties->type_id << 4 | (p)->type_flags)
#define RRR_MQTT_P_GET_IDENTIFIER(p)		((p)->packet_identifier)
#define RRR_MQTT_P_GET_TYPE_NAME(p)			((p)->type_properties->name)
#define RRR_MQTT_P_GET_SIZE(p)				((p)->type_properties->packet_size)
#define RRR_MQTT_P_GET_COMPLEMENTARY(p)		((p)->type_properties->complementary_id)
#define RRR_MQTT_P_GET_PROP_FLAGS(p)		((p)->type_properties->flags)
#define RRR_MQTT_P_GET_PARSER(p)			((p)->type_properties->parse)
#define RRR_MQTT_P_GET_ASSEMBLER(p)			((p)->type_properties->assemble)
#define RRR_MQTT_P_GET_FREE(p)				((p)->type_properties->free)
#define RRR_MQTT_P_IS_RESERVED_FLAGS(p)		((p)->type_properties->has_reserved_flags)
#define RRR_MQTT_P_IS_ACK(p)				((p)->type_properties->complementary_id == 0)
#define RRR_MQTT_P_IS_V5(p)					((p)->protocol_version->id == 5)

#define RRR_MQTT_P_CALL_FREE(p)				((p)->type_properties->free(p))

static inline void rrr_mqtt_p_standardized_incref (void *arg) {
	struct rrr_mqtt_p_standarized_usercount *p = arg;
	pthread_mutex_lock(&p->refcount_lock);
	p->users++;
	pthread_mutex_unlock(&p->refcount_lock);
}

static inline void rrr_mqtt_p_standardized_decref (void *arg) {
	if (arg == NULL) {
		return;
	}
	struct rrr_mqtt_p_standarized_usercount *p = arg;
	pthread_mutex_lock(&(p)->refcount_lock);
	--(p)->users;
	pthread_mutex_unlock(&(p)->refcount_lock);
	if ((p)->users < 0) {
		VL_BUG("Users was < 0 in RRR_MQTT_P_DECREF\n");
	}
	if (p->users == 0) {
		pthread_mutex_destroy(&p->refcount_lock);
		p->destroy(p);
	}
}

#define RRR_MQTT_P_INCREF(p) \
	rrr_mqtt_p_standardized_incref(p)

#define RRR_MQTT_P_DECREF(p) \
	rrr_mqtt_p_standardized_decref(p)

#define RRR_MQTT_P_DECREF_IF_NOT_NULL(p)	\
	if ((p) != NULL)						\
		RRR_MQTT_P_DECREF(p)

#define RRR_MQTT_P_LOCK(p)	\
	pthread_mutex_lock(&((p)->data_lock))

#define RRR_MQTT_P_UNLOCK(p)	\
	pthread_mutex_unlock(&((p)->data_lock))

#define RRR_MQTT_P_TRYLOCK(p)	\
	pthread_mutex_trylock(&((p)->data_lock))

struct rrr_mqtt_p_connect {
	RRR_MQTT_P_PACKET_HEADER;

	uint8_t connect_flags;
	uint16_t keep_alive;

	char *client_identifier;

	// For version 5
	struct rrr_mqtt_property_collection properties;
	struct rrr_mqtt_property_collection will_properties;

	char *will_topic;
	char *will_message;

	char *username;
	char *password;
};

#define RRR_MQTT_P_CONNECT_GET_FLAG_RESERVED(p)			(((1<<0) &			((struct rrr_mqtt_p_connect *)(p))->connect_flags))
#define RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(p)		(((1<<1) &			((struct rrr_mqtt_p_connect *)(p))->connect_flags) >> 1)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL(p)				(((1<<2) &			((struct rrr_mqtt_p_connect *)(p))->connect_flags) >> 2)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(p)			((((1<<4)|(1<<3)) &	((struct rrr_mqtt_p_connect *)(p))->connect_flags) >> 3)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(p)		(((1<<5) &			((struct rrr_mqtt_p_connect *)(p))->connect_flags) >> 5)
#define RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(p) 		(((1<<6) &			((struct rrr_mqtt_p_connect *)(p))->connect_flags) >> 6)
#define RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(p)		(((1<<7) &			((struct rrr_mqtt_p_connect *)(p))->connect_flags) >> 7)

struct rrr_mqtt_p_connack {
	RRR_MQTT_P_PACKET_HEADER;

	// Only least significant bit is used (session_present)
	uint8_t ack_flags;

	uint8_t reason_v5;

	struct rrr_mqtt_property_collection properties;
};

#define RRR_MQTT_P_CONNACK_GET_REASON_V5(p)		(((struct rrr_mqtt_p_connack *)(p))->reason_v5)

struct rrr_mqtt_p_publish {
	RRR_MQTT_P_PACKET_HEADER;

	/* These are also accessible through packet type flags but we cache them here */
	uint8_t dup;
	uint8_t qos;
	uint8_t retain;

	/* If the packet is to be rejected, set to non-zero in parser */
	uint8_t reason_v5;

	char *topic;
	struct rrr_mqtt_topic_token *token_tree;

	struct rrr_mqtt_property_collection properties;
};

#define RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(p)	(((1<<0) &			((struct rrr_mqtt_p_publish *)(p))->type_flags))
#define RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(p)		((((1<<2)|(1<<1)) &	((struct rrr_mqtt_p_publish *)(p))->type_flags) >> 2)
#define RRR_MQTT_P_PUBLISH_GET_FLAG_DUP(p)		(((1<<3) &			((struct rrr_mqtt_p_publish *)(p))->type_flags) >> 3)

struct rrr_mqtt_p_puback {
	RRR_MQTT_P_PACKET_HEADER;
	uint8_t reason_v5;
	struct rrr_mqtt_property_collection properties;
};
struct rrr_mqtt_p_pubrec {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_pubrel {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_pubcomp {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_subscribe {
	RRR_MQTT_P_PACKET_HEADER;

	char *data_tmp;

	int max_qos;

	struct rrr_mqtt_subscription_collection *subscriptions;
	struct rrr_mqtt_property_collection properties;
};
struct rrr_mqtt_p_suback {
	RRR_MQTT_P_PACKET_HEADER;
	struct rrr_mqtt_property_collection properties;
	struct rrr_mqtt_subscription_collection *subscriptions;
};
struct rrr_mqtt_p_unsubscribe {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_unsuback {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_pingreq {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_pingresp {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_disconnect {
	RRR_MQTT_P_PACKET_HEADER;

	uint8_t disconnect_reason_code;

	struct rrr_mqtt_property_collection properties;
};
struct rrr_mqtt_p_auth {
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

static inline int rrr_mqtt_p_get_refcount (struct rrr_mqtt_p *packet) {
	int ret = 0;
	pthread_mutex_lock(&packet->refcount_lock);
	ret = packet->users;
	pthread_mutex_unlock(&packet->refcount_lock);
	return ret;
}

extern const struct rrr_mqtt_p_type_properties rrr_mqtt_p_type_properties[];
static inline const struct rrr_mqtt_p_type_properties *rrr_mqtt_p_get_type_properties (uint8_t id) {
	if (id > 15 || id == 0) {
		VL_BUG("Invalid ID in rrr_mqtt_p_get_type_properties\n");
	}
	return &rrr_mqtt_p_type_properties[id];
}

int rrr_mqtt_p_payload_set_data (
		struct rrr_mqtt_p_payload *target,
		const char *data,
		ssize_t size
);
int rrr_mqtt_p_payload_new (
		struct rrr_mqtt_p_payload **target
);
int rrr_mqtt_p_payload_new_with_allocated_payload (
		struct rrr_mqtt_p_payload **target,
		char *packet_start,
		const char *payload_start,
		ssize_t payload_size
);
static inline struct rrr_mqtt_p *rrr_mqtt_p_allocate (
		uint8_t id,
		const struct rrr_mqtt_p_protocol_version *protocol_version
) {
	const struct rrr_mqtt_p_type_properties *properties = rrr_mqtt_p_get_type_properties(id);
	return properties->allocate(rrr_mqtt_p_get_type_properties(id), protocol_version);
}

static inline struct rrr_mqtt_p *rrr_mqtt_p_clone (
		const struct rrr_mqtt_p *source
) {
	const struct rrr_mqtt_p_type_properties *properties = source->type_properties;
	if (properties->clone == NULL) {
		VL_BUG("No clone defined for packet type %s in rrr_mqtt_p_clone\n", RRR_MQTT_P_GET_TYPE_NAME(source));
	}

	return properties->clone(source);
}

uint8_t rrr_mqtt_p_translate_reason_from_v5 (uint8_t v5_reason);
uint8_t rrr_mqtt_p_translate_reason_from_v31 (uint8_t v31_reason);

#endif /* RRR_MQTT_PACKET_H */
