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

#define RRR_MQTT_VERSION_3_1		3
#define RRR_MQTT_VERSION_3_1_1		4
#define RRR_MQTT_VERSION_5			5

struct rrr_mqtt_p_packet;
struct rrr_mqtt_p_parse_session;

struct rrr_mqtt_p_protocol_version {
	uint8_t id;
	const char *name;
};

struct rrr_mqtt_p_header {
	uint8_t type;
	uint8_t length[4];
} __attribute__((packed));

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

#define RRR_MQTT_P_PARSE_STATUS_NONE					0
#define RRR_MQTT_P_PARSE_STATUS_FIXED_HEADER_DONE		(1<<0)
#define RRR_MQTT_P_PARSE_STATUS_VARIABLE_HEADER_DONE	(1<<1)
#define RRR_MQTT_P_PARSE_STATUS_PAYLOAD_DONE			(1<<2)
#define RRR_MQTT_P_PARSE_STATUS_COMPLETE				(1<<3)
#define RRR_MQTT_P_PARSE_STATUS_ERR						(1<<15)

#define RRR_MQTT_P_PARSE_FIXED_HEADER_IS_DONE(s) \
	(((s)->status & RRR_MQTT_P_PARSE_STATUS_FIXED_HEADER_DONE) > 0)
#define RRR_MQTT_P_PARSE_VARIABLE_HEADER_IS_DONE(s) \
	(((s)->status & RRR_MQTT_P_PARSE_STATUS_VARIABLE_HEADER_DONE) > 0)
#define RRR_MQTT_P_PARSE_PAYLOAD_IS_DONE(s) \
	(((s)->status & RRR_MQTT_P_PARSE_STATUS_PAYLOAD_DONE) > 0)
#define RRR_MQTT_P_PARSE_IS_COMPLETE(s) \
	(((s)->status & RRR_MQTT_P_PARSE_STATUS_COMPLETE) > 0)
#define RRR_MQTT_P_PARSE_IS_ERR(s) \
	(((s)->status & RRR_MQTT_P_PARSE_STATUS_ERR) > 0)
#define RRR_MQTT_P_PARSE_STATUS_SET(s,f) \
	((s)->status |= (f))
#define RRR_MQTT_P_PARSE_STATUS_SET_ERR(s) \
	RRR_MQTT_P_PARSE_STATUS_SET(s,RRR_MQTT_P_PARSE_STATUS_ERR)

#define RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION \
		struct rrr_mqtt_p_type_properties *type_properties, \
		struct rrr_mqtt_p_protocol_version *protocol_version

#define RRR_MQTT_P_TYPE_PARSER_DEFINITION \
		struct rrr_mqtt_p_parse_session *session

#define RRR_MQTT_P_TYPE_FREE_DEFINITION \
		struct rrr_mqtt_p_packet *packet

struct rrr_mqtt_p_type_properties {
	/* If has_reserved_flags is non-zero, a packet must have the exact specified flags set to be valid */
	uint8_t type_id;
	uint8_t has_reserved_flags;
	uint8_t flags;
	ssize_t packet_size;
	struct rrr_mqtt_p_packet *(*allocate)(RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION);
	int (*parse)(RRR_MQTT_P_TYPE_PARSER_DEFINITION);
	void (*free)(RRR_MQTT_P_TYPE_FREE_DEFINITION);
};

#define RRR_MQTT_P_PACKET_HEADER								\
	int users;													\
	struct rrr_mqtt_p_packet *next;								\
	pthread_mutex_t lock;										\
	const struct rrr_mqtt_p_protocol_version *protocol_version;	\
	const struct rrr_mqtt_p_type_properties *type_properties

struct rrr_mqtt_p_packet {
	RRR_MQTT_P_PACKET_HEADER;
};

#define RRR_MQTT_P_INCREF(p)				\
	do {									\
		pthread_mutex_lock(&p->lock);		\
		p->users++;							\
		pthread_mutex_unlock(&p->lock);		\
	} while (0)

#define RRR_MQTT_P_DECREF(p)				\
	do {									\
		pthread_mutex_lock(&p->lock);		\
		--p->users;							\
		pthread_mutex_unlock(&p->lock);		\
		if (p->users == 0) {				\
			p->type_properties->free(p);	\
		}									\
	} while (0)

struct rrr_mqtt_p_packet_connect {
	RRR_MQTT_P_PACKET_HEADER;

	uint8_t connect_flags;
	uint16_t keep_alive;

	struct rrr_mqtt_p_property_collection properties;

	char *client_identifier;

	// For version 5
	struct rrr_mqtt_p_property_collection will_properties;

	char *will_topic;
	char *will_message;

	char *username;
	char *password;
};

struct rrr_mqtt_p_packet_connack {
	RRR_MQTT_P_PACKET_HEADER;
};
struct rrr_mqtt_p_packet_publish {
	RRR_MQTT_P_PACKET_HEADER;
};
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
};
struct rrr_mqtt_p_packet_auth {
	RRR_MQTT_P_PACKET_HEADER;
};

struct rrr_mqtt_p_parse_session {
	int status;
	const char *buf;

	int header_parse_attempts;
	struct rrr_mqtt_p_packet *packet;

	ssize_t variable_header_pos;
	ssize_t payload_pos;

	ssize_t buf_size;
	ssize_t target_size;

	uint8_t type;
	uint8_t type_flags;
};

struct rrr_mqtt_p_queue {
	/* Must be first */
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

#define RRR_MQTT_P_GET_TYPE(p)			(((p)->type & ((uint8_t) 0xF << 4)) >> 4)
#define RRR_MQTT_P_GET_TYPE_FLAGS(p)	((p)->type & ((uint8_t) 0xF))

#define RRR_MQTT_P_CONNECT_GET_FLAG_RESERVED(p)			((1<<0) & (p)->connect_flags)
#define RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(p)		(((1<<1) & (p)->connect_flags) >> 1)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL(p)				(((1<<2) & (p)->connect_flags) >> 2)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(p)			((((1<<4)|(1<<3)) & (p)->connect_flags) >> 3)
#define RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(p)		(((1<<5) & (p)->connect_flags) >> 5)
#define RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(p) 		(((1<<6) & (p)->connect_flags) >> 6)
#define RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(p)		(((1<<7) & (p)->connect_flags) >> 7)

void rrr_mqtt_packet_parse_session_destroy (
		struct rrr_mqtt_p_parse_session *session
);
void rrr_mqtt_packet_parse_session_init (
		struct rrr_mqtt_p_parse_session *session,
		const char *buf,
		ssize_t buf_size
);
int rrr_mqtt_packet_parse (
		struct rrr_mqtt_p_parse_session *session
);
int rrr_mqtt_packet_parse_finalize (
		struct rrr_mqtt_p_packet **packet,
		struct rrr_mqtt_p_parse_session *session
);

#endif /* RRR_MQTT_PACKET_H */
