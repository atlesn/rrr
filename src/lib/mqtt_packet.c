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

#include <stdint.h>
#include <string.h>

#include "mqtt_assemble.h"
#include "mqtt_parse.h"
#include "mqtt_packet.h"
#include "mqtt_common.h"
#include "vl_time.h"

static const struct rrr_mqtt_p_protocol_version protocol_versions[] = {
		{RRR_MQTT_VERSION_3_1, "MQISDP"},
		{RRR_MQTT_VERSION_3_1_1, "MQTT"},
		{RRR_MQTT_VERSION_5, "MQTT"},
		{0, NULL}
};

const struct rrr_mqtt_p_protocol_version *rrr_mqtt_p_get_protocol_version (uint8_t id) {
	for (int i = 0; protocol_versions[i].name != NULL; i++) {
		if (protocol_versions[i].id == id) {
			return &protocol_versions[i];
		}
	}

	return NULL;
}

/* If a packet type only contains values which are to be zero-initialized, it only
 * needs this default allocator. If it contains special objects, a custom allocator must
 * be written which again calls this default allocator to initialize the header before
 * initializing other special data. */
static struct rrr_mqtt_p_packet *__rrr_mqtt_p_allocate_raw (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = malloc(type_properties->packet_size);
	if (ret != NULL) {
		memset(ret, '\0', type_properties->packet_size);
		ret->type_properties = type_properties;
		ret->protocol_version = protocol_version;
		ret->users = 1;
		ret->create_time = time_get_64();
		ret->packet_identifier = 0;
		pthread_mutex_init(&ret->data_lock, 0);
		pthread_mutex_init(&ret->refcount_lock, 0);
	}
	return ret;
}

static struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate_connect (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = __rrr_mqtt_p_allocate_raw (type_properties, protocol_version);
	struct rrr_mqtt_p_packet_connect *connect = (struct rrr_mqtt_p_packet_connect *) ret;

	if (ret != NULL) {
		rrr_mqtt_packet_property_collection_init(&connect->properties);
		rrr_mqtt_packet_property_collection_init(&connect->will_properties);
	}

	return ret;
}

static struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate_connack (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = __rrr_mqtt_p_allocate_raw (type_properties, protocol_version);
	struct rrr_mqtt_p_packet_connack *connack = (struct rrr_mqtt_p_packet_connack *) ret;

	if (ret != NULL) {
		rrr_mqtt_packet_property_collection_init(&connack->properties);
	}

	return ret;
}

static struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate_disconnect (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = __rrr_mqtt_p_allocate_raw (type_properties, protocol_version);
	struct rrr_mqtt_p_packet_disconnect *disconnect = (struct rrr_mqtt_p_packet_disconnect *) ret;

	if (ret != NULL) {
		rrr_mqtt_packet_property_collection_init(&disconnect->properties);
	}

	return ret;
}

static struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate_publish (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = __rrr_mqtt_p_allocate_raw (type_properties, protocol_version);
	struct rrr_mqtt_p_packet_publish *publish = (struct rrr_mqtt_p_packet_publish *) ret;

	if (ret != NULL) {
		rrr_mqtt_packet_property_collection_init(&publish->properties);
	}

	return ret;
}

static void __rrr_mqtt_p_free_connect (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_packet_connect *connect = (struct rrr_mqtt_p_packet_connect *) packet;

	rrr_mqtt_packet_property_collection_destroy(&connect->properties);
	rrr_mqtt_packet_property_collection_destroy(&connect->will_properties);

	RRR_FREE_IF_NOT_NULL(connect->client_identifier);
	RRR_FREE_IF_NOT_NULL(connect->username);
	RRR_FREE_IF_NOT_NULL(connect->password);
	RRR_FREE_IF_NOT_NULL(connect->will_topic);
	RRR_FREE_IF_NOT_NULL(connect->will_message);

	free(connect);
}

static void __rrr_mqtt_p_free_connack (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_packet_connack *connack = (struct rrr_mqtt_p_packet_connack *) packet;
	rrr_mqtt_packet_property_collection_destroy(&connack->properties);
	free(connack);
}

static void __rrr_mqtt_p_free_publish (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_packet_publish *publish = (struct rrr_mqtt_p_packet_publish *) packet;
	rrr_mqtt_packet_property_collection_destroy(&publish->properties);
	RRR_FREE_IF_NOT_NULL(publish->topic);
	free(publish);
}

static void __rrr_mqtt_p_free_puback (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_pubrec (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_pubrel (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_pubcomp (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_subscribe (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_suback (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_unsubscribe (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_unsuback (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_pingreq (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_pingresp (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_disconnect (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_packet_disconnect *disconnect = (struct rrr_mqtt_p_packet_disconnect *) packet;
	rrr_mqtt_packet_property_collection_destroy(&disconnect->properties);
	free(disconnect);
}

static void __rrr_mqtt_p_free_auth (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

const struct rrr_mqtt_p_type_properties rrr_mqtt_p_type_properties[] = {
	{0,  0, "RESERVED",		1, 0, 0,											NULL,							NULL,						NULL,							NULL},
	{1,  0, "CONNECT",		1, 0, sizeof(struct rrr_mqtt_p_packet_connect),		rrr_mqtt_p_allocate_connect,	rrr_mqtt_parse_connect,		rrr_mqtt_assemble_connect,		__rrr_mqtt_p_free_connect},
	{2,  1, "CONNACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_connack), 	rrr_mqtt_p_allocate_connack,	rrr_mqtt_parse_connack,		rrr_mqtt_assemble_connack,		__rrr_mqtt_p_free_connack},
	{3,  0, "PUBLISH",		0, 0, sizeof(struct rrr_mqtt_p_packet_publish),		rrr_mqtt_p_allocate_publish,	rrr_mqtt_parse_publish,		rrr_mqtt_assemble_publish,		__rrr_mqtt_p_free_publish},
	{4,  3, "PUBACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_puback),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_puback,		rrr_mqtt_assemble_puback,		__rrr_mqtt_p_free_puback},
	{5,  3, "PUBREC",		1, 0, sizeof(struct rrr_mqtt_p_packet_pubrec),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pubrec,		rrr_mqtt_assemble_pubrec,		__rrr_mqtt_p_free_pubrec},
	{6,  5, "PUBREL",		1, 2, sizeof(struct rrr_mqtt_p_packet_pubrel),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pubrel,		rrr_mqtt_assemble_pubrel,		__rrr_mqtt_p_free_pubrel},
	{7,  7, "PUBCOMP",		1, 0, sizeof(struct rrr_mqtt_p_packet_pubcomp),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pubcomp,		rrr_mqtt_assemble_pubcomp,		__rrr_mqtt_p_free_pubcomp},
	{8,  0, "SUBSCRIBE",	1, 2, sizeof(struct rrr_mqtt_p_packet_subscribe),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_subscribe,	rrr_mqtt_assemble_subscribe,	__rrr_mqtt_p_free_subscribe},
	{9,  8, "SUBACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_suback),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_suback,		rrr_mqtt_assemble_suback,		__rrr_mqtt_p_free_suback},
	{10, 0, "UNSUBSCRIBE",	1, 2, sizeof(struct rrr_mqtt_p_packet_unsubscribe),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_unsubscribe,	rrr_mqtt_assemble_unsubscribe,	__rrr_mqtt_p_free_unsubscribe},
	{11, 10,"UNSUBACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_unsuback),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_unsuback,	rrr_mqtt_assemble_unsuback,		__rrr_mqtt_p_free_unsuback},
	{12, 0, "PINGREQ",		1, 0, sizeof(struct rrr_mqtt_p_packet_pingreq),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pingreq,		rrr_mqtt_assemble_pingreq,		__rrr_mqtt_p_free_pingreq},
	{13, 12,"PINGRESP",		1, 0, sizeof(struct rrr_mqtt_p_packet_pingresp),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pingresp,	rrr_mqtt_assemble_pingresp,		__rrr_mqtt_p_free_pingresp},
	{14, 0,	"DISCONNECT",	1, 0, sizeof(struct rrr_mqtt_p_packet_disconnect),	rrr_mqtt_p_allocate_disconnect,	rrr_mqtt_parse_disconnect,	rrr_mqtt_assemble_disconnect,	__rrr_mqtt_p_free_disconnect},
	{15, 0,	"AUTH",			1, 0, sizeof(struct rrr_mqtt_p_packet_auth),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_auth,		rrr_mqtt_assemble_auth,			__rrr_mqtt_p_free_auth}
};

struct rrr_mqtt_p_reason {
	uint8_t v5_reason;
	uint8_t v31_reason;
	uint8_t for_connack;
	uint8_t for_disconnect;
	const char *description;
};

const struct rrr_mqtt_p_reason rrr_mqtt_p_reason_map[] = {
		// The six version 3.1 reasons must be first
		{ 0x00, RRR_MQTT_P_31_REASON_OK,					1, 1, "Success"},
		{ 0x84, RRR_MQTT_P_31_REASON_BAD_PROTOCOL_VERSION,	1, 0, "Refused/unsupported protocol version"},
		{ 0x85, RRR_MQTT_P_31_REASON_CLIENT_ID_REJECTED,	1, 0, "Client identifier not valid/rejected"},
		{ 0x86, RRR_MQTT_P_31_REASON_BAD_CREDENTIALS,		1, 0, "Bad user name or password"},
		{ 0x87, RRR_MQTT_P_31_REASON_NOT_AUTHORIZED,		1, 0, "Not authorized"},
		{ 0x88, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, "Server unavailable"},

		{ 0x04, RRR_MQTT_P_31_REASON_NA,					0, 1, "Disconnect with Will Message"},
		{ 0x80, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, "Unspecified error"},
		{ 0x81, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, "Malformed packet"},
		{ 0x82, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, "Protocol error"},
		{ 0x83, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, "Implementation specific error"},

		{ 0x89, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 1, "Server busy"},
		{ 0x8A, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Banned"},
		{ 0x8B, RRR_MQTT_P_31_REASON_NA,					0, 1, "Server shutting down"},
		{ 0x8C, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Bad authentication method"},
		{ 0x8D, RRR_MQTT_P_31_REASON_NA,					0, 1, "Keep alive timeout"},

		{ 0x8E, RRR_MQTT_P_31_REASON_NA,					0, 1, "Session taken over"},
		{ 0x8F, RRR_MQTT_P_31_REASON_NA,					0, 1, "Topic filter invalid"},
		{ 0x90, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Topic Name invalid"},
		{ 0x93, RRR_MQTT_P_31_REASON_NA,					0, 1, "Receive maximum exceeded"},
		{ 0x94, RRR_MQTT_P_31_REASON_NA,					0, 1, "Topic alias invalid"},

		{ 0x95, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Packet too large"},
		{ 0x96, RRR_MQTT_P_31_REASON_NA,					0, 1, "Messsage rate too large"},
		{ 0x97, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Quota exceeded"},
		{ 0x98, RRR_MQTT_P_31_REASON_NA,					0, 1, "Administrative action"},
		{ 0x99, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Payload format invalid"},

		{ 0x9A, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "Retain not supported"},
		{ 0x9B, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, "QoS not supported"},
		{ 0x9C, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, "Use another server"},
		{ 0x9D, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, "Server moved"},
		{ 0x9F, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, "Connection rate exceeded"},

		{ 0xA0, RRR_MQTT_P_31_REASON_NA,					0, 1, "Maximum connect time"},
		{ 0xA1, RRR_MQTT_P_31_REASON_NA,					0, 1, "Subscription Identifiers not supported"},
		{ 0xA2, RRR_MQTT_P_31_REASON_NA,					0, 1, "Wildcard Subscriptions not supported"},
		{ 0,	0,											0, 0, NULL}
};

uint8_t rrr_mqtt_p_translate_reason_from_v5 (uint8_t v5_reason) {
	for (int i = 0; rrr_mqtt_p_reason_map[i].description != NULL; i++) {
		const struct rrr_mqtt_p_reason *test = &rrr_mqtt_p_reason_map[i];
		if (test->v5_reason == v5_reason) {
			return test->v31_reason;
		}
	}
	VL_BUG("Could not find v5 reason code %u in rrr_mqtt_p_translate_connect_reason\n", v5_reason);
	return 0;
}

uint8_t rrr_mqtt_p_translate_reason_from_v31 (uint8_t v31_reason) {
	if (v31_reason > RRR_MQTT_P_31_REASON_MAX) {
		VL_BUG("Reason was above max in rrr_mqtt_p_translate_reason_from_v31 (got %u)\n", v31_reason);
	}
	for (int i = 0; rrr_mqtt_p_reason_map[i].description != NULL; i++) {
		const struct rrr_mqtt_p_reason *test = &rrr_mqtt_p_reason_map[i];
		if (test->v31_reason == v31_reason) {
			return test->v5_reason;
		}
	}
	VL_BUG("Could not find v31 reason code %u in rrr_mqtt_p_translate_connect_reason\n", v31_reason);
	return 0;
}
