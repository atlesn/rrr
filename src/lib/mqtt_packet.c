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

struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = malloc(type_properties->packet_size);
	if (ret != NULL) {
		memset(ret, '\0', type_properties->packet_size);
		ret->type_properties = type_properties;
		ret->protocol_version = protocol_version;
		ret->users = 1;
		ret->create_time = time_get_64();
		ret->packet_identifier = 0;
		pthread_mutex_init(&ret->lock, 0);
	}
	return ret;
}

void rrr_mqtt_p_decref (void *packet) {
	RRR_MQTT_P_DECREF((struct rrr_mqtt_p_packet *) packet);
}

struct rrr_mqtt_p_packet *rrr_mqtt_p_allocate_connect (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p_packet *ret = rrr_mqtt_p_allocate (type_properties, protocol_version);
	struct rrr_mqtt_p_packet_connect *connect = (struct rrr_mqtt_p_packet_connect *) ret;

	if (ret != 0) {
		rrr_mqtt_packet_property_collection_init(&connect->properties);
		rrr_mqtt_packet_property_collection_init(&connect->will_properties);
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
	free(packet);
}

static void __rrr_mqtt_p_free_publish (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
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
	free(packet);
}

static void __rrr_mqtt_p_free_auth (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

const struct rrr_mqtt_p_type_properties rrr_mqtt_p_type_properties[] = {
	{0,  0, "RESERVED",		1, 0, 0,											NULL,				NULL,						NULL},
	{1,  0, "CONNECT",		1, 0, sizeof(struct rrr_mqtt_p_packet_connect),		rrr_mqtt_p_allocate, rrr_mqtt_parse_connect,	__rrr_mqtt_p_free_connect},
	{2,  1, "CONNACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_connack), 	rrr_mqtt_p_allocate, rrr_mqtt_parse_connack,	__rrr_mqtt_p_free_connack},
	{3,  0, "PUBLISH",		0, 0, sizeof(struct rrr_mqtt_p_packet_publish),		rrr_mqtt_p_allocate, rrr_mqtt_parse_publish,	__rrr_mqtt_p_free_publish},
	{4,  3, "PUBACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_puback),		rrr_mqtt_p_allocate, rrr_mqtt_parse_puback,		__rrr_mqtt_p_free_puback},
	{5,  3, "PUBREC",		1, 0, sizeof(struct rrr_mqtt_p_packet_pubrec),		rrr_mqtt_p_allocate, rrr_mqtt_parse_pubrec,		__rrr_mqtt_p_free_pubrec},
	{6,  5, "PUBREL",		1, 2, sizeof(struct rrr_mqtt_p_packet_pubrel),		rrr_mqtt_p_allocate, rrr_mqtt_parse_pubrel,		__rrr_mqtt_p_free_pubrel},
	{7,  7, "PUBCOMP",		1, 0, sizeof(struct rrr_mqtt_p_packet_pubcomp),		rrr_mqtt_p_allocate, rrr_mqtt_parse_pubcomp,	__rrr_mqtt_p_free_pubcomp},
	{8,  0, "SUBSCRIBE",	1, 2, sizeof(struct rrr_mqtt_p_packet_subscribe),	rrr_mqtt_p_allocate, rrr_mqtt_parse_subscribe,	__rrr_mqtt_p_free_subscribe},
	{9,  8, "SUBACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_suback),		rrr_mqtt_p_allocate, rrr_mqtt_parse_suback,		__rrr_mqtt_p_free_suback},
	{10, 0, "UNSUBSCRIBE",	1, 2, sizeof(struct rrr_mqtt_p_packet_unsubscribe),	rrr_mqtt_p_allocate, rrr_mqtt_parse_unsubscribe,__rrr_mqtt_p_free_unsubscribe},
	{11, 10,"UNSUBACK",		1, 0, sizeof(struct rrr_mqtt_p_packet_unsuback),	rrr_mqtt_p_allocate, rrr_mqtt_parse_unsuback,	__rrr_mqtt_p_free_unsuback},
	{12, 0, "PINGREQ",		1, 0, sizeof(struct rrr_mqtt_p_packet_pingreq),		rrr_mqtt_p_allocate, rrr_mqtt_parse_pingreq,	__rrr_mqtt_p_free_pingreq},
	{13, 12,"PINGRESP",		1, 0, sizeof(struct rrr_mqtt_p_packet_pingresp),	rrr_mqtt_p_allocate, rrr_mqtt_parse_pingresp,	__rrr_mqtt_p_free_pingresp},
	{14, 0,	"DISCONNECT",	1, 0, sizeof(struct rrr_mqtt_p_packet_disconnect),	rrr_mqtt_p_allocate, rrr_mqtt_parse_disconnect,	__rrr_mqtt_p_free_disconnect},
	{15, 0,	"AUTH",			1, 0, sizeof(struct rrr_mqtt_p_packet_auth),		rrr_mqtt_p_allocate, rrr_mqtt_parse_auth,		__rrr_mqtt_p_free_auth}
};

const struct rrr_mqtt_p_type_properties *rrr_mqtt_p_get_type_properties (uint8_t id) {
	if (id > 15 || id == 0) {
		VL_BUG("Invalid ID in rrr_mqtt_p_get_type_properties\n");
	}
	return &rrr_mqtt_p_type_properties[id];
}
