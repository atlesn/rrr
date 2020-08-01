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

#include "../log.h"

#include "mqtt_assemble.h"
#include "mqtt_parse.h"
#include "mqtt_packet.h"
#include "mqtt_common.h"
#include "mqtt_topic.h"
#include "mqtt_subscription.h"

#include "../util/rrr_time.h"
#include "../util/macro_utils.h"

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

static int __rrr_mqtt_p_standarized_usercount_init (
		struct rrr_mqtt_p_standarized_usercount *head,
		void (*destroy)(void *arg)
) {
	int ret = pthread_mutex_init(&head->refcount_lock, 0);
	if (ret != 0) {
		RRR_MSG_0("Could not initialize mutex in __rrr_mqtt_p_standarized_usercount_init\n");
		return 1;
	}

	head->destroy = destroy;
	head->users = 1;

	return 0;
}

static void __rrr_mqtt_p_payload_destroy (void *arg) {
	struct rrr_mqtt_p_payload *payload = arg;
	RRR_FREE_IF_NOT_NULL(payload->packet_data);
	pthread_mutex_destroy(&payload->data_lock);
	free(payload);
}

int rrr_mqtt_p_payload_set_data (
		struct rrr_mqtt_p_payload *target,
		const char *data,
		ssize_t size
) {
	int ret = 0;

	RRR_MQTT_P_LOCK(target);
	RRR_FREE_IF_NOT_NULL(target->packet_data);

	target->packet_data = malloc(size);
	if (target->packet_data == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_p_payload_set_data\n");
		ret = 1;
		goto out_unlock;
	}

	memcpy(target->packet_data, data, size);
	target->length = size;
	target->payload_start = target->packet_data;

	out_unlock:
	RRR_MQTT_P_UNLOCK(target);

	return ret;
}

int rrr_mqtt_p_payload_new (
		struct rrr_mqtt_p_payload **target
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_p_payload *result = malloc(sizeof(*result));

	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_p_payload_new\n");
		ret = 1;
		goto out;
	}
	memset(result, '\0', sizeof(*result));

	ret = pthread_mutex_init(&result->data_lock, 0);
	if (ret != 0) {
		RRR_MSG_0("Could not initialize mutex in __rrr_mqtt_p_payload_new\n");
		ret = 1;
		goto out_free;
	}

	ret = __rrr_mqtt_p_standarized_usercount_init (
			(struct rrr_mqtt_p_standarized_usercount *) result,
			__rrr_mqtt_p_payload_destroy
	);
	if (ret != 0) {
		RRR_MSG_0("Could not initialize refcount in __rrr_mqtt_p_payload_new\n");
		ret = 1;
		goto out_destroy_mutex;
	}

	*target = result;

	goto out;
	out_destroy_mutex:
		pthread_mutex_destroy(&result->data_lock);
	out_free:
		free(result);
	out:
		return ret;
}

int rrr_mqtt_p_payload_new_with_allocated_payload (
		struct rrr_mqtt_p_payload **target,
		char *packet_start,
		const char *payload_start,
		ssize_t payload_length
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_p_payload *result = NULL;

	ret = rrr_mqtt_p_payload_new (&result);
	if (ret != 0) {
		RRR_MSG_0("Could not create payload in rrr_mqtt_p_payload_new_with_allocated_payload\n");
		ret = 1;
		goto out;
	}

	RRR_MQTT_P_LOCK(result);
	result->packet_data = packet_start;
	result->payload_start = payload_start;
	result->length = payload_length;
	RRR_MQTT_P_UNLOCK(result);

	*target = result;

	out:
	return ret;
}

static void __rrr_mqtt_p_destroy (void *arg) {
	struct rrr_mqtt_p *p = arg;
	if (p->users != 0) {
		RRR_BUG("users was not 0 in __rrr_mqtt_p_destroy\n");
	}
//	printf("Release pool ID %u: %p(%p, %p)\n",
//			p->packet_identifier, p->release_packet_id_func, p->release_packet_id_arg1, p->release_packet_id_arg2);
	RRR_MQTT_P_RELEASE_POOL_ID(p);
	RRR_FREE_IF_NOT_NULL(p->_assembled_data);
	pthread_mutex_destroy(&p->data_lock);
	RRR_MQTT_P_DECREF(p->payload);
	RRR_MQTT_P_CALL_FREE(p);
}

/* If a packet type only contains values which are to be zero-initialized, it only
 * needs this default allocator. If it contains special objects, a custom allocator must
 * be written which again calls this default allocator to initialize the header before
 * initializing other special data. */
static struct rrr_mqtt_p *__rrr_mqtt_p_allocate_raw (RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p *ret = malloc(type_properties->packet_size);
	if (ret == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_p_allocate_raw\n");
		goto out;
	}

	memset(ret, '\0', type_properties->packet_size);
	ret->type_properties = type_properties;
	ret->protocol_version = protocol_version;
	ret->create_time = rrr_time_get_64();
	ret->packet_identifier = 0;

	if (type_properties->has_reserved_flags != 0) {
		ret->type_flags = type_properties->flags;
	}

	if (pthread_mutex_init(&ret->data_lock, 0) != 0) {
		RRR_MSG_0("Could not initialize mutex in __rrr_mqtt_p_allocate_raw\n");
		goto out_free;
	}

	if (__rrr_mqtt_p_standarized_usercount_init (
			(struct rrr_mqtt_p_standarized_usercount *) ret,
			__rrr_mqtt_p_destroy
	) != 0) {
		RRR_MSG_0("Could not initialize refcount in __rrr_mqtt_p_payload_new\n");
		goto out_destroy_mutex;
	}

	goto out;
	out_destroy_mutex:
		pthread_mutex_destroy(&ret->data_lock);
	out_free:
		free(ret);
		ret = NULL;
	out:
		return ret;
}

static struct rrr_mqtt_p *rrr_mqtt_p_allocate_sub_usub(RRR_MQTT_P_TYPE_ALLOCATE_DEFINITION) {
	struct rrr_mqtt_p *result = __rrr_mqtt_p_allocate_raw (type_properties, protocol_version);
	struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) result;

	int ret = 0;

	if (result == NULL) {
		RRR_MSG_0("Could not allocate subscribe packet in rrr_mqtt_p_allocate_subscribe\n");
		goto out;
	}

	ret = rrr_mqtt_subscription_collection_new(&sub_usub->subscriptions);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not allocate subscriptions in subscribe packet in rrr_mqtt_p_allocate_subscribe\n");
		goto out_destroy_properties;
	}

	goto out;

	out_destroy_properties:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(sub_usub);

	out:
	return result;
}

static void __rrr_mqtt_p_free_connect (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_connect *connect = (struct rrr_mqtt_p_connect *) packet;

	rrr_mqtt_property_collection_destroy(&connect->properties);
	rrr_mqtt_property_collection_destroy(&connect->will_properties);

	RRR_FREE_IF_NOT_NULL(connect->client_identifier);
	RRR_FREE_IF_NOT_NULL(connect->username);
	RRR_FREE_IF_NOT_NULL(connect->password);
	RRR_FREE_IF_NOT_NULL(connect->will_topic);
	RRR_FREE_IF_NOT_NULL(connect->will_message);

	free(connect);
}

static void __rrr_mqtt_p_free_connack (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_connack *connack = (struct rrr_mqtt_p_connack *) packet;
	rrr_mqtt_property_collection_destroy(&connack->properties);
	free(connack);
}

static void __rrr_mqtt_p_free_publish (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;
	rrr_mqtt_property_collection_destroy(&publish->properties);
	rrr_mqtt_property_collection_destroy(&publish->user_properties);
	rrr_mqtt_property_collection_destroy(&publish->subscription_ids);
	rrr_mqtt_topic_token_destroy(publish->token_tree_);
	RRR_FREE_IF_NOT_NULL(publish->topic);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->qos_packets.puback);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->qos_packets.pubrec);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->qos_packets.pubrel);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->qos_packets.pubcomp);
	free(publish);
}

static void __rrr_mqtt_p_free_def_puback (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_def_puback *puback_default = (struct rrr_mqtt_p_def_puback *) packet;
	rrr_mqtt_property_collection_destroy(&puback_default->properties);
	free(packet);
}

static void __rrr_mqtt_p_free_subscribe (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) packet;
	rrr_mqtt_property_collection_destroy(&subscribe->properties);
	if (subscribe->subscriptions != NULL) {
		rrr_mqtt_subscription_collection_destroy(subscribe->subscriptions);
	}
	RRR_FREE_IF_NOT_NULL(subscribe->data_tmp);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(subscribe->suback);
	free(packet);
}

static void __rrr_mqtt_p_free_suback (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) packet;
	rrr_mqtt_property_collection_destroy(&suback->properties);
	rrr_mqtt_subscription_collection_destroy(suback->subscriptions_);
	free(packet);
}

static void __rrr_mqtt_p_free_unsubscribe (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	__rrr_mqtt_p_free_subscribe(packet);
}

static void __rrr_mqtt_p_free_unsuback (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	__rrr_mqtt_p_free_suback(packet);
}

static void __rrr_mqtt_p_free_pingreq (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_pingresp (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

static void __rrr_mqtt_p_free_disconnect (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) packet;
	rrr_mqtt_property_collection_destroy(&disconnect->properties);
	free(disconnect);
}

static void __rrr_mqtt_p_free_auth (RRR_MQTT_P_TYPE_FREE_DEFINITION) {
	free(packet);
}

const struct rrr_mqtt_p_type_properties rrr_mqtt_p_type_properties[] = {
	{0,  0, "RESERVED",		1, 0, 0,									NULL,							NULL,						NULL,                           NULL},
	{1,  0, "CONNECT",		1, 0, sizeof(struct rrr_mqtt_p_connect),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_connect,		rrr_mqtt_assemble_connect,		__rrr_mqtt_p_free_connect},
	{2,  1, "CONNACK",		1, 0, sizeof(struct rrr_mqtt_p_connack), 	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_connack,		rrr_mqtt_assemble_connack,		__rrr_mqtt_p_free_connack},
	{3,  0, "PUBLISH",		0, 0, sizeof(struct rrr_mqtt_p_publish),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_publish,		rrr_mqtt_assemble_publish,		__rrr_mqtt_p_free_publish},
	{4,  1, "PUBACK",		1, 0, sizeof(struct rrr_mqtt_p_puback),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_def_puback,	rrr_mqtt_assemble_def_puback,	__rrr_mqtt_p_free_def_puback},
	{5,  1, "PUBREC",		1, 0, sizeof(struct rrr_mqtt_p_pubrec),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_def_puback,	rrr_mqtt_assemble_def_puback,	__rrr_mqtt_p_free_def_puback},
	{6,  1, "PUBREL",		1, 2, sizeof(struct rrr_mqtt_p_pubrel),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_def_puback,	rrr_mqtt_assemble_def_puback,	__rrr_mqtt_p_free_def_puback},
	{7,  1, "PUBCOMP",		1, 0, sizeof(struct rrr_mqtt_p_pubcomp),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_def_puback,	rrr_mqtt_assemble_def_puback,	__rrr_mqtt_p_free_def_puback},
	{8,  0, "SUBSCRIBE",	1, 2, sizeof(struct rrr_mqtt_p_subscribe),	rrr_mqtt_p_allocate_sub_usub,	rrr_mqtt_parse_subscribe,	rrr_mqtt_assemble_subscribe,	__rrr_mqtt_p_free_subscribe},
	{9,  1, "SUBACK",		1, 0, sizeof(struct rrr_mqtt_p_suback),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_suback,		rrr_mqtt_assemble_suback,		__rrr_mqtt_p_free_suback},
	{10, 0, "UNSUBSCRIBE",	1, 2, sizeof(struct rrr_mqtt_p_unsubscribe),rrr_mqtt_p_allocate_sub_usub,	rrr_mqtt_parse_unsubscribe,	rrr_mqtt_assemble_unsubscribe,	__rrr_mqtt_p_free_unsubscribe},
	{11, 1, "UNSUBACK",		1, 0, sizeof(struct rrr_mqtt_p_unsuback),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_unsuback,	rrr_mqtt_assemble_unsuback,		__rrr_mqtt_p_free_unsuback},
	{12, 0, "PINGREQ",		1, 0, sizeof(struct rrr_mqtt_p_pingreq),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pingreq,		rrr_mqtt_assemble_pingreq,		__rrr_mqtt_p_free_pingreq},
	{13, 1, "PINGRESP",		1, 0, sizeof(struct rrr_mqtt_p_pingresp),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_pingresp,	rrr_mqtt_assemble_pingresp,		__rrr_mqtt_p_free_pingresp},
	{14, 0,	"DISCONNECT",	1, 0, sizeof(struct rrr_mqtt_p_disconnect),	__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_disconnect,	rrr_mqtt_assemble_disconnect,	__rrr_mqtt_p_free_disconnect},
	{15, 0,	"AUTH",			1, 0, sizeof(struct rrr_mqtt_p_auth),		__rrr_mqtt_p_allocate_raw,		rrr_mqtt_parse_auth,		rrr_mqtt_assemble_auth,			__rrr_mqtt_p_free_auth}
};

const struct rrr_mqtt_p_reason rrr_mqtt_p_reason_map[] = {
		// The six version 3.1 reasons must be first
		{ 0x00, RRR_MQTT_P_31_REASON_OK,					1, 1, 1, 1, 1, 1, "Success"},
		{ 0x84, RRR_MQTT_P_31_REASON_BAD_PROTOCOL_VERSION,	1, 0, 0, 0, 0, 0, "Refused/unsupported protocol version"},
		{ 0x85, RRR_MQTT_P_31_REASON_CLIENT_ID_REJECTED,	1, 0, 0, 0, 0, 0, "Client identifier not valid/rejected"},
		{ 0x86, RRR_MQTT_P_31_REASON_BAD_CREDENTIALS,		1, 0, 0, 0, 0, 0, "Bad user name or password"},
		{ 0x87, RRR_MQTT_P_31_REASON_NOT_AUTHORIZED,		1, 0, 1, 0, 1, 1, "Not authorized"},
		{ 0x88, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, 0, 0, 0, 0, "Server unavailable"},

		{ 0x01, RRR_MQTT_P_31_REASON_OK,					0, 0, 0, 0, 1, 0, "Success with QoS 1"},
		{ 0x02, RRR_MQTT_P_31_REASON_OK,					0, 0, 0, 0, 1, 0, "Success with QoS 2"},
		{ 0x04, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Disconnect with Will Message"},
		{ 0x10, RRR_MQTT_P_31_REASON_NA,					0, 0, 1, 0, 0, 0, "No matching subscribers"},
		{ 0x11, RRR_MQTT_P_31_REASON_NA,					0, 0, 0, 0, 0, 1, "No subscriptions existed"},

		{ 0x80, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, 1, 0, 1, 1, "Unspecified error"},
		{ 0x81, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, 0, 0, 0, 0, "Malformed packet"},
		{ 0x82, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, 0, 0, 0, 0, "Protocol error"},
		{ 0x83, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 1, 1, 0, 1, 1, "Implementation specific error"},
		{ 0x89, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 1, 0, 0, 0, 0, "Server busy"},
		{ 0x8A, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 0, 0, 0, 0, "Banned"},
		{ 0x8B, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Server shutting down"},
		{ 0x8C, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 0, 0, 0, 0, "Bad authentication method"},
		{ 0x8D, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Keep alive timeout"},
		{ 0x8E, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Session taken over"},
		{ 0x8F, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 1, 1, "Topic filter invalid"},

		{ 0x90, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 1, 0, 0, 0, "Topic Name invalid"},
		{ 0x91, RRR_MQTT_P_31_REASON_NA,					0, 0, 1, 0, 1, 1, "Packet identifier in use"},
		{ 0x92, RRR_MQTT_P_31_REASON_NA,					0, 0, 1, 1, 0, 0, "Packet identifier not found"},
		{ 0x93, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Receive maximum exceeded"},
		{ 0x94, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Topic alias invalid"},
		{ 0x95, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 0, 0, 0, 0, "Packet too large"},
		{ 0x96, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Messsage rate too large"},
		{ 0x97, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 1, 0, 1, 0, "Quota exceeded"},
		{ 0x98, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Administrative action"},
		{ 0x99, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 1, 0, 0, 0, "Payload format invalid"},
		{ 0x9A, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 0, 0, 0, 0, "Retain not supported"},
		{ 0x9B, RRR_MQTT_P_31_REASON_NO_CONNACK,			1, 0, 0, 0, 0, 0, "QoS not supported"},
		{ 0x9C, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, 0, 0, 0, 0, "Use another server"},
		{ 0x9D, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, 0, 0, 0, 0, "Server moved"},
		{ 0x9E, RRR_MQTT_P_31_REASON_NA,					0, 0, 0, 0, 1, 0, "Shared subscriptions not supported"},
		{ 0x9F, RRR_MQTT_P_31_REASON_SERVER_UNAVAILABLE,	1, 0, 0, 0, 0, 0, "Connection rate exceeded"},

		{ 0xA0, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 0, 0, "Maximum connect time"},
		{ 0xA1, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 1, 0, "Subscription Identifiers not supported"},
		{ 0xA2, RRR_MQTT_P_31_REASON_NA,					0, 1, 0, 0, 1, 0, "Wildcard Subscriptions not supported"},
		{ 0,	0,											0, 0, 0, 0, 0, 0, NULL}
};

static struct rrr_mqtt_p_publish *__rrr_mqtt_p_clone_publish_raw (
		const struct rrr_mqtt_p_publish *publish
) {
	struct rrr_mqtt_p_publish *result = (struct rrr_mqtt_p_publish *) __rrr_mqtt_p_allocate_raw (
			publish->type_properties,
			publish->protocol_version
	);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate PUBLISH packet while cloning in __rrr_mqtt_p_clone_publish\n");
		goto out_unlock_if_needed;
	}

	RRR_MQTT_P_LOCK(result);

	int ret = rrr_mqtt_property_collection_add_from_collection(&result->properties, &publish->properties);
	if (ret != 0) {
		RRR_MSG_0("Could not clone property collection in __rrr_mqtt_p_clone_publish\n");
		goto out_unlock_and_free;
	}

	if (publish->topic != NULL) {
		result->topic = malloc(strlen(publish->topic) + 1);
		if (result->topic == NULL) {
			RRR_MSG_0("Could not allocate memory for topic in __rrr_mqtt_p_clone_publish\n");
			goto out_destroy_properties;
		}
		strcpy(result->topic, publish->topic);
	}

	ret = rrr_mqtt_topic_tokens_clone(&result->token_tree_, publish->token_tree_);
	if (ret != 0) {
		RRR_MSG_0("Could not clone topic tokens in __rrr_mqtt_p_clone_publish\n");
		goto out_free_topic;
	}

	if (publish->payload != NULL) {
		RRR_MQTT_P_INCREF(publish->payload);
		result->payload = (struct rrr_mqtt_p_payload *) publish->payload;
	}

	goto out_unlock_if_needed;
	out_free_topic:
		RRR_FREE_IF_NOT_NULL(result->topic);
	out_destroy_properties:
		rrr_mqtt_property_collection_destroy(&result->properties);
	out_unlock_and_free:
		RRR_MQTT_P_UNLOCK(result);
		RRR_MQTT_P_DECREF(result);
		result = NULL;
	out_unlock_if_needed:
		if (result != NULL) {
			RRR_MQTT_P_UNLOCK(result);
		}
		return result;
}

int rrr_mqtt_p_new_publish (
		struct rrr_mqtt_p_publish **result,
		const char *topic,
		const char *data,
		uint16_t data_size,
		const struct rrr_mqtt_p_protocol_version *protocol_version
) {
	int ret = 0;

	*result = NULL;

	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBLISH, protocol_version);
	if (publish == NULL) {
		ret = 1;
		goto out;
	}

	RRR_MQTT_P_LOCK(publish);

	if (topic == NULL || *topic == '\0') {
		RRR_BUG("BUG: No topic set in rrr_mqtt_p_new_publish\n");
	}

	if (data_size > 0) {
		if (rrr_mqtt_p_payload_new(&publish->payload) != 0) {
			RRR_MSG_0("Could not create payload in rrr_mqtt_p_new_publish\n");
			ret = 1;
			goto out_free;
		}
		// Set function locks payload
		ssize_t ssize_data_size = data_size;
		if (rrr_mqtt_p_payload_set_data(publish->payload, data, ssize_data_size)) {
			RRR_MSG_0("Could not set payload data in rrr_mqtt_p_new_publish\n");
			ret = 1;
			goto out_free;
		}
	}

	if ((publish->topic = strdup(topic)) == NULL) {
		RRR_MSG_0("Could not allocate topic in rrr_mqtt_p_new_publish\n");
		ret = 1;
		goto out_free;
	}

	if (rrr_mqtt_topic_tokenize(&publish->token_tree_, publish->topic) != 0) {
		RRR_MSG_0("Could not tokenize topic in rrr_mqtt_p_new_publish\n");
		ret = 1;
		goto out_free;
	}

	*result = publish;
	// Do not set to NULL, must unlock below

	goto out;
	out_free:
		RRR_MQTT_P_UNLOCK(publish);
		RRR_MQTT_P_DECREF(publish);
	out:
		if (publish != NULL) {
			RRR_MQTT_P_UNLOCK(publish);
		}
		return ret;
}

struct rrr_mqtt_p_publish *rrr_mqtt_p_clone_publish (
		const struct rrr_mqtt_p_publish *source,
		int do_preserve_type_flags,
		int do_preserve_dup,
		int do_preserve_reason
) {
	if (RRR_MQTT_P_GET_TYPE(source) != RRR_MQTT_P_TYPE_PUBLISH) {
		RRR_BUG("BUG: Non-publish packet of type %u given to rrr_mqtt_p_clone_publish\n");
	}

	rrr_mqtt_p_bug_if_not_locked((struct rrr_mqtt_p *) source);

	struct rrr_mqtt_p_publish *result = NULL;

	if ((result = __rrr_mqtt_p_clone_publish_raw(source)) == NULL) {
		return NULL;
	}

	RRR_MQTT_P_LOCK(result);
	if (do_preserve_type_flags) {
		result->type_flags = source->type_flags;
	}
	if (do_preserve_dup) {
		result->dup = source->dup;
	}
	if (do_preserve_reason) {
		result->reason_v5 = source->reason_v5;
	}
	RRR_MQTT_P_UNLOCK(result);

	return result;
}

const struct rrr_mqtt_p_reason *rrr_mqtt_p_reason_get_v5 (uint8_t reason_v5) {
	const struct rrr_mqtt_p_reason *test;
	int i = 0;

	test = &rrr_mqtt_p_reason_map[i];

	while (test != NULL && test->description != NULL) {
		if (test->v5_reason == reason_v5) {
			return test;
		}

		test = &rrr_mqtt_p_reason_map[i++];
	}

	return NULL;
}

const struct rrr_mqtt_p_reason *rrr_mqtt_p_reason_get_v31 (uint8_t reason_v31) {
	const struct rrr_mqtt_p_reason *test;
	int i = 0;

	test = &rrr_mqtt_p_reason_map[i];

	while (test != NULL && test->v31_reason <= RRR_MQTT_P_31_REASON_MAX) {
		if (test->v31_reason == reason_v31) {
			return test;
		}

		test = &rrr_mqtt_p_reason_map[i++];
	}

	return NULL;

	return NULL;
}


uint8_t rrr_mqtt_p_translate_reason_from_v5 (uint8_t v5_reason) {
	for (int i = 0; rrr_mqtt_p_reason_map[i].description != NULL; i++) {
		const struct rrr_mqtt_p_reason *test = &rrr_mqtt_p_reason_map[i];
		if (test->v5_reason == v5_reason) {
			return test->v31_reason;
		}
	}
	RRR_BUG("Could not find v5 reason code %u in rrr_mqtt_p_translate_connect_reason\n", v5_reason);
	return 0;
}

uint8_t rrr_mqtt_p_translate_reason_from_v31 (uint8_t v31_reason) {
	if (v31_reason > RRR_MQTT_P_31_REASON_MAX) {
		RRR_BUG("Reason was above max in rrr_mqtt_p_translate_reason_from_v31 (got %u)\n", v31_reason);
	}
	for (int i = 0; rrr_mqtt_p_reason_map[i].description != NULL; i++) {
		const struct rrr_mqtt_p_reason *test = &rrr_mqtt_p_reason_map[i];
		if (test->v31_reason == v31_reason) {
			return test->v5_reason;
		}
	}
	RRR_BUG("Could not find v31 reason code %u in rrr_mqtt_p_translate_connect_reason\n", v31_reason);
	return 0;
}
