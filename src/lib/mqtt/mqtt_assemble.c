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

#include <inttypes.h>
#include <string.h>

#include "../log.h"

#include "mqtt_assemble.h"
#include "mqtt_packet.h"
#include "mqtt_payload_buf.h"
#include "mqtt_subscription.h"

#include "../util/rrr_endian.h"

#define BUF_INIT() 																	\
		int ret = RRR_MQTT_ASSEMBLE_OK;												\
		*size = 0;																	\
		*target = NULL;																\
		struct rrr_mqtt_payload_buf_session _session;								\
		struct rrr_mqtt_payload_buf_session *session = &_session;					\
		do {if (rrr_mqtt_payload_buf_init(session) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;												\
		}} while(0)

#define PUT_RAW(data,size) do {																	\
		if (rrr_mqtt_payload_buf_put_raw (session, data, size) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;												\
			goto out;																			\
		}} while (0)

#define PUT_U8(byte) do {					\
		uint8_t data = (byte);				\
		PUT_RAW(&data, sizeof(uint8_t));	\
		} while (0)

#define PUT_U16(byte) do {					\
		uint16_t data = rrr_htobe16(byte);		\
		PUT_RAW(&data, sizeof(uint16_t));	\
		} while (0)

#define PUT_U32(byte) do {					\
		uint32_t data = rrr_htobe32(byte);		\
		PUT_RAW(&data, sizeof(uint32_t));	\
		} while (0)


#define PUT_RAW_WITH_LENGTH(data,size) do {														\
		PUT_U16(size);																			\
		if (rrr_mqtt_payload_buf_put_raw (session, data, size) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;												\
			goto out;																			\
		}} while (0)

#define PUT_AND_VERIFY_RAW_WITH_LENGTH(data,size,msg) do {			\
			if ((data) == NULL) {									\
				RRR_BUG("Data was null " msg "\n");					\
			}														\
			if (*(data) == '\0' && (size) > 0) {					\
				RRR_BUG("Data was \\0 but length was > 0 " msg "\n");\
			}														\
			if ((size) > 0xffff) {									\
				RRR_BUG("Data was too long " msg "\n");				\
			}														\
			PUT_RAW_WITH_LENGTH(data,size);							\
		} while(0)

#define PUT_RAW_AT_OFFSET(data,size,offset) do {		\
		if (rrr_mqtt_payload_buf_put_raw_at_offset (	\
				session,								\
				(data),									\
				(size),									\
				(offset)								\
		) != RRR_MQTT_PAYLOAD_BUF_OK) {					\
			ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;		\
			goto out;									\
		}} while (0)

#define PUT_VARIABLE_INT(value) do {					\
		if (rrr_mqtt_payload_buf_put_variable_int(		\
				session,								\
				(value)									\
		) != RRR_MQTT_PAYLOAD_BUF_OK) {					\
			ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;		\
			goto out;									\
		}} while (0)

#define PUT_U8_AT_OFFSET(byte,offset) do {						\
		uint8_t data = (byte);									\
		PUT_RAW_AT_OFFSET(&data, sizeof(uint8_t), offset);		\
		} while (0)

#define BUF_DESTROY_AND_RETURN(extra_ret_value)						\
		goto out;													\
		out:														\
		*size = rrr_mqtt_payload_buf_get_touched_size(session);		\
		*target = rrr_mqtt_payload_buf_extract_buffer(session);		\
		rrr_mqtt_payload_buf_destroy (session);						\
		return (ret | (extra_ret_value))

static int __rrr_mqtt_assemble_put_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
) {
	int ret = RRR_MQTT_ASSEMBLE_OK;

	struct rrr_mqtt_payload_buf_session *session = arg;

	if (property->data == NULL || property->length == 0) {
		RRR_BUG("Property data and/or length was 0 in __rrr_mqtt_assemble_put_properties_callback\n");
	}

	PUT_U8(property->definition->identifier);

	switch (property->definition->internal_data_type) {
		case RRR_MQTT_PROPERTY_DATA_TYPE_ONE:
			PUT_U8(*((uint8_t *) property->data));
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_TWO:
			PUT_U16(*((uint16_t *) property->data));
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_FOUR:
			PUT_U32(*((uint32_t *) property->data));
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_VINT:
			if (*((uint32_t *) property->data) > 0xfffffff) { // <-- Seven f's
				RRR_BUG("Length of VINT field was too long in __rrr_mqtt_assemble_put_properties_callback");
			}
			PUT_VARIABLE_INT(*((uint32_t *) property->data));
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_BLOB:
			if (property->length > 0xffff) {
				RRR_BUG("Length of BLOB field was too long in __rrr_mqtt_assemble_put_properties_callback");
			}
			PUT_RAW_WITH_LENGTH(property->data, property->length);
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_UTF8:
			if (property->length > 0xffff) {
				RRR_BUG("Length of UTF8 field was too long in __rrr_mqtt_assemble_put_properties_callback");
			}
			PUT_RAW_WITH_LENGTH(property->data, property->length);
			break;
		case RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8:
			if (property->sibling == NULL || property->sibling->sibling != NULL) {
				RRR_BUG("Sibling problem of 2UTF8 property in __rrr_mqtt_assemble_put_properties_callback\n");
			}
			if (property->length > 0xffff || property->sibling->length > 0xffff) {
				RRR_BUG("Length of 2UTF8 field was too long in __rrr_mqtt_assemble_put_properties_callback");
			}
			PUT_RAW_WITH_LENGTH(property->data, property->length);
			PUT_RAW_WITH_LENGTH(property->sibling->data, property->sibling->length);
			break;
		default:
			RRR_BUG("Unknown property type %u in __rrr_mqtt_assemble_put_properties_callback\n",
					property->definition->internal_data_type);
	};

	out:
	return ret;
}

static int __rrr_mqtt_assemble_put_properties (
		struct rrr_mqtt_payload_buf_session *session,
		const struct rrr_mqtt_property_collection *properties
) {
	int ret = RRR_MQTT_ASSEMBLE_OK;

	ssize_t total_size = 0;
	ssize_t count = 0;
	if (rrr_mqtt_property_collection_calculate_size (&total_size, &count, properties) != 0) {
		RRR_MSG_0("Could not calculate size of properties in __rrr_mqtt_assemble_put_properties\n");
		ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;
		goto out;
	}

	// count becomes one byte for each property (it's ID)
	total_size += count;

	if (total_size + count > 0xfffffff) { // <-- Seven f's
		// This should be checked prior to calling assembly function
		RRR_BUG("Size of collection was too large in __rrr_mqtt_assemble_put_properties\n");
	}

	PUT_VARIABLE_INT(total_size);

	const char *begin = session->wpos;

	if (rrr_mqtt_property_collection_iterate(properties, __rrr_mqtt_assemble_put_properties_callback, session) != 0) {
		RRR_MSG_0("Error while iterating properties in __rrr_mqtt_assemble_put_properties\n");
		ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;
		goto out;
	}

	const char *end = session->wpos;

	if (end - begin != total_size) {
		RRR_BUG("Size mismatch in __rrr_mqtt_assemble_put_properties\n");
	}

	out:
	return ret;
}

#define PUT_PROPERTIES(properties) do {					\
		if (__rrr_mqtt_assemble_put_properties(			\
				session,								\
				(properties)							\
		) != RRR_MQTT_ASSEMBLE_OK) {					\
			ret = RRR_MQTT_ASSEMBLE_INTERNAL_ERR;		\
			goto out;									\
		}} while (0)

int rrr_mqtt_assemble_connect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_connect *connect = (struct rrr_mqtt_p_connect *) packet;

	BUF_INIT();

	PUT_RAW_WITH_LENGTH(connect->protocol_version->name, strlen(connect->protocol_version->name));
	PUT_U8(connect->protocol_version->id);
	PUT_U8(connect->connect_flags);
	PUT_U16(connect->keep_alive);

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_PROPERTIES(&connect->properties);
	}

	if (connect->client_identifier != NULL) {
		PUT_AND_VERIFY_RAW_WITH_LENGTH(
				connect->client_identifier,
				strlen(connect->client_identifier),
				" for client identifier in trr_mqtt_assemble_connect"
		);
	}
	else {
		PUT_U16(0);
	}

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_PROPERTIES(&connect->will_properties);
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL(connect) != 0) {
		PUT_AND_VERIFY_RAW_WITH_LENGTH(
			connect->will_topic,
			strlen(connect->will_topic),
			" for will topic in rrr_mqtt_assemble_connect"
		);
		PUT_AND_VERIFY_RAW_WITH_LENGTH(
			connect->will_message,
			strlen(connect->will_message),
			" for will message in rrr_mqtt_assemble_connect"
		);
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(connect) != 0) {
		PUT_AND_VERIFY_RAW_WITH_LENGTH(
			connect->username,
			strlen(connect->username),
			" for user name in rrr_mqtt_assemble_connect"
		);
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(connect) != 0) {
		PUT_AND_VERIFY_RAW_WITH_LENGTH(
			connect->password,
			strlen(connect->password),
			" for password in rrr_mqtt_assemble_connect"
		);
	}

	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_connack (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_connack *connack = (struct rrr_mqtt_p_connack *) packet;

	BUF_INIT();

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_U8(connack->ack_flags);
		PUT_U8(connack->reason_v5);
		PUT_PROPERTIES(&connack->properties);
	}
	else {
		uint8_t reason_v31 = rrr_mqtt_p_translate_reason_from_v5(connack->reason_v5);
		if (reason_v31 > 5) {
			RRR_BUG("invalid v31 reason in rrr_mqtt_assemble_connack for v5 reason %u\n", connack->reason_v5);
		}
		PUT_U8(connack->ack_flags);
		PUT_U8(reason_v31);
	}

	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_publish (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;

	BUF_INIT();

	PUT_RAW_WITH_LENGTH(publish->topic, strlen(publish->topic));

	// Note : The separate dup variable overrides the value in type_flags.
	RRR_MQTT_P_PUBLISH_SET_FLAG_DUP(publish, publish->dup);

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) > 0) {
		PUT_U16(publish->packet_identifier);
	}

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_PROPERTIES(&publish->properties);
	}

	// Payload is added automatically

	BUF_DESTROY_AND_RETURN(RRR_MQTT_P_5_REASON_OK);
}

// Assemble PUBACK, PUBREC, PUBREL, PUBCOMP
int rrr_mqtt_assemble_def_puback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_def_puback *puback = (struct rrr_mqtt_p_def_puback *) packet;
	BUF_INIT();

	PUT_U16(puback->packet_identifier);
	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_U8(puback->reason_v5);
		if (RRR_MQTT_P_IS_V5(packet)) {
			PUT_PROPERTIES(&puback->properties);
		}
	}
	BUF_DESTROY_AND_RETURN(RRR_MQTT_P_5_REASON_OK);
}

struct assemble_sub_usub_callback_data {
	struct rrr_mqtt_payload_buf_session *session;
	int is_v5;
	int has_topic_options; // For SUBSCRIBE packet
};

int __rrr_mqtt_assemble_sub_usub_callback (struct rrr_mqtt_subscription *sub, void *arg) {
	int ret = RRR_MQTT_SUBSCRIPTION_ITERATE_OK;

	struct assemble_sub_usub_callback_data *callback_data = arg;
	struct rrr_mqtt_payload_buf_session *session = callback_data->session;

	if (sub->nl > 0 || sub->rap > 0 || sub->retain_handling > 2 || sub->qos_or_reason_v5 > 2) {
		RRR_BUG("Invalid flags/QoS in __rrr_mqtt_assemble_subscribe_callback\n");
	}

	uint8_t flags = sub->qos_or_reason_v5;

	if (callback_data->is_v5 != 0) {
		flags |= sub->nl << 2;
		flags |= sub->rap << 3;
		flags |= sub->retain_handling << 4;
	}

	ssize_t length = strlen(sub->topic_filter);
	if (length > 0xffff) {
		RRR_BUG("Topic filter was too long in __rrr_mqtt_assemble_subscribe_callback\n");
	}

	PUT_RAW_WITH_LENGTH(sub->topic_filter,length);
	if (callback_data->has_topic_options) {
		PUT_U8(flags);
	}

	out:
	return ret;
}

static int __rrr_mqtt_assemble_sub_usub (
		RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION,
		int has_topic_options
) {
	struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) packet;

	BUF_INIT();
	PUT_U16(sub_usub->packet_identifier);

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_PROPERTIES(&sub_usub->properties);
	}

	if (rrr_mqtt_subscription_collection_count(sub_usub->subscriptions) <= 0) {
		RRR_BUG("Subscription count was <= 0 in rrr_mqtt_assemble_sub_usub\n");
	}

	struct assemble_sub_usub_callback_data callback_data = {
			session,
			RRR_MQTT_P_IS_V5(packet),
			has_topic_options
	};

	ret = rrr_mqtt_subscription_collection_iterate(
			sub_usub->subscriptions,
			__rrr_mqtt_assemble_sub_usub_callback,
			&callback_data
	);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error while assembling SUBSCRIBE packet in rrr_mqtt_assemble_sub_usub\n");
		goto out;
	}

	BUF_DESTROY_AND_RETURN(RRR_MQTT_P_5_REASON_OK);
}

int rrr_mqtt_assemble_subscribe (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	return __rrr_mqtt_assemble_sub_usub(target, size, packet, 1);
}

int rrr_mqtt_assemble_unsubscribe (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	return __rrr_mqtt_assemble_sub_usub(target, size, packet, 0);
}

struct rrr_mqtt_assemble_suback_callback_data {
	struct rrr_mqtt_payload_buf_session *session;
	int is_v5;
};

int __rrr_mqtt_assemble_suback_callback (struct rrr_mqtt_subscription *sub, void *arg) {
	int ret = RRR_MQTT_SUBSCRIPTION_ITERATE_OK;

	struct rrr_mqtt_assemble_suback_callback_data *callback_data = arg;
	struct rrr_mqtt_payload_buf_session *session = callback_data->session;

	uint8_t reason = sub->qos_or_reason_v5;

	if (!callback_data->is_v5) {
		if (reason > 2) {
			// No other reasons allowed in V3.1 for SUBACK
			reason = 0x80;
		}
	}

	PUT_U8(reason);

	out:
	return ret;
}

int rrr_mqtt_assemble_suback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) packet;

	BUF_INIT();

	PUT_U16(suback->packet_identifier);

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_PROPERTIES(&suback->properties);
	}

	if (rrr_mqtt_subscription_collection_count(suback->subscriptions_) <= 0) {
		RRR_BUG("Subscription count was <= 0 in rrr_mqtt_assemble_suback\n");
	}

	struct rrr_mqtt_assemble_suback_callback_data callback_data = { session, RRR_MQTT_P_IS_V5(packet) };

	ret = rrr_mqtt_subscription_collection_iterate(
			suback->subscriptions_,
			__rrr_mqtt_assemble_suback_callback,
			&callback_data
	);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error while assembling SUBACK packet in rrr_mqtt_assemble_suback\n");
		goto out;
	}

	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_unsuback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) packet;

	BUF_INIT();

	PUT_U16(suback->packet_identifier);

	// V3.1 has no payload
	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_PROPERTIES(&suback->properties);

		if (rrr_mqtt_subscription_collection_count(suback->subscriptions_) <= 0) {
			RRR_BUG("Subscription count was <= 0 in rrr_mqtt_assemble_suback\n");
		}

		struct rrr_mqtt_assemble_suback_callback_data callback_data = { session, RRR_MQTT_P_IS_V5(packet) };

		ret = rrr_mqtt_subscription_collection_iterate(
				suback->subscriptions_,
				__rrr_mqtt_assemble_suback_callback,
				&callback_data
		);
		if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
			RRR_MSG_0("Error while assembling SUBACK packet in rrr_mqtt_assemble_suback\n");
			goto out;
		}
	}

	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_pingreq (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	(void)(packet);
	BUF_INIT();
	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_pingresp (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	(void)(packet);
	BUF_INIT();
	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_disconnect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) packet;

	BUF_INIT();

	if (RRR_MQTT_P_IS_V5(packet)) {
		PUT_U8(disconnect->reason_v5);
		uint8_t zero = 0;
		PUT_U8(zero);

		// TODO : Replace zero byte with disconnect properties
	}
	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_auth (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	RRR_MSG_0("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_INTERNAL_ERR;
}
