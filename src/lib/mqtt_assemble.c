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

#include "mqtt_assemble.h"
#include "mqtt_packet.h"
#include "mqtt_payload_buf.h"
#include "mqtt_subscription.h"
#include "../global.h"

#define BUF_INIT() 																	\
		int ret = RRR_MQTT_ASSEMBLE_OK;												\
		*size = 0;																	\
		*target = NULL;																\
		struct rrr_mqtt_payload_buf_session _session;								\
		struct rrr_mqtt_payload_buf_session *session = &_session;					\
		do {if (rrr_mqtt_payload_buf_init(session) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			return RRR_MQTT_ASSEMBLE_ERR;											\
		}} while(0)

#define PUT_RAW(data,size) do {																	\
		if (rrr_mqtt_payload_buf_put_raw (session, data, size) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			ret = RRR_MQTT_ASSEMBLE_ERR;														\
			goto out;																			\
		}} while (0)

#define PUT_U8(byte) do {					\
		uint8_t data = (byte);				\
		PUT_RAW(&data, sizeof(uint8_t));	\
		} while (0)

#define PUT_U16(byte) do {					\
		uint16_t data = htobe16(byte);		\
		PUT_RAW(&data, sizeof(uint16_t));	\
		} while (0)

#define PUT_RAW_AT_OFFSET(data,size,offset) do {		\
		if (rrr_mqtt_payload_buf_put_raw_at_offset (	\
				session,								\
				(data),									\
				(size),									\
				(offset)								\
		) != RRR_MQTT_PAYLOAD_BUF_OK) {					\
			ret = RRR_MQTT_ASSEMBLE_ERR;				\
			goto out;									\
		}} while (0)

#define PUT_U8_AT_OFFSET(byte,offset) do {						\
		uint8_t data = (byte);									\
		PUT_RAW_AT_OFFSET(&data, sizeof(uint8_t), offset);		\
		} while (0)

#define PUT_NOTHING(count) do {																\
		if (rrr_mqtt_payload_buf_ensure (session, count) != RRR_MQTT_PAYLOAD_BUF_OK) {		\
			return RRR_MQTT_ASSEMBLE_ERR;													\
		}																					\
		session->wpos += count;																\
		} while (0)

#define BUF_DESTROY_AND_RETURN(extra_ret_value)						\
		out:														\
		*size = rrr_mqtt_payload_buf_get_touched_size(session);		\
		*target = rrr_mqtt_payload_buf_extract_buffer(session);		\
		rrr_mqtt_payload_buf_destroy (session);						\
		return (ret | (extra_ret_value))

#define PUT_HEADER(rem_length) do {																\
		if (RRR_MQTT_P_IS_RESERVED_FLAGS(packet) &&												\
			RRR_MQTT_P_GET_PROP_FLAGS(packet) != RRR_MQTT_P_GET_TYPE_FLAGS(packet)				\
		) {																						\
			VL_BUG("Illegal flags %u for packet type %s in rrr_mqtt_assemble PUT_HEADER\n",		\
			RRR_MQTT_P_GET_TYPE_FLAGS(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));				\
		}																						\
		PUT_U8_AT_OFFSET(RRR_MQTT_P_GET_TYPE_AND_FLAGS(packet), 0);								\
		PUT_U8_AT_OFFSET(rem_length, 1);														\
		} while (0)

#define START_VARIABLE_LENGTH() do {											\
		PUT_NOTHING(2)

#define END_VARIABLE_LENGTH_PUT_HEADER()										\
		PUT_HEADER(rrr_mqtt_payload_buf_get_touched_size(session)-2);			\
		} while (0)

#define NO_HEADER() \
	PUT_HEADER(0)

int rrr_mqtt_assemble_connect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_connack (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_packet_connack *connack = (struct rrr_mqtt_p_packet_connack *) packet;

	BUF_INIT();

	if (RRR_MQTT_P_IS_V5(packet)) {
		START_VARIABLE_LENGTH();
		PUT_U8(connack->ack_flags);
		PUT_U8(connack->reason_v5);
		uint8_t zero = 0;
		PUT_U8(zero);

		// TODO : Replace zero byte with connack properties

		END_VARIABLE_LENGTH_PUT_HEADER();
	}
	else {
		uint8_t reason_v31 = rrr_mqtt_p_translate_reason_from_v5(connack->reason_v5);
		if (reason_v31 > 5) {
			VL_BUG("invalid v31 reason in rrr_mqtt_assemble_connack for v5 reason %u\n", connack->reason_v5);
		}
		START_VARIABLE_LENGTH();
		PUT_U8(connack->ack_flags);
		PUT_U8(reason_v31);
		END_VARIABLE_LENGTH_PUT_HEADER();
	}

	BUF_DESTROY_AND_RETURN(connack->reason_v5 != RRR_MQTT_P_5_REASON_OK ? RRR_MQTT_ASSEMBLE_DESTROY_CONNECTION : 0);
}

int rrr_mqtt_assemble_publish (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_puback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_pubrec (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_pubrel (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_pubcomp (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_subscribe (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int __rrr_mqtt_assemble_suback_callback (struct rrr_mqtt_subscription *sub, void *arg) {
	int ret = RRR_MQTT_SUBSCRIPTION_ITERATE_OK;

	struct rrr_mqtt_payload_buf_session *session = arg;
	PUT_U8(sub->qos_or_reason_v5);

	out:
	return ret;
}

int rrr_mqtt_assemble_suback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_packet_suback *suback = (struct rrr_mqtt_p_packet_suback *) packet;

	BUF_INIT();
	START_VARIABLE_LENGTH();

	PUT_U16(suback->packet_identifier);

	if (RRR_MQTT_P_IS_V5(packet)) {
		uint8_t zero = 0;
		PUT_U8(zero);

		// TODO : Replace zero byte with suback properties
	}

	ret = rrr_mqtt_subscription_collection_iterate(suback->subscriptions, __rrr_mqtt_assemble_suback_callback, session);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		VL_MSG_ERR("Error while assembling SUBACK packet in rrr_mqtt_assemble_suback\n");
		goto out;
	}

	END_VARIABLE_LENGTH_PUT_HEADER();
	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
 }

int rrr_mqtt_assemble_unsubscribe (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_unsuback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_pingreq (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	BUF_INIT();
	NO_HEADER();
	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_pingresp (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	BUF_INIT();
	NO_HEADER();
	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_OK);
}

int rrr_mqtt_assemble_disconnect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_packet_disconnect *disconnect = (struct rrr_mqtt_p_packet_disconnect *) packet;

	BUF_INIT();

	if (RRR_MQTT_P_IS_V5(packet)) {
		START_VARIABLE_LENGTH();
		PUT_U8(disconnect->disconnect_reason_code);
		uint8_t zero = 0;
		PUT_U8(zero);

		// TODO : Replace zero byte with disconnect properties

		END_VARIABLE_LENGTH_PUT_HEADER();
	}
	else {
		NO_HEADER();
	}

	BUF_DESTROY_AND_RETURN(RRR_MQTT_ASSEMBLE_DESTROY_CONNECTION);
}

int rrr_mqtt_assemble_auth (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}
