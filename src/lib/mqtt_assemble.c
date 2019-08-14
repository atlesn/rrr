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
#include "../global.h"

#define BUF_INIT() 																	\
		int ret = RRR_MQTT_ASSEMBLE_OK;												\
		*size = 0;																	\
		*target = NULL;																\
		struct rrr_mqtt_payload_buf_session session;								\
		do {if (rrr_mqtt_payload_buf_init(&session) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			return RRR_MQTT_ASSEMBLE_ERR;											\
		}} while(0)

#define PUT_RAW(data,size)	do {																\
		if (rrr_mqtt_payload_buf_put_raw (&session, data, size) != RRR_MQTT_PAYLOAD_BUF_OK) {	\
			ret = RRR_MQTT_ASSEMBLE_ERR;														\
			goto out;																			\
		}} while (0)

#define PUT_BYTE(byte) do {																		\
		uint8_t data = (byte);																	\
		if (rrr_mqtt_payload_buf_put_raw (&session, &data, 1) != RRR_MQTT_PAYLOAD_BUF_OK) {		\
			ret = RRR_MQTT_ASSEMBLE_ERR;														\
			goto out;																			\
		}} while (0)

#define PUT_NOTHING(count) do {																\
		if (rrr_mqtt_payload_buf_ensure (&session, count) != RRR_MQTT_PAYLOAD_BUF_OK) {		\
			return RRR_MQTT_ASSEMBLE_ERR;													\
		}																					\
		session.wpos += count;																\
		} while (0)

#define BUF_DESTROY_AND_RETURN()									\
		out:														\
		*size = session.wpos - session.buf;							\
		*target = rrr_mqtt_payload_buf_extract_buffer(&session);	\
		rrr_mqtt_payload_buf_destroy (&session);					\
		return ret

#define PUT_HEADER(rem_length) do {																\
		if (RRR_MQTT_P_IS_RESERVED_FLAGS(packet) &&												\
			RRR_MQTT_P_GET_PROP_FLAGS(packet) != RRR_MQTT_P_GET_TYPE_FLAGS(packet)				\
		) {																						\
			VL_BUG("Illegal flags %u for packet type %s in rrr_mqtt_assemble PUT_HEADER\n",		\
			RRR_MQTT_P_GET_TYPE_FLAGS(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));				\
		}																						\
		uint8_t _type_and_flags = RRR_MQTT_P_GET_TYPE(packet) << 4 |							\
			RRR_MQTT_P_GET_TYPE_FLAGS(packet);													\
		uint8_t _remaining_length = rem_length;													\
		PUT_RAW(&_type_and_flags, sizeof(_type_and_flags));										\
		PUT_RAW(&_remaining_length, sizeof(_remaining_length));									\
		} while (0)

#define START_VARIABLE_HEADER() do {									\
		ssize_t variable_header_start = session.wpos - session.buf;		\
		PUT_NOTHING(2)

#define END_VARIABLE_HEADER() \
		ssize_t current_wpos = session.wpos - session.buf;					\
		ssize_t remaining_length = current_wpos - variable_header_start;	\
		session.wpos = session.buf + variable_header_start;					\
		PUT_HEADER(remaining_length);										\
		session.wpos = session.buf + current_wpos;							\
		} while (0)

int rrr_mqtt_assemble_connect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_connack (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_packet_connack *connack = (struct rrr_mqtt_p_packet_connack *) packet;

	BUF_INIT();

	if (RRR_MQTT_P_IS_V5(packet)) {
		START_VARIABLE_HEADER();
		PUT_BYTE(connack->ack_flags);
		PUT_BYTE(connack->reason_v5);
		uint8_t zero = 0;
		PUT_BYTE(zero);

		// TODO : Replace zero byte with connack properties

		END_VARIABLE_HEADER();
	}
	else {
		uint8_t reason_v31 = rrr_mqtt_p_translate_reason_from_v5(connack->reason_v5);
		if (reason_v31 > 5) {
			VL_BUG("invalid v31 reason in rrr_mqtt_assemble_connack for v5 reason %u\n", connack->reason_v5);
		}
		PUT_HEADER(2);
		PUT_BYTE(connack->ack_flags);
		PUT_BYTE(reason_v31);
	}

	BUF_DESTROY_AND_RETURN();
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

int rrr_mqtt_assemble_suback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
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
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_pingresp (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}

int rrr_mqtt_assemble_disconnect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	struct rrr_mqtt_p_packet_disconnect *disconnect = (struct rrr_mqtt_p_packet_disconnect *) packet;

	BUF_INIT();

	if (RRR_MQTT_P_IS_V5(packet)) {
		START_VARIABLE_HEADER();
		PUT_BYTE(disconnect->disconnect_reason_code);
		uint8_t zero = 0;
		PUT_BYTE(zero);

		// TODO : Replace zero byte with disconnect properties

		END_VARIABLE_HEADER();
	}
	else {
		PUT_HEADER(0);
	}

	BUF_DESTROY_AND_RETURN();
}

int rrr_mqtt_assemble_auth (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION) {
	VL_MSG_ERR("Assemble function not implemented\n");
	return RRR_MQTT_ASSEMBLE_ERR;
}
