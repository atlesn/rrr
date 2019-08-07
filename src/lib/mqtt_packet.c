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

#include "mqtt_packet.h"
#include "mqtt_common.h"

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

#define RRR_MQTT_P_GET_TYPE_NAME(p)	\
	(rrr_mqtt_packet_type_names[RRR_MQTT_P_GET_TYPE(p)])

#define RRR_MQTT_P_GET_TYPE_NAME_RAW(t)	\
	(rrr_mqtt_packet_type_names[(t)])

void rrr_mqtt_packet_parse_session_destroy (
		struct rrr_mqtt_p_parse_session *session
) {
	if (session->buf == NULL) {
		return;
	}

	memset(session, '\0', sizeof(*session));
}

void rrr_mqtt_packet_parse_session_init (
		struct rrr_mqtt_p_parse_session *session,
		const char *buf,
		ssize_t buf_size,
		const struct rrr_mqtt_p_type_properties *type_properties
) {
	if (session->buf != NULL) {
		VL_BUG("rrr_mqtt_packet_parse_session_init called with non-NULL buf\n");
	}

	memset(session, '\0', sizeof(*session));

	session->buf = buf;
	session->buf_size = buf_size;
	session->type_properties = type_properties;
}

#define RRR_MQTT_PACKET_PARSE_OK 0
#define RRR_MQTT_PACKET_PARSE_OVERFLOW 1
#define RRR_MQTT_PACKET_PARSE_INCOMPLETE 2

static int rrr_mqtt_p_parser_connect (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_connack (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_publish (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_puback (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pubrec (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pubrel (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pubcomp (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_subscribe (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_suback (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_unsubscribe (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_unsuback (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pingreq (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pingresp (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_disconnect (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_auth (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}

static const struct rrr_mqtt_p_type_parser_properties  parser_properties[] = {
	{1, 0, NULL},
	{1, 0, rrr_mqtt_p_parser_connect},
	{1, 0, rrr_mqtt_p_parser_connack},
	{0, 0, rrr_mqtt_p_parser_publish},
	{1, 0, rrr_mqtt_p_parser_puback},
	{1, 0, rrr_mqtt_p_parser_pubrec},
	{1, 2, rrr_mqtt_p_parser_pubrel},
	{1, 0, rrr_mqtt_p_parser_pubcomp},
	{1, 2, rrr_mqtt_p_parser_subscribe},
	{1, 0, rrr_mqtt_p_parser_suback},
	{1, 2, rrr_mqtt_p_parser_unsubscribe},
	{1, 0, rrr_mqtt_p_parser_unsuback},
	{1, 0, rrr_mqtt_p_parser_pingreq},
	{1, 0, rrr_mqtt_p_parser_pingresp},
	{1, 0, rrr_mqtt_p_parser_disconnect},
	{1, 0, rrr_mqtt_p_parser_auth}
};

int __rrr_mqtt_packet_parse_variable_int (uint32_t *target, ssize_t *bytes_parsed, const void *buf, ssize_t len) {
	ssize_t pos = 0;
	uint32_t result = 0;
	uint32_t exponent = 1;
	uint8_t carry = 1;

	*target = 0;
	*bytes_parsed = 0;

	if (len == 0) {
		VL_BUG("__rrr_mqtt_packet_parse_variable_int called with zero length");
	}

	while (carry) {
		if (pos == len) {
			/* Could not finish the value, input too short */
			return RRR_MQTT_PACKET_PARSE_INCOMPLETE;
		}
		if (pos > 3) {
			/* Only four bytes allowed */
			return RRR_MQTT_PACKET_PARSE_OVERFLOW;
		}

		uint8_t current = *((uint8_t *) (buf + pos));
		uint8_t value = current & 0x7f;
		carry = current & 0x80;

		result += (value * exponent);

		exponent *= 128;
	}

	*target = result;
	*bytes_parsed = pos;

	return RRR_MQTT_PACKET_PARSE_OK;
}

int rrr_mqtt_packet_parse (
		struct rrr_mqtt_p_parse_session *session
) {
	int ret = 0;

	if (session->buf == NULL) {
		VL_BUG("buf was NULL in rrr_mqtt_packet_parse\n");
	}

	if (RRR_MQTT_P_PARSE_IS_ERR(session)) {
		VL_BUG("rrr_mqtt_packet_parse called with error flag set, connection should have been closed.\n");
	}

	if (session->buf_size < 2) {
		goto out;
	}

	if (!RRR_MQTT_P_PARSE_FIXED_HEADER_IS_DONE(session)) {
		const struct rrr_mqtt_p_header *header = (const struct rrr_mqtt_p_header *) session->buf;

		if (RRR_MQTT_P_GET_TYPE(header) == 0) {
			VL_MSG_ERR("Received 0 header type in rrr_mqtt_packet_parse\n");
			ret = 1;
			goto out;
		}

		const struct rrr_mqtt_p_type_parser_properties *properties = &parser_properties[header->type];

		if (properties->has_reserved_flags != 0 && RRR_MQTT_P_GET_TYPE_FLAGS(header) != properties->flags) {
			VL_MSG_ERR("Invalid reserved flags %u received in mqtt packet of type %s\n",
					RRR_MQTT_P_GET_TYPE_FLAGS(header),
					RRR_MQTT_P_GET_TYPE_NAME(header)
			);
			ret = 1;
			goto out;
		}

		if ((ret = properties->parser(session)) != 0) {
			VL_MSG_ERR("Error while parsing mqtt packet of type %s\n", RRR_MQTT_P_GET_TYPE_NAME(header));
			ret = 1;
			goto out;
		}

		uint32_t remaining_length = 0;
		ssize_t bytes_parsed = 0;
		if ((ret = __rrr_mqtt_packet_parse_variable_int (
				&remaining_length,
				&bytes_parsed,
				header->length,
				session->buf_size - sizeof(header->type))
		) != 0) {
			if (ret == RRR_MQTT_PACKET_PARSE_INCOMPLETE) {
				/* Not enough bytes were read */
				ret = 0;
				goto out;
			}
			else {
				VL_MSG_ERR("Parse error in packet fixed header remaining length of type %s\n",
						RRR_MQTT_P_GET_TYPE_NAME(header));
				ret = 1;
				goto out;
			}
		}

		session->variable_header_pos = sizeof(header->type) + bytes_parsed;
		session->target_size = sizeof(header->type) + bytes_parsed + remaining_length;
		session->type = RRR_MQTT_P_GET_TYPE(header);
		session->type_flags = RRR_MQTT_P_GET_TYPE_FLAGS(header);

		printf ("parsed a packet fixed header of type %s\n",
				RRR_MQTT_P_GET_TYPE_NAME(header));

		RRR_MQTT_P_PARSE_STATUS_SET(session,RRR_MQTT_P_PARSE_STATUS_FIXED_HEADER_DONE);
	}

	if ((ret = parser_properties[session->type].parser(session)) != RRR_MQTT_PACKET_PARSE_OK) {
		if (ret == RRR_MQTT_PACKET_PARSE_INCOMPLETE) {
			/* Not enough bytes were read */
			ret = 0;
			goto out;
		}
		else {
			VL_MSG_ERR("Error from mqtt parse function of type %s\n",
					RRR_MQTT_P_GET_TYPE_NAME_RAW(session->type));
			ret = 1;
			goto out;
		}
	}

	out:
	if (ret != 0) {
		RRR_MQTT_P_PARSE_STATUS_SET(session,RRR_MQTT_P_PARSE_STATUS_ERR);
	}
	return ret;
}

int rrr_mqtt_packet_parse_finalize (
		struct rrr_mqtt_packet_internal **packet,
		struct rrr_mqtt_p_parse_session *session
) {
	int ret = 0;

	*packet = NULL;

	// TODO : Finalize packet

	rrr_mqtt_packet_parse_session_destroy(session);

	return ret;
}
