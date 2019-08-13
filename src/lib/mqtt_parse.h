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

#ifndef RRR_MQTT_PARSE_H
#define RRR_MQTT_PARSE_H

#include <stdio.h>

#define RRR_MQTT_PARSE_OK				0
#define RRR_MQTT_PARSE_INTERNAL_ERROR	1
#define RRR_MQTT_PARSE_INCOMPLETE		2
#define RRR_MQTT_PARSE_PARAMETER_ERROR	3
#define RRR_MQTT_PARSE_OVERFLOW			4

#define RRR_MQTT_PARSE_STATUS_NONE					0
#define RRR_MQTT_PARSE_STATUS_FIXED_HEADER_DONE		(1<<0)
#define RRR_MQTT_PARSE_STATUS_VARIABLE_HEADER_DONE	(1<<1)
#define RRR_MQTT_PARSE_STATUS_PAYLOAD_DONE			(1<<2)
#define RRR_MQTT_PARSE_STATUS_COMPLETE				(1<<3)
#define RRR_MQTT_PARSE_STATUS_PAYLOAD_TO_PACKET	(1<<4)
#define RRR_MQTT_PARSE_STATUS_ERR					(1<<15)

#define RRR_MQTT_PARSE_FIXED_HEADER_IS_DONE(s) \
	(((s)->status & RRR_MQTT_PARSE_STATUS_FIXED_HEADER_DONE) > 0)

#define RRR_MQTT_PARSE_VARIABLE_HEADER_IS_DONE(s) \
	(((s)->status & RRR_MQTT_PARSE_STATUS_VARIABLE_HEADER_DONE) > 0)

#define RRR_MQTT_PARSE_PAYLOAD_IS_DONE(s) \
	(((s)->status & RRR_MQTT_PARSE_STATUS_PAYLOAD_DONE) > 0)

#define RRR_MQTT_PARSE_PAYLOAD_IS_MOVE_PAYLOAD_PACKET(s) \
	(((s)->status & RRR_MQTT_PARSE_STATUS_PAYLOAD_TO_PACKET) > 0)

#define RRR_MQTT_PARSE_IS_COMPLETE(s) \
	(((s)->status & RRR_MQTT_PARSE_STATUS_COMPLETE) > 0)

#define RRR_MQTT_PARSE_IS_ERR(s) \
	(((s)->status & RRR_MQTT_PARSE_STATUS_ERR) > 0)

#define RRR_MQTT_PARSE_STATUS_SET(s,f) \
	((s)->status |= (f))

#define RRR_MQTT_PARSE_STATUS_SET_ERR(s) \
	RRR_MQTT_PARSE_STATUS_SET(s,RRR_MQTT_PARSE_STATUS_ERR)

struct rrr_mqtt_p_packet;
struct rrr_mqtt_p_type_properties;
struct rrr_mqtt_p_protocol_version;

struct rrr_mqtt_p_parse_session {
	int status;
	const char *buf;

	int header_parse_attempts;
	const struct rrr_mqtt_p_type_properties *type_properties;
	const struct rrr_mqtt_p_protocol_version *protocol_version;

	struct rrr_mqtt_p_packet *packet;

	ssize_t variable_header_pos;
	ssize_t payload_pos;

	ssize_t buf_size;
	ssize_t target_size;

	uint8_t type;
	uint8_t type_flags;
};

int rrr_mqtt_parse_connect (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_connack (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_publish (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_puback (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_pubrec (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_pubrel (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_pubcomp (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_subscribe (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_suback (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_unsubscribe (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_unsuback (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_pingreq (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_pingresp (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_disconnect (struct rrr_mqtt_p_parse_session *session);
int rrr_mqtt_parse_auth (struct rrr_mqtt_p_parse_session *session);

void rrr_mqtt_parse_session_destroy (
		struct rrr_mqtt_p_parse_session *session
);
void rrr_mqtt_parse_session_init (
		struct rrr_mqtt_p_parse_session *session,
		const char *buf,
		ssize_t buf_size,
		const struct rrr_mqtt_p_protocol_version *protocol_version
);
int rrr_mqtt_packet_parse (
		struct rrr_mqtt_p_parse_session *session
);
int rrr_mqtt_packet_parse_finalize (
		struct rrr_mqtt_p_packet **packet,
		struct rrr_mqtt_p_parse_session *session
);

#endif /* RRR_MQTT_PARSE_H */
