/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MQTT_COMMON_H
#define RRR_MQTT_COMMON_H

#include <stdio.h>

#include "mqtt_connection.h"

#define RRR_MQTT_DATA_CLIENT_NAME_LENGTH 64
#define RRR_MQTT_SYNCHRONIZED_READ_STEP_MAX_SIZE 4096

struct ip_accept_data;
struct rrr_mqtt_packet_internal;
struct rrr_mqtt_data;
struct rrr_mqtt_session_collection;

#define RRR_MQTT_TYPE_HANDLER_DEFINITION \
		struct rrr_mqtt_data *mqtt_data, \
		struct rrr_mqtt_conn *connection, \
		struct rrr_mqtt_p *packet

struct rrr_mqtt_type_handler_properties {
	int (*handler)(RRR_MQTT_TYPE_HANDLER_DEFINITION);
};

struct rrr_mqtt_data {
	struct rrr_mqtt_conn_collection connections;
	char client_name[RRR_MQTT_DATA_CLIENT_NAME_LENGTH + 1];
	const struct rrr_mqtt_type_handler_properties *handler_properties;
	int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *arg);
	void *event_handler_arg;
	struct rrr_mqtt_session_collection *sessions;
	uint64_t close_wait_time_usec;
};

#define MQTT_COMMON_CALL_SESSION_HEARTBEAT(mqtt,session) \
		(mqtt)->sessions->methods->heartbeat((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_NOTIFY_DISCONNECT(mqtt,session) \
		(mqtt)->sessions->methods->notify_disconnect((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_ADD_SUBSCRIPTIONS(mqtt,session,subscriptions) \
		(mqtt)->sessions->methods->add_subscriptions((mqtt)->sessions, &(session), (subscriptions))

#define MQTT_COMMON_CALL_SESSION_RECEIVE_PUBLISH(mqtt,session,publish) \
		(mqtt)->sessions->methods->receive_publish((mqtt)->sessions, &(session), (publish))

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data);
int rrr_mqtt_common_data_init (struct rrr_mqtt_data *data,
		const char *client_name,
		const struct rrr_mqtt_type_handler_properties *handler_properties,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *arg),
		void *event_handler_arg,
		uint64_t close_wait_time_usec,
		int max_socket_connections
);
int rrr_mqtt_common_data_register_connection (
		struct rrr_mqtt_data *data,
		const struct ip_accept_data *accept_data
);
int rrr_mqtt_common_read_parse_handle (struct rrr_mqtt_data *data);

#endif /* RRR_MQTT_COMMON_H */
