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
#include "mqtt_session.h"

#define RRR_MQTT_DATA_CLIENT_NAME_LENGTH 64
#define RRR_MQTT_SYNCHRONIZED_READ_STEP_MAX_SIZE 4096

struct ip_accept_data;
struct rrr_mqtt_data;
struct rrr_mqtt_p_publish;

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
	int (*event_handler)(
			struct rrr_mqtt_conn *connection,
			int event,
			void *static_arg,
			void *arg
	);
	void *event_handler_static_arg;
	struct rrr_mqtt_session_collection *sessions;
	uint64_t close_wait_time_usec;
};

struct rrr_mqtt_send_from_sessions_callback_data {
	struct rrr_mqtt_conn *connection;
};

#define MQTT_COMMON_CALL_SESSION_HEARTBEAT(mqtt,session) \
		(mqtt)->sessions->methods->heartbeat((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_NOTIFY_DISCONNECT(mqtt,session) \
		(mqtt)->sessions->methods->notify_disconnect((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_ADD_SUBSCRIPTIONS(mqtt,session,subscriptions) \
		(mqtt)->sessions->methods->add_subscriptions((mqtt)->sessions, &(session), (subscriptions))

#define MQTT_COMMON_CALL_SESSION_RECEIVE_PUBLISH(mqtt,session,publish) \
		(mqtt)->sessions->methods->receive_publish((mqtt)->sessions, &(session), (publish))

#define MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD	\
	const struct rrr_mqtt_property_collection *source;		\
	uint8_t reason_v5

struct rrr_mqtt_common_parse_properties_data {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
};

struct rrr_mqtt_common_parse_properties_data_connect {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_session_properties session_properties;
};

struct rrr_mqtt_common_parse_properties_data_publish {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_p_publish *publish;
};

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data);
int rrr_mqtt_common_data_init (struct rrr_mqtt_data *data,
		const char *client_name,
		const struct rrr_mqtt_type_handler_properties *handler_properties,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_arg,
		uint64_t close_wait_time_usec,
		int max_socket_connections
);
int rrr_mqtt_common_data_register_connection (
		struct rrr_mqtt_data *data,
		const struct ip_accept_data *accept_data
);

int rrr_mqtt_common_handler_connect_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
);
int rrr_mqtt_common_handler_publish_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
);
int rrr_mqtt_common_handle_properties (
		const struct rrr_mqtt_property_collection *source,
		int (*callback)(const struct rrr_mqtt_property *property, void *arg),
		struct rrr_mqtt_common_parse_properties_data *callback_data,
		uint8_t *reason_v5
);

#define RRR_MQTT_COMMON_HANDLE_PROPERTIES(target,callback,action_on_error)							\
	do {if ((ret = rrr_mqtt_common_handle_properties (												\
			(target),																				\
			callback,																				\
			(struct rrr_mqtt_common_parse_properties_data*) &callback_data,							\
			&reason_v5																				\
	)) != 0) {																						\
		if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0) {												\
			VL_MSG_ERR("Soft error while iterating %s source_properties\n",							\
					RRR_MQTT_P_GET_TYPE_NAME(packet));												\
			ret = ret & ~(RRR_MQTT_CONN_SOFT_ERROR);												\
		}																							\
		if (ret != 0) {																				\
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;														\
			VL_MSG_ERR("Internal error while iterating %s source_properties, return was %i\n",		\
					RRR_MQTT_P_GET_TYPE_NAME(packet), ret);											\
			goto out;																				\
		}																							\
																									\
		ret = RRR_MQTT_CONN_SOFT_ERROR;																\
		action_on_error;																			\
	}} while(0)

int rrr_mqtt_common_handle_publish (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_puback_pubcomp (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_pubrec (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_pubrel (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION);

int rrr_mqtt_common_send_from_sessions_callback (struct rrr_mqtt_p *packet, void *arg);
int rrr_mqtt_common_read_parse_handle (struct rrr_mqtt_data *data);

#endif /* RRR_MQTT_COMMON_H */
