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
#include <stdlib.h>

#include "mqtt_client.h"
#include "mqtt_common.h"

const struct rrr_mqtt_session_properties default_session_properties = {
		session_expiry:					RRR_MQTT_CLIENT_SESSION_EXPIRY,
		receive_maximum:				0,
		maximum_packet_size:			0,
		topic_alias_maximum:			0,
		request_response_information:	0,
		request_problem_information:	0,
		{0},
		NULL,
		NULL
};

int rrr_mqtt_client_connect (
		struct rrr_mqtt_common_remote_handle *result_handle,
		struct rrr_mqtt_client_data *data,
		const char *server,
		uint16_t port,
		uint8_t version,
		uint16_t keep_alive,
		uint8_t clean_start
) {
	int ret = 0;

	struct rrr_mqtt_data *mqtt_data = &data->mqtt_data;

	struct ip_accept_data *accept_data = NULL;
	struct rrr_mqtt_p_connect *connect = NULL;
	struct rrr_mqtt_session *session = NULL;

	// Sleep a bit in case server runs in the same RRR program
	usleep(500000); // 500ms

	if (ip_network_connect_tcp_ipv4_or_ipv6 (&accept_data, port, server) != 0) {
		VL_MSG_ERR("Could not connect to mqtt server '%s'\n", server);
		ret = 1;
		goto out_nolock;
	}

	if (rrr_mqtt_common_register_connection(result_handle, &data->mqtt_data, accept_data) != 0) {
		VL_MSG_ERR("Could not register connection to mqtt server %s\n", server);
		ret = 1;
		goto out_nolock;
	}

	const struct rrr_mqtt_p_protocol_version *protocol_version = rrr_mqtt_p_get_protocol_version(version);
	if (protocol_version == NULL) {
		VL_BUG("Invalid protocol version %u in rrr_mqtt_client_connect\n", version);
	}

	connect = (struct rrr_mqtt_p_connect *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_CONNECT, protocol_version);
	RRR_MQTT_P_LOCK(connect);

	connect->client_identifier = malloc(strlen(data->mqtt_data.client_name) + 1);
	if (connect->client_identifier == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_client_connect\n");
		ret = 1;
		goto out;
	}
	strcpy(connect->client_identifier, data->mqtt_data.client_name);

	connect->keep_alive = keep_alive;
	// Clean start
	connect->connect_flags |= (clean_start != 0)<<1;
	// Will QoS
	// connect->connect_flags |= 2 << 3;

	// TODO : Set connect properties

	struct rrr_mqtt_session_properties session_properties = default_session_properties;

	if (version >= 5) {
		// Default for version 3.1 is that sessions do not expire,
		// only use clean session to control this
		session_properties.session_expiry = 0xffffffff;

		ret |= rrr_mqtt_property_collection_add_uint32 (
				&connect->properties,
				RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL,
				session_properties.session_expiry
		);
	}

	struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
			&connect->properties,
			RRR_MQTT_P_5_REASON_OK,
			session_properties
	};

	uint8_t reason_v5 = 0;
	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&connect->properties,
			connect,
			rrr_mqtt_common_handler_connect_handle_properties_callback,
			goto out
	);

	int session_present = 0;
	if ((ret = mqtt_data->sessions->methods->get_session (
			&session,
			mqtt_data->sessions,
			connect->client_identifier,
			&session_present,
			0,  // Create if non-existent client ID
			1   // Local delivery (check received PUBLISH agains subscriptions and deliver locally)
	)) != RRR_MQTT_SESSION_OK || session == NULL) {
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		VL_MSG_ERR("Internal error getting session in rrr_mqtt_client_connect\n");
		goto out;
	}

	if ((ret = mqtt_data->sessions->methods->init_session (
			mqtt_data->sessions,
			&session,
			&callback_data.session_properties,
			mqtt_data->retry_interval_usec,
			RRR_MQTT_CLIENT_MAX_IN_FLIGHT,
			RRR_MQTT_CLIENT_COMPLETE_PUBLISH_GRACE_TIME,
			RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect),
			&session_present
	)) != RRR_MQTT_SESSION_OK) {
		if ((ret & RRR_MQTT_SESSION_DELETED) != 0) {
			VL_MSG_ERR("New session was deleted in rrr_mqtt_client_connect\n");
		}
		else {
			VL_MSG_ERR("Error while initializing session in rrr_mqtt_client_connect, return was %i\n", ret);
		}
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_conn_with_iterator_ctx_do (
			&data->mqtt_data.connections,
			result_handle->connection,
			(struct rrr_mqtt_p *) connect,
			rrr_mqtt_conn_iterator_ctx_send_packet
	) != 0) {
		VL_MSG_ERR("Could not send CONNECT packet in rrr_mqtt_client_connect");
		ret = 1;
		goto out;
	}

	out:
		RRR_MQTT_P_UNLOCK(connect);
	out_nolock:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(connect);
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

static const struct rrr_mqtt_type_handler_properties handler_properties[] = {
	{NULL},
	{NULL},
	{NULL},
	{rrr_mqtt_common_handle_publish},
	{rrr_mqtt_common_handle_puback_pubcomp},
	{rrr_mqtt_common_handle_pubrec},
	{rrr_mqtt_common_handle_pubrel},
	{rrr_mqtt_common_handle_puback_pubcomp},
	{NULL},
	{NULL},
	{NULL},
	{NULL},
	{NULL},
	{NULL},
	{rrr_mqtt_common_handle_disconnect},
	{NULL}
};

static int __rrr_mqtt_client_event_handler (
		struct rrr_mqtt_conn *connection,
		int event,
		void *static_arg,
		void *arg
) {
	struct rrr_mqtt_client_data *data = static_arg;

	(void)(connection);

	int ret = RRR_MQTT_CONN_OK;

	switch (event) {
		case RRR_MQTT_CONN_EVENT_DISCONNECT:
			break;
		case RRR_MQTT_CONN_EVENT_ACK_SENT:
			if ((ret = data->mqtt_data.sessions->methods->notify_ack_sent (
					data->mqtt_data.sessions,
					&connection->session,
					(struct rrr_mqtt_p *) arg
			)) != RRR_MQTT_SESSION_OK) {
				VL_MSG_ERR("Error from session ACK notification function in __rrr_mqtt_client_event_handler\n");
				goto out;
			}
			break;
		default:
			break;
	};

	out:
	return ret;
}

void rrr_mqtt_client_destroy (struct rrr_mqtt_client_data *client) {
	rrr_mqtt_common_data_destroy(&client->mqtt_data);
	free(client);
}

int rrr_mqtt_client_new (
		struct rrr_mqtt_client_data **client,
		const char *client_name,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg
) {
	int ret = 0;

	struct rrr_mqtt_client_data *result = malloc(sizeof(*result));

	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_client_new\n");
		ret = 1;
		goto out;
	}

	memset (result, '\0', sizeof(*result));

	ret = rrr_mqtt_common_data_init (
			&result->mqtt_data,
			client_name,
			handler_properties,
			session_initializer,
			session_initializer_arg,
			__rrr_mqtt_client_event_handler,
			result,
			RRR_MQTT_CLIENT_RETRY_INTERVAL * 1000 * 1000,
			RRR_MQTT_CLIENT_CLOSE_WAIT_TIME * 1000 * 1000,
			RRR_MQTT_CLIENT_MAX_SOCKETS
	);

	if (ret != 0) {
		VL_MSG_ERR("Could not initialize MQTT common data in rrr_mqtt_client_new\n");
		ret = 1;
		goto out_free;
	}

	*client = result;

	goto out;
	out_free:
		free(result);
	out:
		return ret;
}

int rrr_mqtt_client_synchronized_tick (struct rrr_mqtt_client_data *data) {
	int ret = 0;

	if ((ret = rrr_mqtt_common_read_parse_handle (&data->mqtt_data)) != 0) {
		goto out;
	}

	if ((ret = data->mqtt_data.sessions->methods->maintain (
			data->mqtt_data.sessions
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
