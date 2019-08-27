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

#include "mqtt_client.h"
#include "mqtt_common.h"

#include <inttypes.h>
#include <stdlib.h>

int rrr_mqtt_client_connect (
		struct rrr_mqtt_common_remote_handle *result_handle,
		struct rrr_mqtt_client_data *data,
		const char *server,
		uint16_t port
) {
	int ret = 0;

	struct ip_accept_data *accept_data = NULL;

	if (ip_network_connect_tcp_ipv4_or_ipv6 (&accept_data, port, server) != 0) {
		VL_MSG_ERR("Could not connect to mqtt server '%s'\n", server);
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_common_register_connection(result_handle, &data->mqtt_data, accept_data) != 0) {
		VL_MSG_ERR("Could not register connection to mqtt server %s\n", server);
		ret = 1;
		goto out;
	}

	out:
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
