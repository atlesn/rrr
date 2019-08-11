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

#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_session.h"

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data) {
	if (data == NULL) {
		return;
	}

	if (data->connections.invalid == 0) {
		rrr_mqtt_connection_collection_destroy(&data->connections);
	}

	if (data->sessions != NULL) {
		data->sessions->destroy(data->sessions);
	}

	*(data->client_name) = '\0';
	data->handler_properties = NULL;
}

int rrr_mqtt_common_data_init (struct rrr_mqtt_data *data,
		const char *client_name,
		const struct rrr_mqtt_type_handler_properties *handler_properties,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg
) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	if (strlen(client_name) > RRR_MQTT_DATA_CLIENT_NAME_LENGTH) {
		VL_MSG_ERR("Client name was too long in rrr_mqtt_data_init\n");
		ret = 1;
		goto out;
	}

	data->handler_properties = handler_properties;
	strcpy(data->client_name, client_name);

	if (rrr_mqtt_connection_collection_init(&data->connections) != 0) {
		VL_MSG_ERR("Could not initialize connection collection in rrr_mqtt_data_new\n");
		ret = 1;
		goto out;
	}

	if (session_initializer (&data->sessions, session_initializer_arg) != 0) {
		VL_MSG_ERR("Could not initialize session data in rrr_mqtt_data_new\n");
		ret = 1;
		goto out_destroy_connections;
	}

	goto out;

	out_destroy_connections:
		rrr_mqtt_connection_collection_destroy(&data->connections);

	out:
		return ret;
}

int rrr_mqtt_common_data_register_connection (
		struct rrr_mqtt_data *data,
		const struct ip_accept_data *accept_data
) {
	int ret = 0;

	struct rrr_mqtt_connection *connection;

	ret = rrr_mqtt_connection_collection_new_connection (
			&connection,
			&data->connections,
			&accept_data->ip_data,
			&accept_data->addr
	);

	return ret;
}

int rrr_mqtt_common_read_parse_handle (struct rrr_mqtt_data *data) {
	int ret = 0;

	ret = rrr_mqtt_connection_collection_read_parse_handle (
			&data->connections,
			data
	);

	if (ret != 0) {
		VL_MSG_ERR("Error in rrr_mqtt_common_read_parse_handle\n");
	}

	return ret;
}
