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

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data) {
	if (data == NULL) {
		return;
	}

	if (data->connections.invalid == 0) {
		rrr_mqtt_connection_collection_destroy(&data->connections);
	}

	*(data->client_name) = '\0';
	data->handler_properties = NULL;
}

int rrr_mqtt_common_data_init (
		struct rrr_mqtt_data *data,
		const char *client_name,
		const struct rrr_mqtt_type_handler_properties *handler_properties
) {
	int ret = 0;

	if (strlen(client_name) > RRR_MQTT_DATA_CLIENT_NAME_LENGTH) {
		VL_MSG_ERR("Client name was too long in rrr_mqtt_data_init\n");
		ret = 1;
		goto out;
	}

	data->handler_properties = handler_properties;
	strcpy(data->client_name, client_name);

	/* XXX : If the connection collection is not initialized last, make sure it is destroyed on errors after out: */
	if (rrr_mqtt_connection_collection_init(&data->connections) != 0) {
		VL_MSG_ERR("Could not initialize connection collection in rrr_mqtt_data_new\n");
		ret = 1;
		goto out;
	}

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

struct read_and_parse_callback_data {
	struct rrr_mqtt_data *data;
};

int __rrr_mqtt_common_read_and_parse_callback (struct rrr_mqtt_connection *connection, void *arg) {
	struct read_and_parse_callback_data *callback_data = arg;

	(void)(callback_data);

	int ret = 0;

	while (ret == 0) {
		ret = rrr_mqtt_connection_read (connection, RRR_MQTT_SYNCHRONIZED_READ_STEP_MAX_SIZE);
	}

	if ((ret & RRR_MQTT_CONNECTION_INTERNAL_ERROR) > 0) {
		VL_MSG_ERR("Internal error while reading data from mqtt client. Closing down server.\n");
		ret =  RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}

	if ((ret & (RRR_MQTT_CONNECTION_DESTROY_CONNECTION|RRR_MQTT_CONNECTION_SOFT_ERROR)) > 0) {
		VL_MSG_ERR("Error while reading data from mqtt client, destroying connection.\n");
		ret = RRR_MQTT_CONNECTION_DESTROY_CONNECTION|RRR_MQTT_CONNECTION_SOFT_ERROR;
		goto out;
	}

	ret = rrr_mqtt_connection_parse (connection);

	if (connection->read_session.packet_complete == 1 && !RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		VL_MSG_ERR("Reading is done for a packet but parsing did not complete. Closing connection.\n");
		ret = RRR_MQTT_CONNECTION_DESTROY_CONNECTION|RRR_MQTT_CONNECTION_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_mqtt_common_read_and_parse (struct rrr_mqtt_data *data) {
	int ret = 0;

	struct read_and_parse_callback_data callback_data = { data };

	ret = rrr_mqtt_connection_collection_iterate(&data->connections, __rrr_mqtt_common_read_and_parse_callback, &callback_data);

	if ((ret & (RRR_MQTT_CONNECTION_SOFT_ERROR|RRR_MQTT_CONNECTION_DESTROY_CONNECTION)) > 0) {
		VL_MSG_ERR("Soft error in rrr_mqtt_common_read_and_parse (one or more connections had to be closed)\n");
		ret = 0;
	}
	if ((ret & RRR_MQTT_CONNECTION_INTERNAL_ERROR) > 0) {
		VL_MSG_ERR("Internal error received in rrr_mqtt_common_read_and_parse\n");
		ret = 1;
	}

	return ret;
}
