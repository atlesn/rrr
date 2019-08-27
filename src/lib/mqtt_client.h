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

#ifndef RRR_MQTT_CLIENT_H
#define RRR_MQTT_CLIENT_H

#define RRR_MQTT_CLIENT_RETRY_INTERVAL 5
#define RRR_MQTT_CLIENT_CLOSE_WAIT_TIME 3
#define RRR_MQTT_CLIENT_MAX_SOCKETS 100

#include <inttypes.h>

#include "mqtt_common.h"

struct rrr_mqtt_session_collection;

struct rrr_mqtt_client_data {
	/* MUST be first */
	struct rrr_mqtt_data mqtt_data;
};

int rrr_mqtt_client_connect (
		struct rrr_mqtt_common_remote_handle *result_handle,
		struct rrr_mqtt_client_data *data,
		const char *server,
		uint16_t port
);
void rrr_mqtt_client_destroy (struct rrr_mqtt_client_data *client);
int rrr_mqtt_client_new (
		struct rrr_mqtt_client_data **client,
		const char *client_name,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg
);
int rrr_mqtt_client_synchronized_tick (struct rrr_mqtt_client_data *data);

#endif /* RRR_MQTT_CLIENT_H */
