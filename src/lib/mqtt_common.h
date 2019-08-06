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

#include "mqtt_connection.h"

struct rrr_mqtt_data {
	struct rrr_mqtt_connection_collection connections;
};

#define RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION \
	struct rrr_mqtt_data *mqtt_data, struct rrr_mqtt_connection *mqtt_conn, struct rrr_mqtt_rx_data *rx_data

struct rrr_mqtt_p_type_properties {
	/* If has_reserved_flags is non-zero, a packet must have the exact specified flags set to be valid */
	uint8_t has_reserved_flags;
	uint8_t flags;
	int (*handler)(RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION);
};

void rrr_mqtt_data_destroy (struct rrr_mqtt_data *data);
int rrr_mqtt_data_init (struct rrr_mqtt_data *data);

#endif /* RRR_MQTT_COMMON_H */
