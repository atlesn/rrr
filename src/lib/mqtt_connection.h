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

#ifndef RRR_MQTT_CONNECTION_H
#define RRR_MQTT_CONNECTION_H

#include <pthread.h>
#include <inttypes.h>
#include <netinet/in.h>

#include "buffer.h"
#include "mqtt_packet.h"

#define RRR_MQTT_CONNECTION_TYPE_IPV4 4
#define RRR_MQTT_CONNECTION_TYPE_IPV6 6

#define RRR_MQTT_CONNECTION_STATE_NEW							0
#define RRR_MQTT_CONNECTION_STATE_CONNECT_SENT_OR_RECEIVED		1
#define RRR_MQTT_CONNECTION_STATE_AUTHENTICATING				2
#define RRR_MQTT_CONNECTION_STATE_ESTABLISHED					3
#define RRR_MQTT_CONNECTION_STATE_DISCONNECT_SENT_OR_RECEIVED	4
#define RRR_MQTT_CONNECTION_STATE_CLOSED						5

struct rrr_mqtt_connection {
	struct rrr_mqtt_connection *next;

	pthread_mutex_t lock;

	int fd;

	uint64_t connect_time;
	uint64_t last_seen_time;

	char *client_id;

	int state;

	struct rrr_mqtt_packet_queue send_queue;
	struct rrr_mqtt_packet_queue receive_queue;
	struct rrr_mqtt_packet_queue wait_for_ack_queue;

	int type; // 4 or 6
	union {
		struct sockaddr_in remote_in;
		struct sockaddr_in6 remote_in6;
	};
};

struct rrr_mqtt_connection_collection {
	struct rrr_mqtt_connection *first;
	int invalid;
	pthread_mutex_t lock;
};

int rrr_mqtt_connection_send_disconnect_and_close (struct rrr_mqtt_connection *connection);
void rrr_mqtt_connection_collection_destroy (struct rrr_mqtt_connection_collection *connections);
int rrr_mqtt_connection_collection_init (struct rrr_mqtt_connection_collection *connections);
int rrr_mqtt_connection_collection_new_connection (
		struct rrr_mqtt_connection **connection,
		struct rrr_mqtt_connection_collection *connections,
		int fd,
		int type
);

#endif /* RRR_MQTT_CONNECTION_H */
