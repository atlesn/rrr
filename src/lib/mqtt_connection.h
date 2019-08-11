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
#include "ip.h"
#include "mqtt_packet.h"
#include "mqtt_parse.h"

#define RRR_MQTT_CONNECTION_TYPE_IPV4 4
#define RRR_MQTT_CONNECTION_TYPE_IPV6 6

#define RRR_MQTT_CONNECTION_STATE_NEW							0
#define RRR_MQTT_CONNECTION_STATE_CONNECT_SENT_OR_RECEIVED		1
#define RRR_MQTT_CONNECTION_STATE_AUTHENTICATING				2
#define RRR_MQTT_CONNECTION_STATE_ESTABLISHED					3
#define RRR_MQTT_CONNECTION_STATE_DISCONNECT_SENT_OR_RECEIVED	4
#define RRR_MQTT_CONNECTION_STATE_CLOSED						5

struct rrr_mqtt_connection_read_session {
	/*
	 * A packet processing action might be temporarily paused if the payload
	 * is large (exceeds step_size_limit is < 0). It will resume in the next process tick.
	 *
	 * When rx_buf_wpos reaches target_size, the retrieval is complete and the processing
	 * of the packet may begin.
	 */
	int packet_complete;

	ssize_t step_size_limit;

	ssize_t target_size;

	char *rx_buf;
	ssize_t rx_buf_size;
	ssize_t rx_buf_wpos;
};

struct rrr_mqtt_connection {
	struct rrr_mqtt_connection *next;

	pthread_mutex_t lock;

	struct ip_data ip_data;

	uint64_t connect_time;
	uint64_t last_seen_time;

	char *client_id;

	int state;

	struct rrr_mqtt_connection_read_session read_session;
	struct rrr_mqtt_p_parse_session parse_session;

	struct rrr_mqtt_p_queue send_queue;
	struct rrr_mqtt_p_queue receive_queue;
	struct rrr_mqtt_p_queue wait_for_ack_queue;

	char ip[INET6_ADDRSTRLEN];
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
	int readers;
	int writers_waiting;
	int write_locked;
};

int rrr_mqtt_connection_send_disconnect_and_close (struct rrr_mqtt_connection *connection);
void rrr_mqtt_connection_collection_destroy (struct rrr_mqtt_connection_collection *connections);
int rrr_mqtt_connection_collection_init (struct rrr_mqtt_connection_collection *connections);
int rrr_mqtt_connection_collection_new_connection (
		struct rrr_mqtt_connection **connection,
		struct rrr_mqtt_connection_collection *connections,
		const struct ip_data *ip_data,
		const struct sockaddr *remote_addr
);

#define RRR_MQTT_CONNECTION_OK					0
#define RRR_MQTT_CONNECTION_INTERNAL_ERROR		(1<<0)
#define RRR_MQTT_CONNECTION_DESTROY_CONNECTION	(1<<1)
#define RRR_MQTT_CONNECTION_SOFT_ERROR			(1<<2)
#define RRR_MQTT_CONNECTION_BUSY				(1<<3)
#define RRR_MQTT_CONNECTION_STEP_LIMIT			(1<<4)

int rrr_mqtt_connection_collection_iterate (
		struct rrr_mqtt_connection_collection *connections,
		int (*callback)(struct rrr_mqtt_connection *connection, void *callback_arg),
		void *callback_arg
);

int rrr_mqtt_connection_read (
		struct rrr_mqtt_connection *connection,
		int read_step_max_size
);
int rrr_mqtt_connection_parse (
		struct rrr_mqtt_connection *connection
);

#endif /* RRR_MQTT_CONNECTION_H */
