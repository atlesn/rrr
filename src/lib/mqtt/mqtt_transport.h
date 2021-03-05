/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MQTT_TRANSPORT_H
#define RRR_MQTT_TRANSPORT_H

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>

#include "mqtt_common.h"
#include "../net_transport/net_transport.h"

#define RRR_MQTT_TRANSPORT_MAX 2

struct rrr_net_transport_config;
struct rrr_mqtt_p;

struct rrr_mqtt_transport {
	ssize_t max;
	uint64_t close_wait_time_usec;
	uint64_t connection_hard_timeout_usec;

	struct rrr_net_transport *transports[RRR_MQTT_TRANSPORT_MAX];
	size_t transport_count;

	struct rrr_event_queue *queue;

	int (*event_handler) (RRR_MQTT_EVENT_HANDLER_DEFINITION);
	void *event_handler_static_arg;
	void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS);
	int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS);
	void *read_callback_arg;
};

void rrr_mqtt_transport_cleanup (
		struct rrr_mqtt_transport *transport
);
void rrr_mqtt_transport_destroy (
		struct rrr_mqtt_transport *transport
);
int rrr_mqtt_transport_new (
		struct rrr_mqtt_transport **result,
		unsigned int max_connections,
		uint64_t close_wait_time_usec,
		uint64_t connection_hard_timeout_usec,
		struct rrr_event_queue *queue,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_arg,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg
);
static inline struct rrr_net_transport *rrr_mqtt_transport_get_latest (
		struct rrr_mqtt_transport *transport
) {
	return (transport->transport_count == 0 ? NULL : transport->transports[transport->transport_count - 1]);
}
int rrr_mqtt_transport_start (
		struct rrr_mqtt_transport *transport,
		const struct rrr_net_transport_config *net_transport_config
);
int rrr_mqtt_transport_accept (
		int *new_transport_handle,
		struct rrr_mqtt_transport *transport,
		void (*new_connection_callback)(
				struct rrr_net_transport_handle *handle,
				const struct sockaddr *sockaddr,
				socklen_t socklen,
				void *rrr_mqtt_transport_accept_and_connect_callback_data
		)
);
int rrr_mqtt_transport_connect (
		int *new_transport_handle,
		struct rrr_mqtt_transport *transport,
		unsigned int port,
		const char *host,
		void (*new_connection_callback)(
				struct rrr_net_transport_handle *handle,
				const struct sockaddr *sockaddr,
				socklen_t socklen,
				void *rrr_mqtt_transport_accept_and_connect_callback_data
		)
);
int rrr_mqtt_transport_iterate (
		struct rrr_mqtt_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *callback_arg),
		void *callback_arg
);
int rrr_mqtt_transport_with_iterator_ctx_do_custom (
		struct rrr_mqtt_transport *transport,
		int transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *callback_arg
);
int rrr_mqtt_transport_with_iterator_ctx_do_packet (
		struct rrr_mqtt_transport *transport,
		int transport_handle,
		struct rrr_mqtt_p *packet,
		int (*callback)(struct rrr_net_transport_handle *handle, struct rrr_mqtt_p *packet)
);

#endif /* RRR_MQTT_TRANSPORT_H */
