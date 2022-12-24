/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MQTT_CONN_H
#define RRR_MQTT_CONN_H

#include <inttypes.h>
#include <netinet/in.h>

#include "mqtt_packet.h"
#include "mqtt_parse.h"
#include "../fifo.h"
#include "../read_constants.h"
#include "../ip/ip.h"
#include "../util/linked_list.h"

#define RRR_MQTT_CONN_TYPE_IPV4 4
#define RRR_MQTT_CONN_TYPE_IPV6 6

#define RRR_MQTT_CONN_STATE_NEW                            (0)
#define RRR_MQTT_CONN_STATE_SEND_CONNACK_ALLOWED        (1<<0)
#define RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_ALLOWED     (1<<1)
#define RRR_MQTT_CONN_STATE_SEND_ANY_ALLOWED            (1<<2)
#define RRR_MQTT_CONN_STATE_RECEIVE_ANY_ALLOWED         (1<<3)
// After disconnecting, we wait a bit before close()-ing to let the client close first. The
// broker sets the timeout for this, the client sets it to 0.
#define RRR_MQTT_CONN_STATE_CLOSE_WAIT                  (1<<5)
// When close wait timer has started, state will transition into CLOSED. When timer is
// complete, the connection is destroyed.
#define RRR_MQTT_CONN_STATE_CLOSED                      (1<<6)

#define RRR_MQTT_CONN_EVENT_DISCONNECT     1
#define RRR_MQTT_CONN_EVENT_PACKET_PARSED  2

#define RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK_NO_ERROR                             \
        struct rrr_mqtt_conn *connection = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);   \
        do { if (RRR_MQTT_CONN_STATE_IS_CLOSED_OR_CLOSE_WAIT(connection)) {             \
            return RRR_MQTT_OK;                                                         \
        }} while (0)

#define RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK                                                                        \
        struct rrr_mqtt_conn *connection = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);                                     \
        do { if (RRR_MQTT_CONN_STATE_IS_CLOSED_OR_CLOSE_WAIT(connection)||RRR_MQTT_CONN_STATE_IS_CLOSED(connection)) {    \
            return RRR_MQTT_SOFT_ERROR;                                                                                   \
        }} while (0)

#define RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, reason)   \
        if ((connection)->disconnect_reason_v5_ == 0) {                   \
            (connection)->disconnect_reason_v5_ = reason;                 \
        }

struct rrr_mqtt_session;
struct rrr_net_transport_handle;

struct rrr_mqtt_conn {
	int transport_handle;

	int (*event_handler)(
			RRR_MQTT_EVENT_HANDLER_DEFINITION
	);
	void *event_handler_static_arg;

	uint64_t connect_time;
	uint64_t last_read_time;
	uint64_t last_write_time;

	char *client_id;
	struct rrr_mqtt_session *session;
	const struct rrr_mqtt_p_protocol_version *protocol_version;
	uint16_t keep_alive;

	char *username;

	uint32_t state_flags;
	uint8_t disconnect_reason_v5_;

	int last_event;

	struct rrr_mqtt_parse_session parse_session;

	struct rrr_mqtt_p_queue receive_buffer;

	uint64_t close_wait_time_usec;
	uint64_t close_wait_start;

	char ip[INET6_ADDRSTRLEN];
	int type; // 4 or 6
	union {
		struct sockaddr_in remote_in;
		struct sockaddr_in6 remote_in6;
	};
};

#define RRR_MQTT_CONN_STATE_CONNECT_ALLOWED(c) \
	((c)->state_flags == RRR_MQTT_CONN_STATE_NEW)

#define RRR_MQTT_CONN_STATE_SET(c,f) \
	(c)->state_flags = (f)

#define RRR_MQTT_CONN_STATE_OR(c) \
	(c)->state_flags |= c

#define RRR_MQTT_CONN_STATE_SEND_IS_BUSY_CLIENT_ID(c)                              \
	(((c)->state_flags & (    RRR_MQTT_CONN_STATE_SEND_CONNACK_ALLOWED |       \
	                          RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_ALLOWED |    \
	                          RRR_MQTT_CONN_STATE_SEND_ANY_ALLOWED |           \
	                          RRR_MQTT_CONN_STATE_RECEIVE_ANY_ALLOWED          \
	)) != 0)

#define RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONN_STATE_SEND_ANY_ALLOWED) != 0)

#define RRR_MQTT_CONN_STATE_RECEIVE_ANY_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONN_STATE_RECEIVE_ANY_ALLOWED) != 0)

#define RRR_MQTT_CONN_STATE_SEND_CONNACK_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONN_STATE_SEND_CONNACK_ALLOWED) != 0)

#define RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_ALLOWED) != 0)

#define RRR_MQTT_CONN_STATE_RECEIVE_CONNECT_IS_ALLOWED(c) \
	((c)->state_flags == RRR_MQTT_CONN_STATE_NEW)

#define RRR_MQTT_CONN_STATE_IS_CLOSE_WAIT(c) \
	(((c)->state_flags & (RRR_MQTT_CONN_STATE_CLOSE_WAIT)) != 0)

#define RRR_MQTT_CONN_STATE_IS_CLOSED_OR_CLOSE_WAIT(c) \
	(((c)->state_flags & (RRR_MQTT_CONN_STATE_CLOSED|RRR_MQTT_CONN_STATE_CLOSE_WAIT)) != 0)

#define RRR_MQTT_CONN_STATE_IS_CLOSED(c) \
	(((c)->state_flags & RRR_MQTT_CONN_STATE_CLOSED) != 0)

#define RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_IN		1
#define RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT	2

int rrr_mqtt_conn_set_client_id (
		struct rrr_mqtt_conn *connection,
		const char *id
);
// No reference counting of packet performed
int rrr_mqtt_conn_update_state (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		int direction
);
int rrr_mqtt_conn_set_data_from_connect_and_connack (
		struct rrr_mqtt_conn *connection,
		uint16_t keep_alive,
		const struct rrr_mqtt_p_protocol_version *protocol_version,
		struct rrr_mqtt_session *session,
		const char *username
);
int rrr_mqtt_conn_iterator_ctx_housekeeping (
		struct rrr_net_transport_handle *handle,
		int (*exceeded_keep_alive_callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *callback_arg
);
void rrr_mqtt_conn_accept_and_connect_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
);
int rrr_mqtt_conn_iterator_ctx_check_alive (
		int *alive,
		int *send_allowed,
		int *close_wait,
		struct rrr_net_transport_handle *handle
);
int rrr_mqtt_conn_iterator_ctx_read (
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_step_max_size,
		int (*handler_callback) (
				struct rrr_net_transport_handle *handle,
				struct rrr_mqtt_p *packet,
				void *arg
		),
		void *handler_callback_arg
);
// No reference counting of packet performed, but event handlers might
// INCREF if they add the packet to a buffer
int rrr_mqtt_conn_iterator_ctx_send_packet (
		int *do_stop,
		struct rrr_net_transport_handle *handle,
		struct rrr_mqtt_p *packet
);
int rrr_mqtt_conn_iterator_ctx_send_packet_urgent (
		struct rrr_net_transport_handle *handle,
		struct rrr_mqtt_p *packet
);
int rrr_mqtt_conn_iterator_ctx_set_disconnect_reason (
		struct rrr_net_transport_handle *handle,
		uint8_t reason_v5
);
int rrr_mqtt_conn_iterator_ctx_send_disconnect (
		struct rrr_net_transport_handle *handle
);

#endif /* RRR_MQTT_CONN_H */
