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

struct rrr_mqtt_data;

struct rrr_mqtt_connection_read_session {
	/*
	 * A packet processing action might be temporarily paused if the payload
	 * is large (exceeds step_size_limit is < 0). It will resume in the next process tick.
	 *
	 * When rx_buf_wpos reaches target_size, the retrieval is complete and the processing
	 * of the packet may begin.
	 */

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

	int read_complete;
	int parse_complete;

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

// Can ONLY be used when holding collection iterator read or write lock AND lock on the connection
int rrr_mqtt_connection_send_disconnect_and_close_unlocked (struct rrr_mqtt_connection *connection);

// Can ONLY be used at program exit when only one thread is running
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
#define RRR_MQTT_CONNECTION_ITERATE_STOP		(1<<5)

// It is possible while being in a callback function for the collection iterator
// to convert the held read lock to a write lock, in case this function is called
// to iterate again with write lock held. Before returning, the write lock is
// converted back to read lock. Returning RRR_MQTT_CONNECTION_DESTROY_CONNECTION
// from a callback of this function IS NOT allowed.
int rrr_mqtt_connection_collection_iterate_reenter_read_to_write (
		struct rrr_mqtt_connection_collection *connections,
		int (*callback)(struct rrr_mqtt_connection *connection, void *callback_arg),
		void *callback_arg
);

// Normal iterator, holds read lock. Connections must be destroyed ONLY by returning
// RRR_MQTT_CONNECTION_DESTROY_CONNECTION from a callback function of an iterator.
// This does not apply when program is closing and the collection is to be destroyed.

// One MUST NOT work with ANY connections outside iterator callback-context

// If it is wanted to only work with one single connection, one must create a custom
// callback function and a callback data structure to search for a specific connection
// and do something with it. It is then possible to detect if the connection
// actually did exist or if it was destroyed in the meantime before we called the
// iterator.
int rrr_mqtt_connection_collection_iterate (
		struct rrr_mqtt_connection_collection *connections,
		int (*callback)(struct rrr_mqtt_connection *connection, void *callback_arg),
		void *callback_arg
);

// These functions may be called asynchronously, BUT they MUST ONLY be used as callbacks
// for the iterator above. It is and error to use these functions as callback for
// rrr_mqtt_connection_collection_iterate_reenter_read_to_write
int rrr_mqtt_connection_read_and_parse (
		struct rrr_mqtt_connection *connection,
		void *arg
);
int rrr_mqtt_connection_handle_packets (
		struct rrr_mqtt_connection *connection,
		void *arg
);

// These functions MUST also be used ONLY in iterator context. Functions with the
// connection/packet argument pair is also supported by the iterator_ctx_do-function
// which can use these as callbacks. This keeps us from writing callbacks for some
// common operations.
int rrr_mqtt_connection_queue_outbound_packet_iterator_ctx (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
);

// Special iterator for functions which accept connection/packet arguments. The callback
// is called exactly one time, and then with the provided connection as argument. The
// return value from the callback is returned. If the connection was destroyed recently,
// the callback is not called and a soft error is returned.
int rrr_mqtt_connection_with_iterator_ctx_do (
		struct rrr_mqtt_connection_collection *connections,
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet,
		int (*callback)(struct rrr_mqtt_connection *connection, struct rrr_mqtt_p_packet *packet)
);

// Helper functions to wrap connection/packet argument pair functions into iterator context. Might
// deadlock if already in iterator context, use the XXX_iterator_ctx-functions above if you already
// are in iterator context
static int rrr_mqtt_connection_queue_outbound_packet (
		struct rrr_mqtt_connection_collection *connections,
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
) {
	return rrr_mqtt_connection_with_iterator_ctx_do(connections, connection, packet, rrr_mqtt_connection_queue_outbound_packet_iterator_ctx);
}

// Iterate connections and do basically everything. mqtt_data is needed for handling packets.
int rrr_mqtt_connection_collection_read_parse_handle (
		struct rrr_mqtt_connection_collection *connections,
		struct rrr_mqtt_data *mqtt_data
);

#endif /* RRR_MQTT_CONNECTION_H */
