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
#include "linked_list.h"

#define RRR_MQTT_CONNECTION_TYPE_IPV4 4
#define RRR_MQTT_CONNECTION_TYPE_IPV6 6

#define RRR_MQTT_CONNECTION_OK					0
#define RRR_MQTT_CONNECTION_INTERNAL_ERROR		(1<<0)
#define RRR_MQTT_CONNECTION_DESTROY_CONNECTION	(1<<1)
#define RRR_MQTT_CONNECTION_SOFT_ERROR			(1<<2)
#define RRR_MQTT_CONNECTION_BUSY				(1<<3)
#define RRR_MQTT_CONNECTION_STEP_LIMIT			(1<<4)
#define RRR_MQTT_CONNECTION_ITERATE_STOP		(1<<5)

#define RRR_MQTT_CONNECTION_STATE_NEW						(0)
#define RRR_MQTT_CONNECTION_STATE_SEND_CONNACK_ALLOWED		(1<<0)
#define RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNACK_ALLOWED	(1<<1)
#define RRR_MQTT_CONNECTION_STATE_SEND_ANY_ALLOWED			(1<<2)
#define RRR_MQTT_CONNECTION_STATE_RECEIVE_ANY_ALLOWED		(1<<3)
// It is not always possible to destroy a connection immediately when we
// send a disconnect packet (or pretend to). This flags tells housekeeping
// to destroy the connection, and also blocks further usage.
#define RRR_MQTT_CONNECTION_STATE_DISCONNECTED				(1<<4)
// After disconnecting, we wait a bit before close()-ing to let the client close first. The
// broker sets the timeout for this, the client sets it to 0.
#define RRR_MQTT_CONNECTION_STATE_DISCONNECT_WAIT			(1<<5)
#define RRR_MQTT_CONNECTION_STATE_CLOSED					(1<<6)

#define RRR_MQTT_CONNECTION_EVENT_DISCONNECT 1
#define RRR_MQTT_CONNECTION_EVENT_PACKET_PARSED 2

struct rrr_mqtt_data;
struct rrr_mqtt_session;

struct rrr_mqtt_connection_read_session {
	/* A packet read action might be temporarily paused if the payload
	 * is large (exceeds step_size_limit is < 0). It will resume in the next process tick.
	 *
	 * When rx_buf_wpos reaches target_size, the retrieval is complete and the processing
	 * of the packet may begin. */

	ssize_t step_size_limit;

	ssize_t target_size;

	char *rx_buf;
	ssize_t rx_buf_size;
	ssize_t rx_buf_wpos;
};

struct rrr_mqtt_connection {
	RRR_LINKED_LIST_NODE(struct rrr_mqtt_connection);
	struct rrr_mqtt_connection_collection *collection;

	pthread_mutex_t lock;

	struct ip_data ip_data;

	uint64_t connect_time;
	uint64_t last_seen_time;

	char *client_id;
	struct rrr_mqtt_session *session;
	const struct rrr_mqtt_p_protocol_version *protocol_version;
	uint16_t keep_alive;

	uint32_t state_flags;
	uint8_t disconnect_reason_v5;

	int last_event;

	struct rrr_mqtt_connection_read_session read_session;
	struct rrr_mqtt_p_parse_session parse_session;

	struct rrr_mqtt_p_queue send_queue;
	struct rrr_mqtt_p_queue receive_queue;

	int read_complete;
	int parse_complete;

	uint64_t close_wait_time_usec;
	uint64_t close_wait_start;

	char ip[INET6_ADDRSTRLEN];
	int type; // 4 or 6
	union {
		struct sockaddr_in remote_in;
		struct sockaddr_in6 remote_in6;
	};
};

struct rrr_mqtt_connection_collection {
	RRR_LINKED_LIST_HEAD(struct rrr_mqtt_connection);

	int invalid;
	int max;

	pthread_mutex_t lock;
	int readers;
	int writers_waiting;
	int write_locked;

	int (*event_handler)(struct rrr_mqtt_connection *connection, int event, void *arg);
	void *event_handler_arg;
};

#define RRR_MQTT_CONNECTION_STATE_CONNECT_ALLOWED(c) \
	((c)->state_flags == RRR_MQTT_CONNECTION_STATE_NEW)

#define RRR_MQTT_CONNECTION_STATE_SET(c,f) \
	(c)->state_flags = (f)

#define RRR_MQTT_CONNECTION_STATE_OR(c) \
	(c)->state_flags |= c

#define RRR_MQTT_CONNECTION_STATE_SEND_IS_BUSY_CLIENT_ID(c)						\
	(((c)->state_flags & (	RRR_MQTT_CONNECTION_STATE_SEND_CONNACK_ALLOWED |	\
							RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNACK_ALLOWED |	\
							RRR_MQTT_CONNECTION_STATE_SEND_ANY_ALLOWED |		\
							RRR_MQTT_CONNECTION_STATE_RECEIVE_ANY_ALLOWED		\
	)) != 0)

#define RRR_MQTT_CONNECTION_STATE_SEND_ANY_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_SEND_ANY_ALLOWED) != 0)

#define RRR_MQTT_CONNECTION_STATE_RECEIVE_ANY_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_RECEIVE_ANY_ALLOWED) != 0)

#define RRR_MQTT_CONNECTION_STATE_SEND_CONNACK_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_SEND_CONNACK_ALLOWED) != 0)

#define RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNACK_IS_ALLOWED(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNACK_ALLOWED) != 0)

#define RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNECT_IS_ALLOWED(c) \
	((c)->state_flags == RRR_MQTT_CONNECTION_STATE_NEW)

#define RRR_MQTT_CONNECTION_STATE_IS_DISCONNECT_WAIT(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_DISCONNECT_WAIT) != 0)

#define RRR_MQTT_CONNECTION_STATE_IS_DISCONNECTED(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_DISCONNECTED) != 0)

#define RRR_MQTT_CONNECTION_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(c) \
	(((c)->state_flags & (RRR_MQTT_CONNECTION_STATE_DISCONNECTED|RRR_MQTT_CONNECTION_STATE_DISCONNECT_WAIT)) != 0)

#define RRR_MQTT_CONNECTION_STATE_IS_CLOSED(c) \
	(((c)->state_flags & RRR_MQTT_CONNECTION_STATE_CLOSED) != 0)

#define RRR_MQTT_CONNECTION_LOCK(c) \
	pthread_mutex_lock(&((c)->lock))

#define RRR_MQTT_CONNECTION_UNLOCK(c) \
	pthread_mutex_unlock(&((c)->lock))

#define RRR_MQTT_CONNECTION_TRYLOCK(c) \
	pthread_mutex_trylock(&((c)->lock))

// Can ONLY be used at program exit when only one thread is running
void rrr_mqtt_connection_collection_destroy (struct rrr_mqtt_connection_collection *connections);

int rrr_mqtt_connection_collection_init (
		struct rrr_mqtt_connection_collection *connections,
		int max_connections,
		int (*event_handler)(struct rrr_mqtt_connection *connection, int event, void *arg),
		void *event_handler_arg
);
int rrr_mqtt_connection_collection_new_connection (
		struct rrr_mqtt_connection **connection,
		struct rrr_mqtt_connection_collection *connections,
		const struct ip_data *ip_data,
		const struct sockaddr *remote_addr,
		uint64_t close_wait_time_usec
);

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
// The iterator will temporarily obtain write lock when destroying a connection.

// One MUST NOT work with ANY connections outside iterator callback-context

// If it is wanted to only work with one single connection, one must create a custom
// callback function and a callback data structure to search for a specific connection
// and do something with it. It is then possible to detect if the connection
// actually did exist or if it was destroyed in the meantime before we called the
// iterator.

// Functions with connection/packet argument pair can be used as callback
// for the rrr_mqtt_connection_with_iterator_ctx_do-function.
int rrr_mqtt_connection_collection_iterate (
		struct rrr_mqtt_connection_collection *connections,
		int (*callback)(struct rrr_mqtt_connection *connection, void *callback_arg),
		void *callback_arg
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

//////////////////////////////////////////////////////////////////////////////////////////////////////
// The iterator_ctx-functions MUST also be used ONLY in iterator context. The connection lock
// AND packet lock (if packet argument present) MUST also be held when calling them.
//
// Functions with the connection/packet argument pair is also supported by the
// iterator_ctx_do-function which can use these as callbacks.
/////////////////////////////////////////////////////////////////////////////////////////////////////

/* To call the outbound packet function safely, we MUST first incref the packet as the FIFO buffer
 * upon errors immediately will decref the packet, and the lock would then be destroyed. It is also
 * possible that another thread reads from the buffer before we continue and decrefs the packet.
 * Caller needs to hold the packet data lock to call the iterator_ctx function, and it cannot be
 * unlocked again if the packet is destroyed. */
int rrr_mqtt_connection_iterator_ctx_check_finalize (
		struct rrr_mqtt_connection *connection
);
int rrr_mqtt_connection_iterator_ctx_parse (
		struct rrr_mqtt_connection *connection
);
int rrr_mqtt_connection_iterator_ctx_read (
		struct rrr_mqtt_connection *connection,
		int read_step_max_size
);
int rrr_mqtt_connection_iterator_ctx_housekeeping (
		struct rrr_mqtt_connection *connection,
		void *arg
);
int rrr_mqtt_connection_iterator_ctx_send_packet (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
);
int rrr_mqtt_connection_iterator_ctx_send_packets (
		struct rrr_mqtt_connection *connection
);
int rrr_mqtt_connection_iterator_ctx_queue_outbound_packet (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
);
int rrr_mqtt_connection_iterator_ctx_set_protocol_version_and_keep_alive (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
);

#define RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_IN	1
#define RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_OUT	2

int rrr_mqtt_connection_iterator_ctx_update_state (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet,
		int direction
);
int rrr_mqtt_connection_iterator_ctx_send_disconnect (
		struct rrr_mqtt_connection *connection,
		uint8_t reason
);

#endif /* RRR_MQTT_CONNECTION_H */
