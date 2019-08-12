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


#ifndef RRR_MQTT_SESSION_H
#define RRR_MQTT_SESSION_H

#include <inttypes.h>

struct rrr_mqtt_p_packet;

// This struct should NOT contain ANY dynamically OR statically allocated data. The
// sessions are merely identified by their pointer value. The struct may be freed
// up at any time (but ONLY by the downstream session engine)
struct rrr_mqtt_session {
	char dummy;
};

#define RRR_MQTT_SESSION_OK				0
#define RRR_MQTT_SESSION_INTERNAL_ERROR	(1<<0)
#define RRR_MQTT_SESSION_DELETED		(1<<1)
#define RRR_MQTT_SESSION_ERROR			(1<<2)

// Session engines must implement these methods
struct rrr_mqtt_session_collection_methods {
	// COLLECTION METHODS

	// Destroy old sessions, read from ACK queue
	int (*maintain) (
			struct rrr_mqtt_session_collection *
	);

	// Destroy collection, only on program exit
	void (*destroy) (
			struct rrr_mqtt_session_collection *
	);

	// Get a new or old session based on client id. If an old session
	// was used, session_present is set to 1
	int (*get_session) (
			struct rrr_mqtt_session **target,
			struct rrr_mqtt_session_collection *collection,
			const char *client_id,
			int *session_present,
			int no_creation
	);

	// SESSION METHODS

	// All these methods take a double pointer as argument. A session can become deleted at any time, and
	// the caller must check for this by checking whether the session was set to NULL or not. The downstream
	// session engine will also return RRR_MQTT_SESSION_DELETED if deletion occurs. If a connection uses this
	// deleted session, it should be closed.

	// If the function returns RRR_MQTT_SESSION_INTERNAL_ERROR, a bad error has happened and the program must
	// be stopped.

	// The callers need not to check whether the session still exists, the downstream session engine will do
	// that and return RRR_MQTT_SESSION_DELETED if the pointer can't be used.

	// Initialize a session based on the clean_session value
	int (*init_session) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			uint32_t session_expiry,
			uint32_t retry_interval,
			uint32_t max_in_flight,
			int clean_session,
			int *session_was_present
	);

	// Called upon reception of ANY packet from the client
	int (*heartbeat) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session
	);

	// Save a packet for which we should receive an ACK.
	// NOTICE : The downstream session engine will decrement the reference count when
	//          the packet is processed. For a RAM engine, it will be decremented when
	//          an ACK is received and the packet is removed from the send queue. For a
	//          database engine, the refcount will be decremented immediately. If the caller
	//          is to keep the packet, the reference count must be incremented prior to calling
	//          this function.
	int (*push_send_queue) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			struct rrr_mqtt_p_packet *packet
	);

	// Receive an ACK for a packet and remove it from the send queue.
	// The ACK is not stored in the session, no reference counting is performed.
	int (*process_ack) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			struct rrr_mqtt_p_packet *packet
	);

	// Iterate send queue and call callback for messages with retry interval exceeded.
	// If force is 1, callback receives all packets.
	int (*iterate_retries) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			int (*callback)(struct rrr_mqtt_p_packet *packet, void *arg),
			void *callback_arg,
			int force
	);

	// Act upon client disconnect event according to clean_session parameter
	int (*notify_disconnect) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session
	);
};

struct rrr_mqtt_session_collection {
	// Data pointer for downstream session engine
	void *private_data;

	const struct rrr_mqtt_session_collection_methods *methods;
};

// DO NOT use this function directly. Call the provided destroy()-method
void rrr_mqtt_session_collection_destroy (struct rrr_mqtt_session_collection *target);

int rrr_mqtt_session_collection_new (
		struct rrr_mqtt_session_collection **target,
		const struct rrr_mqtt_session_collection_methods *methods
);

#endif /* RRR_MQTT_SESSION_H */
