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

#include "mqtt_property.h"

// These headers for submodules should only include declaration of their new collection function
#include "mqtt_session_ram.h"

struct rrr_mqtt_p;
struct rrr_mqtt_p_publish;
struct rrr_mqtt_session_collection;
struct rrr_mqtt_session_collection_methods;
struct rrr_mqtt_subscription_collection;

// This struct should NOT contain ANY dynamically OR statically allocated data. The
// sessions are merely identified by their pointer value. The struct may be freed
// up at any time (but ONLY by the downstream session engine)
struct rrr_mqtt_session {
	char dummy;
};

struct rrr_mqtt_session_properties_numbers {
	uint32_t session_expiry;
	uint32_t receive_maximum;
	uint32_t maximum_qos;
	uint32_t retain_available;
	uint32_t maximum_packet_size;
	uint32_t wildcard_subscriptions_available;
	uint32_t subscription_identifiers_availbable;
	uint32_t shared_subscriptions_available;
	uint32_t server_keep_alive;
	uint32_t topic_alias_maximum;
	uint32_t request_response_information;
	uint32_t request_problem_information;
};

struct rrr_mqtt_session_properties {
	struct rrr_mqtt_session_properties_numbers numbers;
	struct rrr_mqtt_property_collection user_properties;

	struct rrr_mqtt_property *assigned_client_identifier;
	struct rrr_mqtt_property *reason_string;
	struct rrr_mqtt_property *response_information;
	struct rrr_mqtt_property *server_reference;
	struct rrr_mqtt_property *auth_method;
	struct rrr_mqtt_property *auth_data;
};

#define RRR_MQTT_SESSION_OK				0
#define RRR_MQTT_SESSION_INTERNAL_ERROR	(1<<0)
#define RRR_MQTT_SESSION_DELETED		(1<<1)
#define RRR_MQTT_SESSION_ERROR			(1<<2)

// Session collections may maintain a copy of this struct and copy it into
// the argument to get_stats() or maintain the numbers in some other fashion
// and fill the provided struct field by field
struct rrr_mqtt_session_collection_stats {
	uint64_t active;
	uint64_t total_created;
	uint64_t total_deleted;
	uint64_t total_publish_received;
	uint64_t total_publish_delivered;
	uint64_t total_publish_forwarded;
	uint64_t total_publish_not_forwarded;
	uint64_t in_memory_sessions;
};

// Note that numbers might be lower than actual numbers. When sent_counter
// reaches maximum allowed send per round, iteration may stop and counters
// will not get incremented. The buffer_size is however always the true
// value, and is safer to use when throttling.
struct rrr_mqtt_session_iterate_send_queue_counters {
	unsigned int maintain_deleted_counter;
	unsigned int maintain_ack_complete_counter;
	unsigned int maintain_ack_missing_counter;
	unsigned int incomplete_qos_publish_counter;
	unsigned int sent_counter;
	unsigned int buffer_size;
};

// Session engines must implement these methods
struct rrr_mqtt_session_collection_methods {
	// COLLECTION METHODS

	// Fill provided struct with statistics
	int (*get_stats) (
			struct rrr_mqtt_session_collection_stats *target,
			struct rrr_mqtt_session_collection *sessions
	);

	// Iterate local delivery queue (used by client). Packets are freed after
	// callback returns. To keep packets in client program, do an INCREF. All
	// packets are cleared from the buffer immediately.
	int (*iterate_and_clear_local_delivery) (
			struct rrr_mqtt_session_collection *sessions,
			int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
			void *callback_arg
	);

	// Insert a packet into the forward queue. Done currenty only by broker when publishing
	// will messages. If will delivery
	// interval is set in publish, it is put into will postpone queue. If not, it is
	// published immediately.
	int (*delivery_forward) (
			struct rrr_mqtt_session_collection *sessions,
			struct rrr_mqtt_p_publish *publish
	);

	// Destroy old sessions, read from send queue
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
			struct rrr_mqtt_session **session_to_find,
			const struct rrr_mqtt_session_properties *session_properties,
			uint64_t retry_interval_usec,
			uint32_t max_in_flight,
			uint32_t complete_publish_grace_time,
			int clean_session,
			int *session_was_present
	);

	// Clean a session, delete all packets
	int (*clean_session) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session
	);

	// Update properties for a session, usually after CONNACK
	int (*update_properties) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			const struct rrr_mqtt_session_properties *properties,
			const struct rrr_mqtt_session_properties_numbers *numbers_to_update,
			uint8_t is_v5
	);

	// Get session properties. Target is cleaned up before used.
	int (*get_properties) (
			struct rrr_mqtt_session_properties *target,
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session
	);

	// Called upon reception of ANY packet from the client
	int (*heartbeat) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session
	);

	// Iterate send queue of session. If force=1, return everything. If not,
	// return only non-sent and messages with exceeded retry interval.
	int (*iterate_send_queue) (
			struct rrr_mqtt_session_iterate_send_queue_counters *counters,
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session_to_find,
			int (*callback)(struct rrr_mqtt_p *packet, void *arg),
			void *callback_arg
	);

	// Act upon client disconnect event according to clean_session and
	// session expiry parameters
	int (*notify_disconnect) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			uint8_t reason_v5
	);

	int (*queue_packet) (
			rrr_length *total_send_queue_count,
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			struct rrr_mqtt_p *packet
	);

	int (*send_packet_now) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			struct rrr_mqtt_p *packet,
			int allow_missing_originating_packet,
			int (*send_now_callback)(struct rrr_mqtt_p *packet, void *arg),
			void *send_now_callback_arg
	);

	int (*receive_packet) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			struct rrr_mqtt_p *packet,
			unsigned int *ack_match_count
	);

	// Preserve memory of will publish message to allow use of pointer-matching
	// if a disconnected client reconnects and a postoned will publish must be
	// removed from queue.
	int (*register_will_publish) (
			struct rrr_mqtt_session_collection *collection,
			struct rrr_mqtt_session **session,
			struct rrr_mqtt_p_publish *publish
	);

	int (*unregister_will_publish) (
			struct rrr_mqtt_session_collection *sessions,
			struct rrr_mqtt_session **session
	);
};

#define RRR_MQTT_SESSION_COLLECTION_HEAD \
	const struct rrr_mqtt_session_collection_methods *methods

struct rrr_mqtt_session_collection {
	RRR_MQTT_SESSION_COLLECTION_HEAD;

	// Private data follows
};

void rrr_mqtt_session_properties_clear (
		struct rrr_mqtt_session_properties *target
);
int rrr_mqtt_session_properties_update (
		struct rrr_mqtt_session_properties *target,
		const struct rrr_mqtt_session_properties *source,
		const struct rrr_mqtt_session_properties_numbers *numbers_to_update
);
int rrr_mqtt_session_properties_clone (
		struct rrr_mqtt_session_properties *target,
		const struct rrr_mqtt_session_properties *source
);

// DO NOT use this function directly. Call the provided destroy()-method
void rrr_mqtt_session_collection_destroy (struct rrr_mqtt_session_collection *target);

int rrr_mqtt_session_collection_init (
		struct rrr_mqtt_session_collection *target,
		const struct rrr_mqtt_session_collection_methods *methods
);

#endif /* RRR_MQTT_SESSION_H */
