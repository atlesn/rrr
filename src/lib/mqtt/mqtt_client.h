/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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

#include <inttypes.h>

#include "mqtt_common.h"

struct rrr_event_queue;
struct rrr_mqtt_session_collection;
struct rrr_mqtt_p_suback_unsuback;
struct rrr_net_transport_config;

struct rrr_mqtt_client_stats {
	struct rrr_mqtt_session_collection_stats session_stats;
};

struct rrr_mqtt_client_data {
	/* MUST be first */
	struct rrr_mqtt_data mqtt_data;

//	struct rrr_mqtt_session_properties session_properties;
	ssize_t connection_count;
	uint64_t last_pingreq_time;
	const struct rrr_mqtt_p_protocol_version *protocol_version;
	int (*suback_unsuback_handler)(struct rrr_mqtt_client_data *data, struct rrr_mqtt_p_suback_unsuback *packet, void *private_arg);
	void *suback_unsuback_handler_arg;
	int (*packet_parsed_handler)(struct rrr_mqtt_client_data *data, struct rrr_mqtt_p *p, void *private_arg);
	void *packet_parsed_handler_arg;
	void (*receive_publish_callback)(struct rrr_mqtt_p_publish *publish, void *arg);
	void *receive_publish_callback_arg;
};

/* To start a client, connect, publish and subscribe:

 * Steps prefixed with I are outside event loop, and steps with E are while event loop is running.

 * I 1a. Initialize rrr_mqtt_common_init_data struct (client identifier and misc. timers)
 * I 1b. Initialize event framework
 * I 1c. rrr_mqtt_client_new, pass initialized structs and packet callbacks (see separate callback section)
 
 * I 2a. Initialize net transport struct rrr_net_transport_config_parse (set PLAIN or TLS mod)
 * I 2c. rrr_mqtt_client_start
 
 * I 3a. Prepare connect property collection (irrelevant for v3, can be set to zeros for v5 if no properties are used)
 * I 3b. rrr_mqtt_client_connect
 
 * I 4a. Start event dispatching
 * E 4b. Using a periodic event, wait for positive result from rrr_mqtt_client_connection_check_alive (alive and
         send_allowed set)
 * E 4c. Regularely check rrr_mqtt_client_connection_check_alive
 
 * If subscribing:
 * E 5a. Prepare subscription collection rrr_mqtt_subscription_collection_new + rrr_mqtt_subscription_collection_push_unique_str
 * E 5b. Subscribe with rrr_mqtt_client_subscribe
 
 * If unsubscribing:
 * E 5a. Prepare subscription collection rrr_mqtt_subscription_collection_new + rrr_mqtt_subscription_collection_push_unique_str
 * E 5b. Unsubscribe with rrr_mqtt_client_subscribe
 
 * If publishing:
 * E 6a. Allocate rrr_mqtt_p_publish using rrr_mqtt_p_allocate
 * E 6b. Set topic in publish topic field using allocation function
 * E 6c. Optionally set QoS using RRR_MQTT_P_PUBLISH_SET_FLAG_QOS
 * E 6d. Optionally set retain using RRR_MQTT_P_PUBLISH_SET_FLAG_RETAIN
 * E 6e. Optionally create payload using rrr_mqtt_p_payload_new + rrr_mqtt_p_payload_set_data or
         rrr_mqtt_p_payload_new_with_allocated_payload. Set payload field of publish to the new payload.
 * E 6f. Send publish using rrr_mqtt_client_publish, optionally handle returned send_discouraged value.
 * E 6g. Decref the publish __IMMEDIATELY__ and __DO NOT__ re-use it both upon successful and erronous
         publish using RRR_MQTT_P_DECREF_IF_NOT_NULL. Any payload and topic set in the struct MUST NEVER be
	 freed, this is handled when the publish is destroyed.

 * When disconnecting (politely):
 * E 7a. Disconnect using rrr_mqtt_client_disconnect
 * E 7b. Wait for rrr_mqtt_client_connection_check_alive to return false alive and false close_wait
 * (Go to 3b to reconnect)

 * Cleaning up:
 * I 8a. rrr_mqtt_client_destroy
 * I 8b. Destroy any subscription collections rrr_mqtt_subscription_collection_destroy
 * I 8c. Clear any property collection rrr_mqtt_property_collection_destroy
 * I 8d. Cleanup net transport config

* Callbacks:

XX Received packets in callbacks MUST NOT be decref'ed and the MUST NOT be re-used after callback has completed. XX

* process_suback_unsuback
  - Broker sends ACK after subscribing and unsubscribing
  - Check for packet type RRR_MQTT_P_TYPE_SUBACK or RRR_MQTT_P_TYPE_UNSUBACK
  - Number of acknowledgements in packet->acknowledgements_size and original subscription collection accessible
    in packet->orig_sub_usub->subscriptions. Double check ACK count against rrr_mqtt_subscription_collection_count
    of original collection.
  - Acknowledgements with QoS or version 5 reason in array packet->acknowledgements in the same order as original
    subscription collection.
  - Verify subscriptions
  - Received packets MUST NOT be stored
  
* process_parsed_packet
  - Possibly check for PUBACK and PUBREC packets indicating rejected PUBLISH (reason macro RRR_MQTT_P_GET_REASON_V5
    used for both V3 and V5).
  - Received packets MUST NOT be stored

* process_publish
  - Handle a PUBLISH received when subscribing.
  - Publishes may be cloned using rrr_mqtt_p_clone_publish if they are to be published later (ref. 6f) or used in some other way.

*/

int rrr_mqtt_client_connection_check_alive (
		int *alive,
		int *send_allowed,
		int *close_wait,
		struct rrr_mqtt_client_data *data,
		int transport_handle
);
int rrr_mqtt_client_publish (
		int *send_discouraged,
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		struct rrr_mqtt_p_publish *publish
);
int rrr_mqtt_client_subscribe (
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		const struct rrr_mqtt_subscription_collection *subscriptions
);
int rrr_mqtt_client_unsubscribe (
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		const struct rrr_mqtt_subscription_collection *subscriptions
);
void rrr_mqtt_client_close_all_connections (
		struct rrr_mqtt_client_data *data
);
int rrr_mqtt_client_disconnect (
		struct rrr_mqtt_client_data *data,
		int transport_handle,
		uint8_t reason_v5
);
int rrr_mqtt_client_connect (
		int *transport_handle,
		struct rrr_mqtt_session **session,
		struct rrr_mqtt_client_data *data,
		const char *server,
		uint16_t port,
		uint8_t version,
		uint16_t keep_alive,
		uint8_t clean_start,
		const char *username,
		const char *password,
		const struct rrr_mqtt_property_collection *connect_properties,
		const char *will_topic,
		const struct rrr_nullsafe_str *will_message,
		uint8_t will_qos,
		uint8_t will_retain
);
int rrr_mqtt_client_start (
		struct rrr_mqtt_client_data *data,
		const struct rrr_net_transport_config *net_transport_config
);
void rrr_mqtt_client_destroy (struct rrr_mqtt_client_data *client);
static inline void rrr_mqtt_client_destroy_void (void *client) {
	rrr_mqtt_client_destroy(client);
}
int rrr_mqtt_client_new (
		struct rrr_mqtt_client_data **client,
		const struct rrr_mqtt_common_init_data *init_data,
		struct rrr_event_queue *queue,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*suback_unsuback_handler)(struct rrr_mqtt_client_data *data, struct rrr_mqtt_p_suback_unsuback *packet, void *private_arg),
		void *suback_unsuback_handler_arg,
		int (*packet_parsed_handler)(struct rrr_mqtt_client_data *data, struct rrr_mqtt_p *p, void *private_arg),
		void *packet_parsed_handler_arg,
		void (*receive_publish_callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *receive_publish_callback_arg
);
int rrr_mqtt_client_late_set_client_identifier (
		struct rrr_mqtt_client_data *client,
		const char *client_identifier
);
int rrr_mqtt_client_get_session_properties (
		struct rrr_mqtt_session_properties *target,
		struct rrr_mqtt_client_data *client,
		int transport_handle
);
int rrr_mqtt_client_iterate_and_clear_local_delivery (
		struct rrr_mqtt_client_data *data,
		int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *callback_arg
);

void rrr_mqtt_client_get_stats (
		struct rrr_mqtt_client_stats *target,
		struct rrr_mqtt_client_data *data
);

#endif /* RRR_MQTT_CLIENT_H */
