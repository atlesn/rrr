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

#ifndef RRR_MQTT_BROKER_H
#define RRR_MQTT_BROKER_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <pthread.h>

#include "ip.h"
#include "mqtt_common.h"
#include "linked_list.h"

#define RRR_MQTT_BROKER_CLIENT_PREFIX "mqtt-client-"
#define RRR_MQTT_BROKER_MAX_GENERATED_CLIENT_IDS 65535

#define RRR_MQTT_BROKER_MAX_IN_FLIGHT 	10
#define RRR_MQTT_BROKER_COMPLETE_PUBLISH_GRACE_TIME 10

struct rrr_mqtt_acl;
struct rrr_net_transport;

struct rrr_mqtt_broker_stats {
	uint64_t connections_active;
	uint64_t total_connections_accepted;
	uint64_t total_connections_closed;

	struct rrr_mqtt_session_collection_stats session_stats;
};

struct rrr_mqtt_broker_data {
	/* MUST be first */
	struct rrr_mqtt_data mqtt_data;

	int max_clients;
	uint16_t max_keep_alive;

	pthread_mutex_t client_serial_stats_lock;
	uint32_t client_serial;
	int client_count;
	struct rrr_mqtt_broker_stats stats;

	int disallow_anonymous_logins;
	int disconnect_on_v31_publish_deny;

	const char *password_file;
	const char *permission_name;
	const struct rrr_mqtt_acl *acl;
};

#define RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO(action)				\
	pthread_mutex_lock(&data->client_serial_stats_lock);		\
	action;														\
	pthread_mutex_unlock(&data->client_serial_stats_lock)

int rrr_mqtt_broker_accept_connections (
		struct rrr_mqtt_broker_data *data,
		int listen_handle
);
void rrr_mqtt_broker_destroy (struct rrr_mqtt_broker_data *broker);
static inline void rrr_mqtt_broker_destroy_void (void *broker) {
	rrr_mqtt_broker_destroy (broker);
}
void rrr_mqtt_broker_notify_pthread_cancel (struct rrr_mqtt_broker_data *broker);
static inline void rrr_mqtt_broker_notify_pthread_cancel_void (void *broker) {
	rrr_mqtt_broker_notify_pthread_cancel(broker);
}
int rrr_mqtt_broker_new (
		struct rrr_mqtt_broker_data **broker,
		const struct rrr_mqtt_common_init_data *init_data,
		uint16_t max_keep_alive,
		const char *password_file,
		const char *permission_name,
		const struct rrr_mqtt_acl *acl,
		int disallow_anonymous_logins,
		int disconnect_on_v31_publish_deny,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg
);
int rrr_mqtt_broker_listen_ipv4_and_ipv6_tls (
		int *listen_handle,
		struct rrr_mqtt_broker_data *broker,
		int port,
		const char *certificate_file,
		const char *key_file,
		const char *ca_file,
		const char *ca_path
);
int rrr_mqtt_broker_listen_ipv4_and_ipv6_plain (
		int *listen_handle,
		struct rrr_mqtt_broker_data *broker,
		int port
);

/* Run all tasks in sequence, simply call repeatedly for non-threaded operation */
int rrr_mqtt_broker_synchronized_tick (
		int *something_happened,
		struct rrr_mqtt_broker_data *data,
		int listen_handle
);

void rrr_mqtt_broker_get_stats (
		struct rrr_mqtt_broker_stats *target,
		struct rrr_mqtt_broker_data *data
);

#endif /* RRR_MQTT_BROKER_H */
