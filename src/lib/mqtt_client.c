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

#include <inttypes.h>
#include <stdlib.h>

#include "posix.h"
#include "log.h"
#include "mqtt_client.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_transport.h"
#include "mqtt_subscription.h"
#include "mqtt_packet.h"
#include "mqtt_acl.h"

struct set_connection_settings_callback_data {
	uint16_t keep_alive;
	const struct rrr_mqtt_p_protocol_version *protocol_version;
	struct rrr_mqtt_session *session;
	const char *username;
};

static int __rrr_mqtt_client_connect_set_connection_settings(struct rrr_net_transport_handle *handle, void *arg) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct set_connection_settings_callback_data *callback_data = arg;

	if ((ret = rrr_mqtt_conn_set_data_from_connect_and_connack (
			connection,
			callback_data->keep_alive,
			callback_data->protocol_version,
			callback_data->session,
			callback_data->username
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_mqtt_client_connection_check_alive (
		int *alive,
		int *send_allowed,
		struct rrr_mqtt_client_data *data,
		int transport_handle
) {
	int ret = RRR_MQTT_OK;

	*alive = 0;
	*send_allowed = 0;

	struct rrr_mqtt_conn_check_alive_callback_data callback_data = {
		0, 0
	};

	if (RRR_LL_COUNT(&data->mqtt_data.transport->transports) != 1) {
		RRR_BUG("BUG: Transport count was not exactly one in rrr_mqtt_client_connection_check_alive\n");
	}

	ret = rrr_mqtt_transport_with_iterator_ctx_do_custom (
			data->mqtt_data.transport,
			transport_handle,
			rrr_mqtt_conn_iterator_ctx_check_alive_callback,
			&callback_data
	);

	// Clear all errors (BUSY, SOFT ERROR) except INTERNAL ERROR
	ret = ret & RRR_MQTT_INTERNAL_ERROR;

	if (ret != RRR_MQTT_OK) {
		RRR_MSG_0("Internal error while checking keep-alive for connection in rrr_mqtt_check_alive\n");
		goto out;
	}

	*alive = callback_data.alive;
	*send_allowed = callback_data.send_allowed;

	out:
	return ret;
}

int rrr_mqtt_client_publish (
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = 0;

	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->mqtt_data.sessions->methods->send_packet (
					data->mqtt_data.sessions,
					session,
					(struct rrr_mqtt_p *) publish,
					0
			),
			goto out,
			" while sending PUBLISH packet in rrr_mqtt_client_publish\n"
	);

	out:
	return ret;
}

int rrr_mqtt_client_subscribe (
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		const struct rrr_mqtt_subscription_collection *subscriptions
) {
	int ret = 0;

	if ((ret = rrr_mqtt_subscription_collection_count(subscriptions)) == 0) {
//		VL_DEBUG_MSG_1("No subscriptions in rrr_mqtt_client_subscribe\n");
		goto out;
	}
	else if (ret < 0) {
		RRR_BUG("Unknown return value %i from rrr_mqtt_subscription_collection_count in rrr_mqtt_client_subscribe\n", ret);
	}
	ret = 0;

	if (data->protocol_version == NULL) {
		RRR_MSG_0("Protocol version not set in rrr_mqtt_client_send_subscriptions\n");
		ret = 1;
		goto out;
	}

	struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) rrr_mqtt_p_allocate(
			RRR_MQTT_P_TYPE_SUBSCRIBE,
			data->protocol_version
	);
	if (subscribe == NULL) {
		RRR_MSG_0("Could not allocate SUBSCRIBE message in rrr_mqtt_client_send_subscriptions\n");
		ret = 1;
		goto out;
	}

	RRR_MQTT_P_LOCK(subscribe);

	if (rrr_mqtt_subscription_collection_append_unique_copy_from_collection(subscribe->subscriptions, subscriptions, 0) != 0) {
		RRR_MSG_0("Could not add subscriptions to SUBSCRIBE message in rrr_mqtt_client_send_subscriptions\n");
		goto out_unlock;
	}

	RRR_MQTT_P_UNLOCK(subscribe);

	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->mqtt_data.sessions->methods->send_packet (
					data->mqtt_data.sessions,
					session,
					(struct rrr_mqtt_p *) subscribe,
					0
			),
			goto out_decref,
			" while sending SUBSCRIBE packet in rrr_mqtt_client_send_subscriptions\n"
	);

	goto out_decref;
	out_unlock:
		RRR_MQTT_P_UNLOCK(subscribe);
	out_decref:
		RRR_MQTT_P_DECREF(subscribe);
	out:
		return (ret != 0);
}

int rrr_mqtt_client_unsubscribe (
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		const struct rrr_mqtt_subscription_collection *subscriptions
) {
	int ret = 0;

	if ((ret = rrr_mqtt_subscription_collection_count(subscriptions)) == 0) {
//		VL_DEBUG_MSG_1("No subscriptions in rrr_mqtt_client_subscribe\n");
		goto out;
	}
	else if (ret < 0) {
		RRR_BUG("Unknown return value %i from rrr_mqtt_subscription_collection_count in rrr_mqtt_client_unsubscribe\n", ret);
	}
	ret = 0;

	if (data->protocol_version == NULL) {
		RRR_MSG_0("Protocol version not set in rrr_mqtt_client_unsubscribe\n");
		ret = 1;
		goto out;
	}

	struct rrr_mqtt_p_unsubscribe *unsubscribe = (struct rrr_mqtt_p_unsubscribe *) rrr_mqtt_p_allocate(
			RRR_MQTT_P_TYPE_UNSUBSCRIBE,
			data->protocol_version
	);
	if (unsubscribe == NULL) {
		RRR_MSG_0("Could not allocate UNSUBSCRIBE message in rrr_mqtt_client_unsubscribe\n");
		ret = 1;
		goto out;
	}

	RRR_MQTT_P_LOCK(unsubscribe);

	if (rrr_mqtt_subscription_collection_append_unique_copy_from_collection(unsubscribe->subscriptions, subscriptions, 0) != 0) {
		RRR_MSG_0("Could not add subscriptions to UNSUBSCRIBE message in rrr_mqtt_client_unsubscribe\n");
		goto out_unlock;
	}

	RRR_MQTT_P_UNLOCK(unsubscribe);

	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->mqtt_data.sessions->methods->send_packet (
					data->mqtt_data.sessions,
					session,
					(struct rrr_mqtt_p *) unsubscribe,
					0
			),
			goto out_decref,
			" while sending UNSUBSCRIBE packet in rrr_mqtt_client_unsubscribe\n"
	);

	goto out_decref;
	out_unlock:
		RRR_MQTT_P_UNLOCK(unsubscribe);
	out_decref:
		RRR_MQTT_P_DECREF(unsubscribe);
	out:
		return (ret != 0);
}

struct rrr_mqtt_client_property_override {
	struct rrr_mqtt_property *property;
};

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
		const struct rrr_mqtt_property_collection *connect_properties
) {
	int ret = 0;

	*transport_handle = 0;
	*session = NULL;

	struct rrr_mqtt_data *mqtt_data = &data->mqtt_data;

	struct rrr_mqtt_p_connect *connect = NULL;

	// Sleep a bit in case server runs in the same RRR program
	rrr_posix_usleep(500000); // 500ms

	if (rrr_mqtt_transport_connect (
			transport_handle,
			data->mqtt_data.transport,
			port,
			server,
			rrr_mqtt_conn_accept_and_connect_callback
	) != 0) {
		RRR_MSG_0("Could not connect to mqtt server '%s'\n", server);
		ret = 1;
		goto out_nolock;
	}

	if (*transport_handle == 0) {
		RRR_MSG_0("Could not connect to mqtt server '%s'\n", server);
		return 1;
	}

	const struct rrr_mqtt_p_protocol_version *protocol_version = rrr_mqtt_p_get_protocol_version(version);
	if (protocol_version == NULL) {
		RRR_BUG("Invalid protocol version %u in rrr_mqtt_client_connect\n", version);
	}

	connect = (struct rrr_mqtt_p_connect *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_CONNECT, protocol_version);
	RRR_MQTT_P_LOCK(connect);

	// TODO : Support zero-byte client identifier
	connect->client_identifier = malloc(strlen(data->mqtt_data.client_name) + 1);
	if (connect->client_identifier == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_client_connect\n");
		ret = 1;
		goto out;
	}
	strcpy(connect->client_identifier, data->mqtt_data.client_name);

	connect->keep_alive = keep_alive;
	connect->connect_flags |= (clean_start != 0)<<1;
	// Will QoS
	// connect->connect_flags |= 2 << 3;

	if (username != NULL) {
		if ((connect->username = strdup(username)) == NULL) {
			RRR_MSG_0("Could not allocate memory for username in rrr_mqtt_client_connect\n");
			ret = 1;
			goto out;
		}
	}
	if (password != NULL) {
		if ((connect->password = strdup(password)) == NULL) {
			RRR_MSG_0("Could not allocate memory for password in rrr_mqtt_client_connect\n");
			ret = 1;
			goto out;
		}
	}

	if (rrr_mqtt_property_collection_add_from_collection(&connect->properties, connect_properties) != 0) {
		RRR_MSG_0("Could not add properties to CONNECT packet in rrr_mqtt_client_connect\n");
		ret = 1;
		goto out;
	}

	if (version >= 5) {
		struct rrr_mqtt_property *session_expiry = rrr_mqtt_property_collection_get_property (
				&connect->properties,
				RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL,
				0
		);

		if (session_expiry == NULL) {
			// Default for version 3.1 is that sessions do not expire,
			// only use clean session to control this
			data->session_properties.session_expiry = 0xffffffff;

			if (rrr_mqtt_property_collection_add_uint32 (
					&connect->properties,
					RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL,
					data->session_properties.session_expiry
			) != 0) {
				RRR_MSG_0("Could not set session expiry for CONNECT packet in rrr_mqtt_client_connect\n");
				ret = 1;
				goto out;
			}
		}
	}

	data->protocol_version = protocol_version;
	data->session_properties = rrr_mqtt_common_default_session_properties;

	struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
			&connect->properties,
			RRR_MQTT_P_5_REASON_OK,
			&data->session_properties
	};

	// After adding properties to the CONNECT packet, read out all values and
	// update the session properties. This will fail if non-CONNECT properties
	// has been used.
	uint8_t reason_v5 = 0;
	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&connect->properties,
			connect,
			rrr_mqtt_common_handler_connect_handle_properties_callback,
			goto out
	);

	int session_present = 0;
	if ((ret = mqtt_data->sessions->methods->get_session (
			session,
			mqtt_data->sessions,
			connect->client_identifier,
			&session_present,
			0 // Create if non-existent client ID
	)) != RRR_MQTT_SESSION_OK || *session == NULL) {
		ret = RRR_MQTT_INTERNAL_ERROR;
		RRR_MSG_0("Internal error getting session in rrr_mqtt_client_connect\n");
		goto out;
	}

	if ((ret = rrr_mqtt_common_clear_session_from_connections (mqtt_data, *session, *transport_handle)) != 0) {
		RRR_MSG_0("Error while clearing session from old connections in rrr_mqtt_client_connect\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	if ((ret = mqtt_data->sessions->methods->init_session (
			mqtt_data->sessions,
			session,
			callback_data.session_properties,
			mqtt_data->retry_interval_usec,
			RRR_MQTT_CLIENT_MAX_IN_FLIGHT,
			RRR_MQTT_CLIENT_COMPLETE_PUBLISH_GRACE_TIME,
			RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect),
			1, // Local delivery (check received PUBLISH against subscriptions and deliver locally)
			&session_present
	)) != RRR_MQTT_SESSION_OK) {
		if ((ret & RRR_MQTT_SESSION_DELETED) != 0) {
			RRR_MSG_0("New session was deleted in rrr_mqtt_client_connect\n");
		}
		else {
			RRR_MSG_0("Error while initializing session in rrr_mqtt_client_connect, return was %i\n", ret);
		}
		ret = 1;
		goto out;
	}

	int connect_send_retry_attempts = 10;

	while (--connect_send_retry_attempts > 0) {
		if (rrr_mqtt_transport_with_iterator_ctx_do_packet (
				data->mqtt_data.transport,
				*transport_handle,
				(struct rrr_mqtt_p *) connect,
				rrr_mqtt_conn_iterator_ctx_send_packet
		) != 0) {
			RRR_MSG_0("Could not send CONNECT packet in rrr_mqtt_client_connect");
			ret = 1;
			goto out;
		}
		rrr_posix_usleep(200000); // 200ms

		// This is set to non-zero when the packet has actually been sent
		if (connect->last_attempt != 0) {
			break;
		}
	}

	if (connect->last_attempt == 0) {
		RRR_MSG_0("Could not send CONNECT packet in rrr_mqtt_client_connect after multiple attempts, giving up\n");
		ret = 1;
		goto out;
	}

	{
		struct set_connection_settings_callback_data callback_data = {
			connect->keep_alive,
			connect->protocol_version,
			*session,
			username
		};

		if (rrr_mqtt_transport_with_iterator_ctx_do_custom (
				data->mqtt_data.transport,
				*transport_handle,
				__rrr_mqtt_client_connect_set_connection_settings,
				&callback_data
		) != 0) {
			RRR_MSG_0("Could not set protocol version and keep alive from CONNECT packet in rrr_mqtt_client_connect");
			ret = 1;
			goto out;
		}
	}

	out:
		RRR_MQTT_P_UNLOCK(connect);
	out_nolock:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(connect);
		return ret;
}

int rrr_mqtt_client_start_plain (
		struct rrr_mqtt_client_data *data
) {
	return rrr_mqtt_transport_start_plain(data->mqtt_data.transport);
}

int rrr_mqtt_client_start_tls (
		struct rrr_mqtt_client_data *data,
		const char *certificate_file,
		const char *key_file,
		const char *ca_path
) {
	return rrr_mqtt_transport_start_tls (
			data->mqtt_data.transport,
			certificate_file,
			key_file,
			ca_path
	);
}

static int __rrr_mqtt_client_handle_connack (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_client_data *client_data = (struct rrr_mqtt_client_data *) mqtt_data;
	struct rrr_mqtt_p_connack *connack = (struct rrr_mqtt_p_connack *) packet;

	if (connack->reason_v5 != RRR_MQTT_P_5_REASON_OK) {
		RRR_MSG_0("CONNACK: Connection failed with reason '%s'\n", connack->reason->description);
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	rrr_mqtt_conn_update_state (connection, packet, RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_IN);

	if (connack->session_present == 0) {
		RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
				mqtt_data->sessions->methods->clean_session(mqtt_data->sessions, &connection->session),
				goto out,
				" while cleaning session in __rrr_mqtt_client_handle_connack"
		);
	}

	uint8_t reason_v5 = 0;
	struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
			&connack->properties,
			RRR_MQTT_P_5_REASON_OK,
			&client_data->session_properties
	};

	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&connack->properties,
			connack,
			rrr_mqtt_common_handler_connack_handle_properties_callback,
			goto out
	);

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->reset_properties(
					mqtt_data->sessions,
					&connection->session,
					&client_data->session_properties
			),
			goto out,
			" while resetting properties in __rrr_mqtt_client_handle_connack"
	);

	if (client_data->session_properties.server_keep_alive > 0) {
		if (client_data->session_properties.server_keep_alive > 0xffff) {
			RRR_BUG("Session server keep alive was >0xffff in __rrr_mqtt_client_handle_connack\n");
		}
		if ((ret = rrr_mqtt_conn_set_data_from_connect_and_connack (
				connection,
				client_data->session_properties.server_keep_alive,
				connack->protocol_version,
				connection->session,
				connection->username
		)) != 0 ) {
			RRR_MSG_0 ("Error while setting new keep-alive and username on connection in __rrr_mqtt_client_handle_connack\n");
			goto out;
		}
	}

	RRR_DBG_1("Received CONNACK with keep-alive %u, now connected\n", client_data->session_properties.server_keep_alive);

	out:
		return ret;
}

static int __rrr_mqtt_client_handle_suback_unsuback (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_client_data *client_data = (struct rrr_mqtt_client_data *) mqtt_data;

	unsigned int match_count = 0;
	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
		mqtt_data->sessions->methods->receive_packet (
					mqtt_data->sessions,
					&connection->session,
					packet,
					&match_count
			),
			goto out,
			" while handling SUBACK or UNSUBACK packet"
	);

	if (match_count == 0) {
		RRR_MSG_0("Received %s but did not find corresponding original packet, possible duplicate\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet));
		goto out;
	}

	if (client_data->suback_unsuback_handler != NULL) {
		if (client_data->suback_unsuback_handler(
				client_data,
				(struct rrr_mqtt_p_suback_unsuback *) packet,
				client_data->suback_unsuback_handler_arg
		) != 0) {
			RRR_MSG_0("Error from custom handler in __rrr_mqtt_client_handle_suback_unsuback\n");
			ret = RRR_MQTT_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

int __rrr_mqtt_client_handle_pingresp (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	unsigned int match_count = 0;
	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
		mqtt_data->sessions->methods->receive_packet (
					mqtt_data->sessions,
					&connection->session,
					packet,
					&match_count
			),
			goto out,
			" while handling PINGRESP packet"
	);

	if (match_count == 0) {
		RRR_DBG_1("Received PINGRESP with no matching PINGREQ\n");
	}

	out:
	return ret;
}

static const struct rrr_mqtt_type_handler_properties handler_properties[] = {
	{NULL},
	{NULL},
	{__rrr_mqtt_client_handle_connack},
	{rrr_mqtt_common_handle_publish},
	{rrr_mqtt_common_handle_puback_pubcomp},
	{rrr_mqtt_common_handle_pubrec},
	{rrr_mqtt_common_handle_pubrel},
	{rrr_mqtt_common_handle_puback_pubcomp},
	{NULL},
	{__rrr_mqtt_client_handle_suback_unsuback},
	{NULL},
	{__rrr_mqtt_client_handle_suback_unsuback},
	{NULL},
	{__rrr_mqtt_client_handle_pingresp},
	{rrr_mqtt_common_handle_disconnect},
	{NULL}
};

static int __rrr_mqtt_client_event_handler (
		struct rrr_mqtt_conn *connection,
		int event,
		void *static_arg,
		void *arg
) {
	struct rrr_mqtt_client_data *data = static_arg;

	(void)(connection);

	int ret = RRR_MQTT_OK;

	switch (event) {
		case RRR_MQTT_CONN_EVENT_PACKET_PARSED:
			// Arg is packet
			if (data->packet_parsed_handler != NULL) {
				if ((ret = data->packet_parsed_handler(data, arg, data->packet_parsed_handler_arg)) != 0) {
					RRR_MSG_0("Error %i from downstream handler in __rrr_mqtt_client_event_handler\n", ret);
				}
			}
			break;
		case RRR_MQTT_CONN_EVENT_DISCONNECT:
		default:
			break;
	};

	return ret;
}

static int __rrr_mqtt_client_acl_handler (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		void *arg
) {
	(void)(connection);
	(void)(packet);
	(void)(arg);
	return RRR_MQTT_ACL_RESULT_ALLOW;
}

void rrr_mqtt_client_destroy (struct rrr_mqtt_client_data *client) {
	rrr_mqtt_common_data_destroy(&client->mqtt_data);
	rrr_mqtt_session_properties_destroy(&client->session_properties);
	free(client);
}

void rrr_mqtt_client_notify_pthread_cancel (struct rrr_mqtt_client_data *client) {
	rrr_mqtt_common_data_notify_pthread_cancel(&client->mqtt_data);
}

int rrr_mqtt_client_new (
		struct rrr_mqtt_client_data **client,
		const struct rrr_mqtt_common_init_data *init_data,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*suback_unsuback_handler)(struct rrr_mqtt_client_data *data, struct rrr_mqtt_p_suback_unsuback *packet, void *private_arg),
		void *suback_unsuback_handler_arg,
		int (*packet_parsed_handler)(struct rrr_mqtt_client_data *data, struct rrr_mqtt_p *p, void *private_arg),
		void *packet_parsed_handler_arg
) {
	int ret = 0;

	struct rrr_mqtt_client_data *result = malloc(sizeof(*result));

	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_client_new\n");
		ret = 1;
		goto out;
	}

	memset (result, '\0', sizeof(*result));

	ret = rrr_mqtt_common_data_init (
			&result->mqtt_data,
			handler_properties,
			init_data,
			session_initializer,
			session_initializer_arg,
			__rrr_mqtt_client_event_handler,
			result,
			__rrr_mqtt_client_acl_handler,
			NULL
	);

	if (ret != 0) {
		RRR_MSG_0("Could not initialize MQTT common data in rrr_mqtt_client_new\n");
		ret = 1;
		goto out_free;
	}

	result->last_pingreq_time = rrr_time_get_64();
	result->suback_unsuback_handler = suback_unsuback_handler;
	result->suback_unsuback_handler_arg = suback_unsuback_handler_arg;
	result->packet_parsed_handler = packet_parsed_handler;
	result->packet_parsed_handler_arg = packet_parsed_handler_arg;

	*client = result;

	goto out;
	out_free:
		free(result);
	out:
		return ret;
}

struct exceeded_keep_alive_callback_data {
	struct rrr_mqtt_client_data *data;
};

static int __rrr_mqtt_client_exceeded_keep_alive_callback (struct rrr_mqtt_conn *connection, void *arg) {
	int ret = RRR_MQTT_OK;

	struct exceeded_keep_alive_callback_data *callback_data = arg;
	struct rrr_mqtt_client_data *data = callback_data->data;

	struct rrr_mqtt_p_pingreq *pingreq = NULL;

	if (connection->protocol_version == NULL) {
		// CONNECT/CONNACK not yet done
		goto out;
	}

	if (connection->keep_alive * 1000 * 1000 + data->last_pingreq_time > rrr_time_get_64()) {
		goto out;
	}

	pingreq = (struct rrr_mqtt_p_pingreq *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PINGREQ, connection->protocol_version);

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			data->mqtt_data.sessions->methods->send_packet(
					data->mqtt_data.sessions,
					&connection->session,
					(struct rrr_mqtt_p *) pingreq,
					0
			),
			goto out,
			" while sending PINGREQ in __rrr_mqtt_client_exceeded_keep_alive_callback"
	);

	data->last_pingreq_time = rrr_time_get_64();

	out:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(pingreq);
		return ret;
}

int rrr_mqtt_client_synchronized_tick (struct rrr_mqtt_client_data *data) {
	int ret = 0;

	struct exceeded_keep_alive_callback_data callback_data = {
			data
	};

	if ((ret = rrr_mqtt_common_read_parse_handle (
			&data->mqtt_data,
			__rrr_mqtt_client_exceeded_keep_alive_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	if ((ret = data->mqtt_data.sessions->methods->maintain (
			data->mqtt_data.sessions
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_mqtt_client_iterate_and_clear_local_delivery (
		struct rrr_mqtt_client_data *data,
		int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *callback_arg
) {
	return rrr_mqtt_common_iterate_and_clear_local_delivery (
			&data->mqtt_data,
			callback,
			callback_arg
	) & 1; // Clear all errors but internal error
}

void rrr_mqtt_client_get_stats (
		struct rrr_mqtt_client_stats *target,
		struct rrr_mqtt_client_data *data
) {
	memset(target, '\0', sizeof(*target));

	if (data->mqtt_data.sessions->methods->get_stats (
			&target->session_stats,
			data->mqtt_data.sessions
	) != 0) {
		RRR_MSG_0("Warning: Failed to get session stats in rrr_mqtt_client_get_stats\n");
	}
}
