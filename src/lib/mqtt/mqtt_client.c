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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"

#include "mqtt_client.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_transport.h"
#include "mqtt_subscription.h"
#include "mqtt_packet.h"
#include "mqtt_acl.h"

#include "../util/rrr_time.h"
#include "../util/posix.h"
#include "../util/macro_utils.h"

#define RRR_MQTT_CLIENT_MAX_IN_FLIGHT                   125
#define RRR_MQTT_CLIENT_COMPLETE_PUBLISH_GRACE_TIME_S     2
#define RRR_MQTT_CLIENT_SEND_DISCOURAGE_LIMIT          5000

struct set_connection_settings_callback_data {
	uint16_t keep_alive;
	const struct rrr_mqtt_p_protocol_version *protocol_version;
	struct rrr_mqtt_session *session;
	const char *username;
	const char *client_name;
};

static int __rrr_mqtt_client_connect_set_connection_settings(struct rrr_net_transport_handle *handle, void *arg) {
	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

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

	if (callback_data->client_name != NULL) {
		if ((ret = rrr_mqtt_conn_set_client_id (connection, callback_data->client_name)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_mqtt_client_exceeded_keep_alive_callback (struct rrr_net_transport_handle *handle, void *arg) {
	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_client_data *data = arg;

	struct rrr_mqtt_p_pingreq *pingreq = NULL;

	if (connection->protocol_version == NULL) {
		// CONNECT/CONNACK not yet done
		goto out;
	}

	pingreq = (struct rrr_mqtt_p_pingreq *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PINGREQ, connection->protocol_version);

	if (rrr_mqtt_conn_iterator_ctx_send_packet_urgent(handle, (struct rrr_mqtt_p *) pingreq) != 0) {
		RRR_MSG_0("Could not send PINGREQ packet in %s\n", __func__);
		ret = 1;
		goto out;
	}

	data->last_pingreq_time = rrr_time_get_64();

	out:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(pingreq);
		return ret;
}

struct rrr_mqtt_client_check_alive_callback_data {
	struct rrr_mqtt_client_data *data;
	int alive;
	int send_allowed;
	int close_wait;
};

static int __rrr_mqtt_client_connection_check_alive_callback (
		struct rrr_net_transport_handle *handle, 
		void *arg
) {
	struct rrr_mqtt_client_check_alive_callback_data *callback_data = arg;

	int ret = 0;

	if ((ret = rrr_mqtt_conn_iterator_ctx_check_alive (
			&callback_data->alive,
			&callback_data->send_allowed,
			&callback_data->close_wait,
			handle
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_mqtt_client_connection_check_alive (
		int *alive,
		int *send_allowed,
		int *close_wait,
		struct rrr_mqtt_client_data *data,
		int transport_handle
) {
	int ret = RRR_MQTT_OK;

	*alive = 0;
	*send_allowed = 0;
	*close_wait = 0;

	struct rrr_mqtt_client_check_alive_callback_data callback_data = {
		data,
		0,
		0,
		0
	};

	short handle_found = 0;
	if ((ret = rrr_mqtt_transport_with_iterator_ctx_do_custom (
			&handle_found,
			data->mqtt_data.transport,
			transport_handle,
			__rrr_mqtt_client_connection_check_alive_callback,
			&callback_data
	)) != RRR_MQTT_OK || !handle_found) {
		RRR_MSG_0("Internal error while checking keep-alive for connection in %s\n", __func__);
		goto out;
	}

	*alive = callback_data.alive;
	*send_allowed = callback_data.send_allowed;
	*close_wait = callback_data.close_wait;

	out:
	return ret;
}

void __rrr_mqtt_client_notify_tick (
		struct rrr_mqtt_client_data *data
) {
	rrr_mqtt_transport_notify_tick (data->mqtt_data.transport);
}

int rrr_mqtt_client_publish (
		int *send_discouraged,
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = 0;

	*send_discouraged = 0;

	rrr_length send_queue_count = 0;
	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->mqtt_data.sessions->methods->send_packet_queue (
					&send_queue_count,
					data->mqtt_data.sessions,
					session,
					(struct rrr_mqtt_p *) publish
			),
			goto out,
			" while queuing PUBLISH packet"
	);

	*send_discouraged = send_queue_count > RRR_MQTT_CLIENT_SEND_DISCOURAGE_LIMIT;

	__rrr_mqtt_client_notify_tick(data);

	out:
	return ret;
}

int rrr_mqtt_client_subscribe (
		struct rrr_mqtt_client_data *data,
		struct rrr_mqtt_session **session,
		const struct rrr_mqtt_subscription_collection *subscriptions
) {
	int ret = 0;

	if (rrr_mqtt_subscription_collection_count(subscriptions) == 0) {
		goto out;
	}

	if (data->protocol_version == NULL) {
		RRR_MSG_0("Protocol version not set in %s\n", __func__);
		ret = 1;
		goto out;
	}

	struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) rrr_mqtt_p_allocate(
			RRR_MQTT_P_TYPE_SUBSCRIBE,
			data->protocol_version
	);
	if (subscribe == NULL) {
		RRR_MSG_0("Could not allocate SUBSCRIBE message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
			subscribe->subscriptions,
			subscriptions,
			0,
			NULL,
			NULL
	) != 0) {
		RRR_MSG_0("Could not add subscriptions to SUBSCRIBE message in %s\n", __func__);
		goto out_decref;
	}

	rrr_length send_queue_count_dummy = 0;

	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->mqtt_data.sessions->methods->send_packet_queue (
					&send_queue_count_dummy,
					data->mqtt_data.sessions,
					session,
					(struct rrr_mqtt_p *) subscribe
			),
			goto out_decref,
			" while queuing SUBSCRIBE packet"
	);

	__rrr_mqtt_client_notify_tick(data);

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

	if (rrr_mqtt_subscription_collection_count(subscriptions) == 0) {
		goto out;
	}

	if (data->protocol_version == NULL) {
		RRR_MSG_0("Protocol version not set in %s\n", __func__);
		ret = 1;
		goto out;
	}

	struct rrr_mqtt_p_unsubscribe *unsubscribe = (struct rrr_mqtt_p_unsubscribe *) rrr_mqtt_p_allocate(
			RRR_MQTT_P_TYPE_UNSUBSCRIBE,
			data->protocol_version
	);
	if (unsubscribe == NULL) {
		RRR_MSG_0("Could not allocate UNSUBSCRIBE message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
			unsubscribe->subscriptions,
			subscriptions,
			0,
			NULL,
			NULL
	)) != 0) {
		RRR_MSG_0("Could not add subscriptions to UNSUBSCRIBE message in %s\n", __func__);
		goto out_decref;
	}

	rrr_length send_queue_count_dummy = 0;

	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->mqtt_data.sessions->methods->send_packet_queue (
					&send_queue_count_dummy,
					data->mqtt_data.sessions,
					session,
					(struct rrr_mqtt_p *) unsubscribe
			),
			goto out_decref,
			" while queuing UNSUBSCRIBE packet"
	);

	__rrr_mqtt_client_notify_tick(data);

	out_decref:
		RRR_MQTT_P_DECREF(unsubscribe);
	out:
		return (ret != 0);
}

void rrr_mqtt_client_close_all_connections (
		struct rrr_mqtt_client_data *data
) {
	rrr_mqtt_transport_cleanup(data->mqtt_data.transport);
}

struct rrr_mqtt_client_property_override {
	struct rrr_mqtt_property *property;
};

struct rrr_mqtt_client_disconnect_callback_data {
	uint8_t reason_v5;
};

int __rrr_mqtt_client_disconnect_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_mqtt_client_disconnect_callback_data *callback_data = arg;

	rrr_mqtt_conn_iterator_ctx_set_disconnect_reason (handle, callback_data->reason_v5);

	return RRR_NET_TRANSPORT_READ_READ_EOF;
}

int rrr_mqtt_client_disconnect (
		struct rrr_mqtt_client_data *data,
		int transport_handle,
		uint8_t reason_v5
) {
	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_client_disconnect_callback_data callback_data = {
		reason_v5
	};

	short handle_found = 0;
	if ((ret = rrr_mqtt_transport_with_iterator_ctx_do_custom (
			&handle_found,
			data->mqtt_data.transport,
			transport_handle,
			__rrr_mqtt_client_disconnect_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	// Return OK after connection is finally closed
	ret = handle_found ? RRR_MQTT_INCOMPLETE : RRR_MQTT_OK;

	out:
	return ret;
}

static int __rrr_mqtt_client_connect_set_will (
		struct rrr_mqtt_p_connect *connect,
		const char *will_topic,
		const struct rrr_nullsafe_str *will_message,
		uint8_t will_qos,
		uint8_t will_retain
) {
	int ret = 0;

	if (will_topic == NULL) {
		if (rrr_nullsafe_str_len(will_message) != 0) {
			RRR_BUG("BUG: Will topic was empty but will message was not in %s\n", __func__);
		}
		goto out;
	}

	if (*will_topic == '\0') {
		RRR_BUG("BUG: Will topic was empty in %s\n", __func__);
	}

	RRR_FREE_IF_NOT_NULL(connect->will_topic);
	if ((connect->will_topic = strdup(will_topic)) == NULL) {
		RRR_MSG_0("Failed to allocate will topic in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_nullsafe_str_new_or_replace (
			&connect->will_message,
			will_message
	)) != 0) {
		RRR_MSG_0("Failed to set will message in %s\n", __func__);
		goto out;
	}

	RRR_MQTT_P_CONNECT_SET_FLAG_WILL(connect);
	RRR_MQTT_P_CONNECT_SET_FLAG_WILL_QOS(connect,will_qos);

	if (will_retain) {
		RRR_MQTT_P_CONNECT_SET_FLAG_WILL_RETAIN(connect);
	}

	out:
	return ret;
}

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
) {
	struct rrr_mqtt_data *mqtt_data = &data->mqtt_data;

	int ret = 0;

	*transport_handle = 0;
	*session = NULL;

	struct rrr_mqtt_p_connect *connect = NULL;
	struct rrr_mqtt_session_properties session_properties_tmp = rrr_mqtt_common_default_session_properties;

	// Sleep a bit in case server runs in the same RRR program
	rrr_posix_usleep(500000); // 500ms

	if ((ret = rrr_mqtt_transport_connect (
			transport_handle,
			data->mqtt_data.transport,
			port,
			server,
			rrr_mqtt_conn_accept_and_connect_callback
	)) != 0) {
		RRR_DBG_1("Could not connect to mqtt server '%s'\n", server);
		goto out;
	}

	if (*transport_handle == 0) {
		RRR_DBG_1("Could not connect to mqtt server '%s'\n", server);
		ret = 1;
		goto out;
	}

	const struct rrr_mqtt_p_protocol_version *protocol_version = rrr_mqtt_p_get_protocol_version(version);
	if (protocol_version == NULL) {
		RRR_BUG("Invalid protocol version %u in %s\n", version, __func__);
	}

	connect = (struct rrr_mqtt_p_connect *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_CONNECT, protocol_version);

	if (data->mqtt_data.client_name != NULL && *(data->mqtt_data.client_name) != '\0') {
		if ((connect->client_identifier = rrr_strdup(data->mqtt_data.client_name)) == NULL) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}
	else {
		// Always set clean start if there is no client ID
		connect->connect_flags |= 1<<1;
	}

	if (clean_start) {
		RRR_MQTT_P_CONNECT_SET_FLAG_CLEAN_START(connect);
	}

	connect->keep_alive = keep_alive;

	if ((ret = __rrr_mqtt_client_connect_set_will (connect, will_topic, will_message, will_qos, will_retain)) != 0) {
		goto out;
	}

	if (username != NULL) {
		RRR_MQTT_P_CONNECT_SET_FLAG_USER_NAME(connect);
		if ((connect->username = rrr_strdup(username)) == NULL) {
			RRR_MSG_0("Could not allocate memory for username in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}
	if (password != NULL) {
		if (!RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(connect)) {
			RRR_BUG("BUG: Password given without username in %s\n", __func__);
		}
		RRR_MQTT_P_CONNECT_SET_FLAG_PASSWORD(connect);
		if ((connect->password = rrr_strdup(password)) == NULL) {
			RRR_MSG_0("Could not allocate memory for password in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if (rrr_mqtt_property_collection_add_from_collection(&connect->properties, connect_properties) != 0) {
		RRR_MSG_0("Could not add properties to CONNECT packet in %s\n", __func__);
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
			session_properties_tmp.numbers.session_expiry = 0xffffffff;

			if (rrr_mqtt_property_collection_add_uint32 (
					&connect->properties,
					RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL,
					session_properties_tmp.numbers.session_expiry
			) != 0) {
				RRR_MSG_0("Could not set session expiry for CONNECT packet in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
	}

	data->protocol_version = protocol_version;

	{
		struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
				RRR_MQTT_P_5_REASON_OK,
				&session_properties_tmp,
				{0}
		};

		// After adding properties to the CONNECT packet, read out all values and
		// update the session properties. This will fail if non-CONNECT properties
		// has been used.
		uint8_t reason_v5 = 0;
		RRR_MQTT_COMMON_HANDLE_PROPERTIES (
				&connect->properties,
				connect,
				rrr_mqtt_common_parse_connect_properties_callback,
				goto out
		);
	}

	short session_present_dummy = 0;
	if (mqtt_data->sessions->methods->get_session (
			session,
			mqtt_data->sessions,
			data->mqtt_data.client_name, // May be NULL
			&session_present_dummy,
			0 // no_creation: 0 means to create on non-existent client ID
	) != RRR_MQTT_SESSION_OK || *session == NULL) {
		ret = RRR_MQTT_INTERNAL_ERROR;
		RRR_MSG_0("Internal error while getting session in %s return was %i\n", __func__, ret);
		goto out;
	}

	if ((ret = rrr_mqtt_common_clear_session_from_connections (mqtt_data, *session, *transport_handle)) != 0) {
		RRR_MSG_0("Error while clearing session from old connections in %s return was %i\n", __func__, ret);
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	if ((ret = mqtt_data->sessions->methods->init_session (
			mqtt_data->sessions,
			session,
			&session_properties_tmp,
			mqtt_data->retry_interval_usec,
			RRR_MQTT_CLIENT_MAX_IN_FLIGHT,
			RRR_MQTT_CLIENT_COMPLETE_PUBLISH_GRACE_TIME_S,
			RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect)
	)) != RRR_MQTT_SESSION_OK) {
		if ((ret & RRR_MQTT_SESSION_DELETED) != 0) {
			RRR_MSG_0("New session was deleted in %s\n", __func__);
		}
		else {
			RRR_MSG_0("Error while initializing session in %s, return was %i\n", __func__, ret);
		}
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_transport_with_iterator_ctx_do_packet (
			data->mqtt_data.transport,
			*transport_handle,
			(struct rrr_mqtt_p *) connect,
			rrr_mqtt_conn_iterator_ctx_send_packet_urgent
	) != 0) {
		RRR_MSG_0("Could not send CONNECT packet in %s\n", __func__);
		ret = 1;
		goto out;
	}

	struct set_connection_settings_callback_data callback_data = {
		connect->keep_alive,
		connect->protocol_version,
		*session,
		username,
		mqtt_data->client_name
	};

	short handle_found = 0;
	if (rrr_mqtt_transport_with_iterator_ctx_do_custom (
			&handle_found,
			data->mqtt_data.transport,
			*transport_handle,
			__rrr_mqtt_client_connect_set_connection_settings,
			&callback_data
	) != 0 || !handle_found) {
		RRR_MSG_0("Could not set protocol version and keep alive from CONNECT packet\n");
		ret = 1;
		goto out;
	}

	out:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(connect);
		rrr_mqtt_session_properties_clear(&session_properties_tmp);
		return ret;
}

int rrr_mqtt_client_start (
		struct rrr_mqtt_client_data *data,
		const struct rrr_net_transport_config *net_transport_config
) {
	return rrr_mqtt_transport_start (
			data->mqtt_data.transport,
			net_transport_config,
			"MQTT client"
	);
}

static int __rrr_mqtt_client_handle_connack (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	struct rrr_mqtt_client_data *client_data = (struct rrr_mqtt_client_data *) mqtt_data;
	struct rrr_mqtt_p_connack *connack = (struct rrr_mqtt_p_connack *) packet;

	(void)(client_data);

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_session_properties session_properties_tmp = {0};

	char *client_id_tmp = NULL;

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
				" while cleaning session when handling CONNACK"
		);
	}

	if (connection->client_id == NULL || *(connection->client_id) == '\0') {
		struct rrr_mqtt_property *assigned_client_id_property = rrr_mqtt_property_collection_get_property (
				&connack->properties,
				RRR_MQTT_PROPERTY_ASSIGNED_CLIENT_ID,
				0
		);
		if (assigned_client_id_property != NULL) {
			if ((ret = rrr_mqtt_property_get_blob_as_str (
					&client_id_tmp,
					assigned_client_id_property
			)) != 0) {
				goto out;
			}
			if ((ret = rrr_mqtt_conn_set_client_id(connection, client_id_tmp)) != 0) {
				goto out;
			}
		}
	}

	uint8_t reason_v5 = 0;
	struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
			RRR_MQTT_P_5_REASON_OK,
			&session_properties_tmp,
			{0}
	};

	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&connack->properties,
			connack,
			rrr_mqtt_common_parse_connack_properties_callback,
			goto out
	);

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->update_properties(
					mqtt_data->sessions,
					&connection->session,
					&session_properties_tmp,
					&callback_data.found_number_properties,
					RRR_MQTT_P_IS_V5(connack)
			),
			goto out,
			" while resetting properties while handling CONNACK"
	);

	if (session_properties_tmp.numbers.server_keep_alive > 0) {
		if (session_properties_tmp.numbers.server_keep_alive > 0xffff) {
			RRR_BUG("Session server keep alive was >0xffff in %s\n", __func__);
		}
		if ((ret = rrr_mqtt_conn_set_data_from_connect_and_connack (
				connection,
				(uint16_t) session_properties_tmp.numbers.server_keep_alive,
				connack->protocol_version,
				connection->session,
				NULL // Don't reset username upon CONNACK, will cause corruption
		)) != 0 ) {
			RRR_MSG_0 ("Error while setting new keep-alive and username on connection in %s\n", __func__);
			goto out;
		}
	}

	RRR_DBG_1("Received CONNACK with keep-alive %u, now connected\n", session_properties_tmp.numbers.server_keep_alive);

	out:
		RRR_FREE_IF_NOT_NULL(client_id_tmp);
		rrr_mqtt_session_properties_clear(&session_properties_tmp);
		return ret;
}

static int __rrr_mqtt_client_handle_suback_unsuback (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	struct rrr_mqtt_client_data *client_data = (struct rrr_mqtt_client_data *) mqtt_data;

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

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
			RRR_MSG_0("Error from custom handler in %s\n", __func__);
			ret = RRR_MQTT_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

int __rrr_mqtt_client_handle_pingresp (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	(void)(mqtt_data);
	(void)(handle);
	(void)(packet);

	// Nothing to do

	return RRR_MQTT_OK;
}

static int __rrr_mqtt_client_handle_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	(void)(mqtt_data);

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) packet;

	return rrr_mqtt_common_update_conn_state_upon_disconnect(connection, disconnect);
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
	{__rrr_mqtt_client_handle_disconnect},
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
					RRR_MSG_0("Error %i from downstream handler in %s\n", ret, __func__);
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
	rrr_free(client);
}

static int __rrr_mqtt_client_iterate_and_clear_local_delivery (
		struct rrr_mqtt_client_data *data
) {
	return rrr_mqtt_common_iterate_and_clear_local_delivery (
			&data->mqtt_data,
			data->receive_publish_callback,
			data->receive_publish_callback_arg
	) & RRR_MQTT_INTERNAL_ERROR; // Clear all errors but internal error
}

static int __rrr_mqtt_client_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
) {
	struct rrr_mqtt_client_data *data = arg;

	int ret = 0;

	struct rrr_mqtt_session_iterate_send_queue_counters session_counters = {0};

	if ((ret = rrr_mqtt_common_read_parse_single_handle (
			&session_counters,
			&data->mqtt_data,
			handle,
			__rrr_mqtt_client_exceeded_keep_alive_callback,
			data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
	
static void __rrr_mqtt_client_publish_notify_callback (void *arg) {
	struct rrr_mqtt_client_data *data = arg;

	__rrr_mqtt_client_iterate_and_clear_local_delivery (data);
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
) {
	int ret = 0;

	struct rrr_mqtt_client_data *result = rrr_allocate(sizeof(*result));

	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset (result, '\0', sizeof(*result));

	ret = rrr_mqtt_common_data_init (
			&result->mqtt_data,
			handler_properties,
			init_data,
			queue,
			session_initializer,
			session_initializer_arg,
			__rrr_mqtt_client_event_handler,
			result,
			__rrr_mqtt_client_acl_handler,
			NULL,
			__rrr_mqtt_client_read_callback,
			result
	);

	if (ret != 0) {
		RRR_MSG_0("Could not initialize MQTT common data in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	result->last_pingreq_time = rrr_time_get_64();
	result->suback_unsuback_handler = suback_unsuback_handler;
	result->suback_unsuback_handler_arg = suback_unsuback_handler_arg;
	result->packet_parsed_handler = packet_parsed_handler;
	result->packet_parsed_handler_arg = packet_parsed_handler_arg;
	result->receive_publish_callback = receive_publish_callback;
	result->receive_publish_callback_arg = receive_publish_callback_arg;

	MQTT_COMMON_CALL_SESSION_REGISTER_CALLBACKS(&result->mqtt_data, __rrr_mqtt_client_publish_notify_callback, result);

	*client = result;

	goto out;
	out_free:
		rrr_free(result);
	out:
		return ret;
}

int rrr_mqtt_client_late_set_client_identifier (
		struct rrr_mqtt_client_data *client,
		const char *client_identifier
) {
	struct rrr_mqtt_data *data = &client->mqtt_data;
	if (data->client_name != NULL && strcmp(data->client_name, client_identifier) != 0) {
		RRR_DBG_1("MQTT client late change of client identifier from %s to %s\n",
				data->client_name, client_identifier);
	}
	else {
		RRR_DBG_1("MQTT client late set of client identifier to %s\n",
				client_identifier);
	}

	RRR_FREE_IF_NOT_NULL(data->client_name);

	if ((data->client_name = rrr_strdup(client_identifier)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return 1;
	}

	return 0;
}

struct get_session_properties_callback_data {
	struct rrr_mqtt_session_properties *target;
	struct rrr_mqtt_client_data *client;
};

int __rrr_mqtt_client_get_session_properties_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct get_session_properties_callback_data *callback_data = arg;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	return callback_data->client->mqtt_data.sessions->methods->get_properties (
			callback_data->target,
			callback_data->client->mqtt_data.sessions,
			&connection->session
	);
}

int rrr_mqtt_client_get_session_properties (
		struct rrr_mqtt_session_properties *target,
		struct rrr_mqtt_client_data *client,
		int transport_handle
) {
	struct get_session_properties_callback_data callback_data = {
			target,
			client
	};

	short handle_found = 0;
	return rrr_mqtt_transport_with_iterator_ctx_do_custom (
			&handle_found,
			client->mqtt_data.transport,
			transport_handle,
			__rrr_mqtt_client_get_session_properties_callback,
			&callback_data
	) != 0 && handle_found;
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
		RRR_MSG_0("Warning: Failed to get session stats in %s\n", __func__);
	}
}
