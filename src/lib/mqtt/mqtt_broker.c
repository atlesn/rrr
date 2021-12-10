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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"

#include "mqtt_common.h"
#include "mqtt_broker.h"
#include "mqtt_session.h"
#include "mqtt_property.h"
#include "mqtt_acl.h"
#include "mqtt_subscription.h"
#include "mqtt_topic.h"
#include "mqtt_transport.h"
#include "mqtt_connection.h"
#include "mqtt_packet.h"

#include "../net_transport/net_transport.h"
#include "../passwd.h"
#include "../util/linked_list.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"

#define RRR_MQTT_BROKER_CLIENT_PREFIX "mqtt-client-"
#define RRR_MQTT_BROKER_MAX_GENERATED_CLIENT_IDS 65535

#define RRR_MQTT_BROKER_MAX_IN_FLIGHT 	125
#define RRR_MQTT_BROKER_COMPLETE_PUBLISH_GRACE_TIME_S 2

void __rrr_mqtt_broker_listen_ipv4_and_ipv6_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	(void)(handle);
	(void)(arg);
	// Nothing to do
}

static int __rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		struct rrr_net_transport *transport,
		uint16_t port
) {
	int ret = RRR_MQTT_OK;

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			transport,
			port,
			__rrr_mqtt_broker_listen_ipv4_and_ipv6_callback,
			NULL
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		struct rrr_mqtt_broker_data *broker,
		const struct rrr_net_transport_config *net_transport_config,
		uint16_t port
) {
	int ret = RRR_MQTT_OK;

	// TODO : For multiple ports, transport may be re-used

	if ((ret = rrr_mqtt_transport_start (
			broker->mqtt_data.transport,
			net_transport_config,
			"MQTT broker"
	)) != 0) {
		RRR_MSG_0("Could not start MQTT transport in %s return was %i\n", __func__, ret);
		goto out;
	}

	if ((ret = __rrr_mqtt_broker_listen_ipv4_and_ipv6 (
			rrr_mqtt_transport_get_latest(broker->mqtt_data.transport),
			port
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct validate_client_id_callback_data {
	const struct rrr_mqtt_conn *orig_connection;
	const char *client_id;
	short do_disconnect_other_client;
	short client_name_was_taken;
	short other_client_was_disconnected;
};

static int __rrr_mqtt_broker_check_unique_client_id_callback (struct rrr_net_transport_handle *handle, void *arg) {
	struct validate_client_id_callback_data *callback_data = arg;

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK_NO_ERROR;

	if ( callback_data->orig_connection == connection ||                // Don't validate ourselves (would have been stupid)
	    !RRR_MQTT_CONN_STATE_SEND_IS_BUSY_CLIENT_ID(connection) ||      // Equal name with a CLOSED connection is OK
	     connection->client_id == NULL ||                               // client_id is not set in the connection until CONNECT packet is handled
	     strcmp(connection->client_id, callback_data->client_id) != 0
	) {
		goto out;
	}

	callback_data->client_name_was_taken = 1;

	if (!callback_data->do_disconnect_other_client) {
		goto out;
	}

	RRR_DBG_2("Disconnecting existing client with client ID %s\n", connection->client_id);

	RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, RRR_MQTT_P_5_REASON_SESSION_TAKEN_OVER);

	// On soft error, we cannot be sure that the existing client was actually
	// disconnected, and we must disallow the new connection
	if ((ret = rrr_mqtt_conn_iterator_ctx_send_disconnect(handle)) != 0) {
		if (ret & RRR_MQTT_SOFT_ERROR) {
			RRR_MSG_0("Soft error while disconnecting existing client in %s\n", __func__);
		}
		if (ret & RRR_MQTT_INTERNAL_ERROR) {
			RRR_MSG_0("Internal error while disconnecting existing client in %s\n", __func__);
			ret = RRR_MQTT_INTERNAL_ERROR;
		}
		goto out;
	}

	callback_data->other_client_was_disconnected = 1;

	out:
	// DO NOT return anything else but OK and internal error as this might
	// cause the connection to become destroyed in the net transport loop. The
	// connection is being used by client id generator.
	return ((ret & RRR_MQTT_INTERNAL_ERROR) == RRR_MQTT_INTERNAL_ERROR
			? RRR_NET_TRANSPORT_READ_HARD_ERROR
			: RRR_NET_TRANSPORT_READ_OK
	);
}

static int __rrr_mqtt_broker_check_unique_client_id (
		short *client_name_was_taken,
		short *other_client_was_disconnected,
		const char *client_id,
		const struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *broker,
		short disconnect_other_client
) {
	int ret = RRR_MQTT_OK;

	*client_name_was_taken = 0;
	*other_client_was_disconnected = 0;

	struct validate_client_id_callback_data callback_data = {
			connection,
			client_id,
			disconnect_other_client,
			0,
			0
	};

	if ((ret = rrr_mqtt_transport_iterate (
			broker->mqtt_data.transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_mqtt_broker_check_unique_client_id_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Internal error while checking for unique client ID %s, server must stop.\n", client_id);
		goto out;
	}

	*client_name_was_taken = callback_data.client_name_was_taken;
	*other_client_was_disconnected = callback_data.other_client_was_disconnected;

	if (callback_data.client_name_was_taken && callback_data.do_disconnect_other_client) {
		if (callback_data.other_client_was_disconnected) {
			RRR_DBG_2("Client id %s was already used in an active connection, the old one was disconnected\n", client_id);
		}
		else {
			RRR_DBG_2("Client id %s was already used in an active connection but disconnection of this client possibly failed, new connection must be rejected\n", client_id);
			ret = RRR_MQTT_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_mqtt_broker_generate_unique_client_id (
		char **final_result,
		const struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *broker
) {
	int ret = RRR_MQTT_OK;
	uint32_t serial = 0;
	char *result = NULL;

	*final_result = NULL;

	int retries = RRR_MQTT_BROKER_MAX_GENERATED_CLIENT_IDS;
	while (--retries >= 0) {
		// We let the serial overflow
		serial = ++(broker->client_serial);

		RRR_FREE_IF_NOT_NULL(result);

		if (rrr_asprintf(&result, RRR_MQTT_BROKER_CLIENT_PREFIX "%u", serial) < 0) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			ret = RRR_MQTT_INTERNAL_ERROR;
			goto out;
		}

		short client_name_was_taken = 0;
		short other_client_was_disconnected_dummy = 0;

		ret = __rrr_mqtt_broker_check_unique_client_id (
				&client_name_was_taken,
				&other_client_was_disconnected_dummy,
				result,
				connection,
				broker,
				0 // = do not disconnect other client with equal name
		);

		if (other_client_was_disconnected_dummy != 0) {
			RRR_BUG("Dummy was not 0 in %s\n", __func__);
		}

		if (ret != 0) {
			RRR_MSG_0("Error while validating client ID in %s return was %i\n", __func__, ret);
			goto out;
		}

		if (!client_name_was_taken) {
			break;
		}
	}

	if (retries <= 0) {
		RRR_MSG_0("Number of generated client IDs reached maximum in %s\n", __func__);
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	*final_result = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

static int __rrr_mqtt_broker_new_will_publish (
		uint8_t *reason_v5,
		struct rrr_mqtt_p_publish **result,
		struct rrr_mqtt_common_will_properties *will_properties,
		const char *client_id,
		const struct rrr_mqtt_p_connect *connect
) {
	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_p_publish *publish = NULL;

	struct rrr_mqtt_common_parse_will_properties_callback_data callback_data = {
			0,
			will_properties
	};

	if ((ret = rrr_mqtt_property_collection_iterate (
			&connect->will_properties,
			rrr_mqtt_common_parse_will_properties_callback,
			&callback_data
	)) != 0) {
		*reason_v5 = callback_data.reason_v5;
		if (ret != RRR_MQTT_SOFT_ERROR) {
			RRR_MSG_0("Hard error while iterating will properties in %s\n", __func__);
		}
		goto out;
	}

	if (rrr_mqtt_p_new_publish (
			&publish,
			connect->will_topic,
			rrr_nullsafe_str_ptr_const(connect->will_message),
			rrr_u16_from_biglength_bug_const(rrr_nullsafe_str_len(connect->will_message)),
			connect->protocol_version
	) != 0) {
		RRR_MSG_0("Could not allocate publish in %s\n", __func__);
		ret = 1;
		goto out;
	}

	// These fields are present in both CONNECT will properties and PUBLISH properties. They
	// are copied directly to the new will PUBLISH.
	uint8_t will_property_list[] = {
			RRR_MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR,
			RRR_MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL,
			RRR_MQTT_PROPERTY_CONTENT_TYPE,
			RRR_MQTT_PROPERTY_RESPONSE_TOPIC,
			RRR_MQTT_PROPERTY_CORRELATION_DATA,
			RRR_MQTT_PROPERTY_USER_PROPERTY
	};

	RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(publish, RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(connect));
	RRR_MQTT_P_PUBLISH_SET_FLAG_RETAIN(publish, RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(connect));

	publish->will_delay_interval = will_properties->will_delay_interval;

	if (rrr_mqtt_property_collection_add_selected_from_collection (
			&publish->properties,
			&connect->will_properties,
			will_property_list,
			sizeof(will_property_list)/sizeof(*will_property_list)
	) != 0) {
		RRR_MSG_0("Error while copying will properties to publish in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_DBG_3("Set will message for client '%s' with topic '%s' retain '%u' qos '%u' delay interval '%" PRIu32 "' in MQTT broker\n",
			client_id,
			connect->will_topic,
			RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(connect),
			RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(connect),
			publish->will_delay_interval
	);

	*result = publish;
	publish = NULL;

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish);
	return ret;
}

static int __rrr_mqtt_broker_handle_connect_will (
		uint8_t *reason_v5,
		struct rrr_mqtt_data *mqtt_data,
		const char *client_id,
		const struct rrr_mqtt_p_connect *connect,
		struct rrr_mqtt_session **session_handle
) {
	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_p_publish *publish = NULL;
	struct rrr_mqtt_common_will_properties will_properties = {0};

	if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL(connect) != 0) {
		if ((ret = __rrr_mqtt_broker_new_will_publish (
				reason_v5,
				&publish,
				&will_properties,
				client_id,
				connect
		)) != 0) {
			RRR_MSG_0("Could not create publish will message data in %s, ret %i, reason %u\n",
					__func__, ret, *reason_v5);
			if (ret == RRR_MQTT_SOFT_ERROR && reason_v5 == 0) {
				*reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
				goto out;
			}
		}
	}

	// Passing NULL publish will clear any existing message
	if ((ret = mqtt_data->sessions->methods->register_will_publish (
			mqtt_data->sessions,
			session_handle,
			publish
	)) != RRR_MQTT_SESSION_OK) {
		RRR_MSG_0("Error while registering will publish for session in %s, return was %i\n", __func__, ret);
		goto out;
	}

	out:
	rrr_mqtt_common_will_properties_clear(&will_properties);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish);
	return ret;
}

static int __rrr_mqtt_broker_handle_connect_auth (
		uint8_t *reason_v5,
		struct rrr_mqtt_broker_data *data,
		const struct rrr_mqtt_p_connect *connect
) {
	int ret = RRR_MQTT_OK;

	if (connect->username != NULL && *(connect->username) != '\0') {
		if (connect->password == NULL || *(connect->password) == '\0') {
			RRR_DBG_2("Invalid CONNECT, username given but no password. The RRR MQTT broker requires passwords.\n");
			*reason_v5 = RRR_MQTT_P_5_REASON_IMPL_SPECIFIC_ERROR;
			goto out;
		}

		if (data->password_file == NULL) {
			RRR_DBG_2("Received CONNECT with username and password but no password file is defined in configuration.\n");
			*reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
			goto out;
		}

		if (rrr_passwd_authenticate (
				data->password_file,
				connect->username,
				connect->password,
				data->permission_name // May be NULL which means permissions are not checked
		) != 0) {
			RRR_DBG_2("Received CONNECT with username '%s' but authentication failed\n", connect->username);
			*reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
			goto out;
		}
	}
	else if (data->disallow_anonymous_logins != 0) {
		RRR_DBG_2("Received CONNECT without username but anonymous login is disabled by configuration\n");
		*reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_broker_handle_connect_check_client_identifier (
		uint8_t *reason_v5,
		short *other_client_was_disconnected,
		short *session_was_present,
		struct rrr_mqtt_session **session,
		struct rrr_mqtt_broker_data *data,
		struct rrr_mqtt_conn *connection,
		const struct rrr_mqtt_p_connect *connect
) {
	int ret = RRR_MQTT_OK;

	char *client_id_tmp = NULL;

	if (strlen(connect->client_identifier) >= strlen(RRR_MQTT_BROKER_CLIENT_PREFIX)) {
		char buf[strlen(RRR_MQTT_BROKER_CLIENT_PREFIX)+1];
		strncpy(buf, connect->client_identifier, strlen(RRR_MQTT_BROKER_CLIENT_PREFIX));
		buf[strlen(RRR_MQTT_BROKER_CLIENT_PREFIX)] = '\0';

		// Disallow client ID prefix which we use for generating random client IDs unless session already exists
		if (strcmp(buf, RRR_MQTT_BROKER_CLIENT_PREFIX) == 0) {
			if ((ret = data->mqtt_data.sessions->methods->get_session (
					session,
					data->mqtt_data.sessions,
					connect->client_identifier,
					session_was_present,
					1 // No creation if non-existent client ID
			)) != RRR_MQTT_SESSION_OK) {
				RRR_MSG_0("Error getting session in %s return was %i\n", __func__, ret);
				ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
				goto out;
			}
			if (session == NULL) {
				RRR_DBG_2("Client ID cannot begin with '" RRR_MQTT_BROKER_CLIENT_PREFIX "' unless a session with such name already exists\n");
				*reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
				goto out;
			}
		}
	}

	// If client ID is already used for active connection, disconnect the old one
	short client_name_was_taken_dummy = 0;
	if ((ret = __rrr_mqtt_broker_check_unique_client_id (
			&client_name_was_taken_dummy,
			other_client_was_disconnected,
			connect->client_identifier,
			connection, // Don't check self-connection
			data,
			1 // Disconnect existing client with same ID
	)) != 0) {
		 if (ret == RRR_MQTT_INTERNAL_ERROR) {
			goto out;
		 }

		 RRR_MSG_0("Error while checking if client id '%s' was unique\n", connect->client_identifier);
		 *reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		 goto out;
	}

	if ((ret = rrr_mqtt_conn_set_client_id (connection, connect->client_identifier)) != 0) {
		RRR_MSG_0("Could not set client ID in %s\n", __func__);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(client_id_tmp);
	return ret;
}

static int __rrr_mqtt_broker_handle_connect_assign_client_identifier (
		uint8_t *reason_v5,
		struct rrr_mqtt_p_connack *connack,
		struct rrr_mqtt_broker_data *data,
		struct rrr_mqtt_conn *connection,
		const struct rrr_mqtt_p_connect *connect
) {
	int ret = RRR_MQTT_OK;

	char *client_id_tmp = NULL;

	if (RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect) == 0) {
		RRR_MSG_2("Received CONNECT with zero bytes client identifier and clean start set to 0\n");
		*reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
		goto out;
	}

	if ((ret = __rrr_mqtt_broker_generate_unique_client_id (&client_id_tmp, connection, data)) != 0) {
		if (ret == RRR_MQTT_SOFT_ERROR) {
			*reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
			goto out;
		}
		RRR_MSG_0("Could not generate client identifier in %s\n", __func__);
		goto out;
	}

	if (rrr_mqtt_property_collection_add_blob_or_utf8 (
			&connack->properties,
			RRR_MQTT_PROPERTY_ASSIGNED_CLIENT_ID,
			client_id_tmp,
			rrr_u16_from_biglength_bug_const(strlen(client_id_tmp))
	) != 0) {
		RRR_MSG_0("Could not set assigned client-ID of CONNACK\n");
		*reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		goto out;
	}

	if ((ret = rrr_mqtt_conn_set_client_id (connection, client_id_tmp)) != 0) {
		RRR_MSG_0("Could not set client identifier in %s\n", __func__);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(client_id_tmp);
	return ret;
}

static int _rrr_mqtt_broker_handle_connect_session_init (
		uint8_t *reason_v5_result,
		struct rrr_mqtt_session **session,
		struct rrr_mqtt_broker_data *data,
		const struct rrr_mqtt_p_connect *connect
) {
	int ret = RRR_MQTT_OK;

	// The handle properties macro accesses &reason_v5, create a temporary variable
	uint8_t reason_v5 = 0;

	struct rrr_mqtt_session_properties session_properties = rrr_mqtt_common_default_session_properties;

	if (!RRR_MQTT_P_IS_V5(connect)) {
		// Default for version 3.1 is that sessions do not expire,
		// only use clean session to control this
		session_properties.numbers.session_expiry = 0xffffffff;
	}

	struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
			RRR_MQTT_P_5_REASON_OK,
			&session_properties,
			{0}
	};

	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&connect->properties,
			connect,
			rrr_mqtt_common_parse_connect_properties_callback,
			goto out
	);

	if ((ret = data->mqtt_data.sessions->methods->init_session (
			data->mqtt_data.sessions,
			session,
			&session_properties,
			data->mqtt_data.retry_interval_usec,
			RRR_MQTT_BROKER_MAX_IN_FLIGHT,
			RRR_MQTT_BROKER_COMPLETE_PUBLISH_GRACE_TIME_S,
			RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect)
	)) != RRR_MQTT_SESSION_OK) {
		if (ret & RRR_MQTT_SESSION_DELETED) {
			RRR_MSG_0("New session was deleted in %s\n", __func__);
		}
		else {
			RRR_MSG_0("Error while initializing session in %s, return was %i\n", __func__, ret);
		}

		// All errors are masked
		ret = RRR_MQTT_OK;
		reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		goto out;
	}

	out:
	*reason_v5_result = reason_v5;
	rrr_mqtt_session_properties_clear(&session_properties);
	return ret;
}

static int __rrr_mqtt_broker_handle_connect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	struct rrr_mqtt_broker_data *data = (struct rrr_mqtt_broker_data *) mqtt_data;
	const struct rrr_mqtt_p_connect *connect = (struct rrr_mqtt_p_connect *) packet;

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_session *session = NULL;
	short session_was_present = 0;

	short other_client_was_disconnected = 0;
	const char *client_id_source = "";

	uint8_t reason_v5 = 0;
	struct rrr_mqtt_p_connack *connack = NULL;

	if (connection->client_id != NULL) {
		RRR_BUG("Connection client ID was not NULL in %s\n", __func__);
	}

	if ((connack = (struct rrr_mqtt_p_connack *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_CONNACK, connect->protocol_version)) == NULL) {
		RRR_MSG_0("Could not allocate CONNACK packet in %s\n", __func__);
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	rrr_mqtt_conn_update_state (connection, packet, RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_IN);

	if ((ret = __rrr_mqtt_broker_handle_connect_auth (&reason_v5, data, connect)) != 0) {
		goto out;
	}
	else if (reason_v5 != 0) {
		goto out_send_connack;
	}

	if (connect->client_identifier == NULL || *(connect->client_identifier) == '\0') {
		if ((ret = __rrr_mqtt_broker_handle_connect_assign_client_identifier (
				&reason_v5,
				connack,
				data,
				connection,
				connect
		)) != 0) {
			goto out;
		}
		else if (reason_v5 != 0) {
			goto out_send_connack;
		}

		client_id_source = "generated";
	}
	else {
		if ((ret = __rrr_mqtt_broker_handle_connect_check_client_identifier (
				&reason_v5,
				&other_client_was_disconnected,
				&session_was_present,
				&session,
				data,
				connection,
				connect
		)) != 0) {
			goto out;
		}
		else if (reason_v5 != 0) {
			goto out_send_connack;
		}

		client_id_source = "provided";
	}

	{
		const rrr_length client_count = rrr_mqtt_transport_client_count_get(data->mqtt_data.transport);

		// If max clients are reached, we only allow connection if another client with
		// the same ID got disconnected. To disconnect it will of course cause the client
		// count to decrement, but there might be a delay before this happens.
		if (!other_client_was_disconnected && client_count >= data->max_clients) {
			RRR_MSG_0("Maximum number of clients (%i) reached in %s\n", data->max_clients, __func__);
			reason_v5 = RRR_MQTT_P_5_REASON_SERVER_BUSY;
			goto out_send_connack;
		}

		RRR_DBG_1 (">>>> New connection using client ID '%s'\n",
				connection->client_id
		);
		RRR_DBG_2 (">>>> CONNECT using client ID '%s' (%s) username '%s' clean session %i client count %i\n",
				connection->client_id,
				client_id_source,
				(connect->username != NULL ? connect->username : ""),
				RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect),
				client_count 
		);
	}

	if (session == NULL) {
		if ((ret = mqtt_data->sessions->methods->get_session (
				&session,
				mqtt_data->sessions,
				connection->client_id,
				&session_was_present,
				0 // Create if non-existent client ID
		)) != RRR_MQTT_SESSION_OK || session == NULL) {
			RRR_MSG_0("Error while getting session in %s return was %i\n", __func__, ret);
			ret = RRR_MQTT_INTERNAL_ERROR;
			goto out;
		}
	}

	if ((ret = _rrr_mqtt_broker_handle_connect_session_init (
			&reason_v5,
			&session,
			data,
			connect
	)) != 0) {
		goto out;
	}
	else if (reason_v5 != 0) {
		goto out_send_connack;
	}

	// Remove session from any old connections not yet destroyed
	if (rrr_mqtt_common_clear_session_from_connections (
			&data->mqtt_data,
			session,
			RRR_NET_TRANSPORT_CTX_HANDLE(handle)
	) != 0) {
		RRR_MSG_0("Could not clear session from other connections in %s\n", __func__);
		goto out;
	}

	// Handle will from connect
	if ((ret = __rrr_mqtt_broker_handle_connect_will(&reason_v5, mqtt_data, connection->client_id, connect, &session)) != 0) {
		if (ret == RRR_MQTT_SOFT_ERROR) {
			goto out_send_connack;
		}
		RRR_MSG_0("Error while handling will operations in %s, return was %i\n", __func__, ret);
		goto out;
	}

	// Set misc. parameters in connection struct
	if ((ret = rrr_mqtt_conn_set_data_from_connect_and_connack (
			connection,
			(data->max_keep_alive > 0 && connect->keep_alive > data->max_keep_alive) || connect->keep_alive == 0
				? data->max_keep_alive
				: connect->keep_alive,
			connect->protocol_version,
			session,
			connect->username
	)) != 0) {
		RRR_MSG_0("Could not set connection data in %s\n", __func__);
		goto out;
	}

	RRR_DBG_2("Keep-alive was set to %u\n", connection->keep_alive);

	// Set actual used keep-alive in connack properties
	if (rrr_mqtt_property_collection_add_uint32 (
			&connack->properties,
			RRR_MQTT_PROPERTY_SERVER_KEEP_ALIVE,
			connection->keep_alive
	) != 0) {
		RRR_MSG_0("Could not set server keep-alive of CONNACK\n");
		reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		goto out_send_connack;
	}

	// First (and only) bit of flags is session present bit
	connack->ack_flags = session_was_present && !RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect) ? 1 : 0;

	out_send_connack:

	RRR_DBG_2("Setting connection disconnect reason to %u in %s\n", reason_v5, __func__);
	connack->reason_v5 = reason_v5;
	RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, reason_v5);

	if (connack->protocol_version->id < 5) {
		uint8_t v31_reason = rrr_mqtt_p_translate_reason_from_v5(connack->reason_v5);
		if (v31_reason == RRR_MQTT_P_31_REASON_NO_CONNACK) {
			goto out;
		}
		else if (v31_reason > 5) {
			RRR_BUG("Unknown V3.1 CONNECT reason code %u in %s, v5 code was %u\n",
					v31_reason, __func__, connack->reason_v5);
		}
		// DO NOT store the v31 reason, assembler will convert the v5 reason again later
	}

	if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet_urgent(handle, (struct rrr_mqtt_p *) connack)) != 0) {
		RRR_MSG_0("Error while sending CONNACK, return was %i\n", ret);
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	if (connack->reason_v5 != 0) {
		RRR_DBG_2("A CONNACK which was sent had non-zero reason, destroying connection\n");
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(connack);
	return ret;
}

static int __rrr_mqtt_broker_send_now_callback (
		struct rrr_mqtt_p *packet,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	int ret = RRR_MQTT_OK;

	if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet_urgent(handle, packet)) != 0) {
		RRR_MSG_0("Could not send outbound packet in %s\n", __func__);
	}

	return ret;
}

static int __rrr_mqtt_broker_handle_subscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) packet;

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_p_suback *suback = NULL;

	if ((suback = (struct rrr_mqtt_p_suback *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_SUBACK, packet->protocol_version)) == NULL) {
		RRR_MSG_0("Could not allocate SUBACK packet in %s\n", __func__);
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	// This will set reason in disallowed subscriptions
	if ((ret = mqtt_data->acl_handler(connection, packet, mqtt_data->acl_handler_arg) & ~(RRR_MQTT_ACL_RESULT_ALLOW|RRR_MQTT_ACL_RESULT_DENY)) != 0) {
		RRR_MSG_0("Error while checking ACL rules in __rrr_mqtt_broker_handle_subscribe, return was %i\n", ret);
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	// TODO : Check valid subscriptions here? (is done now while adding to session), set max QoS etc.

	unsigned int ack_match_count_dummy;
	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->receive_packet (
					mqtt_data->sessions,
					&connection->session,
					packet,
					&ack_match_count_dummy
			),
			goto out,
			" while delivering SUBSCRIBE message to session"
	);

	suback->packet_identifier = subscribe->packet_identifier;
	suback->subscriptions_ = subscribe->subscriptions;
	subscribe->subscriptions = NULL;

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->send_packet_now (
					mqtt_data->sessions,
					&connection->session,
					(struct rrr_mqtt_p *) suback,
					0,
					__rrr_mqtt_broker_send_now_callback,
					handle
			),
			goto out,
			" while delivering SUBACK message to session"
	);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(suback);
	return ret;
}

static int __rrr_mqtt_broker_handle_unsubscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	struct rrr_mqtt_p_unsubscribe *unsubscribe = (struct rrr_mqtt_p_unsubscribe *) packet;

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_p_unsuback *unsuback = NULL;

	if ((unsuback = (struct rrr_mqtt_p_unsuback *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_UNSUBACK, packet->protocol_version)) == NULL) {
		RRR_MSG_0("Could not allocate UNSUBACK packet in __rrr_mqtt_broker_handle_unsubscribe \n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	// Session subsystem will update the subscription list and set reason codes for each topic
	unsigned int ack_match_count_dummy;
	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->receive_packet(
					mqtt_data->sessions,
					&connection->session,
					packet,
					&ack_match_count_dummy
			),
			goto out,
			" while delivering UNSUBSCRIBE message to session"
	);

	unsuback->packet_identifier = unsubscribe->packet_identifier;
	unsuback->subscriptions_ = unsubscribe->subscriptions;
	unsubscribe->subscriptions = NULL;

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->send_packet_now(
					mqtt_data->sessions,
					&connection->session,
					(struct rrr_mqtt_p *) unsuback,
					0,
					__rrr_mqtt_broker_send_now_callback,
					handle
			),
			goto out,
			" while delivering UNSUBACK message to session"
	);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(unsuback);
	return ret;
}

static int __rrr_mqtt_broker_handle_pingreq (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	(void)(mqtt_data);

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	struct rrr_mqtt_p_pingresp *pingresp = NULL;

	if ((pingresp = (struct rrr_mqtt_p_pingresp *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_PINGRESP, packet->protocol_version)) == NULL) {
		RRR_MSG_0("Could not allocate CONNACK packet in %s\n", __func__);
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	ret = rrr_mqtt_conn_iterator_ctx_send_packet_urgent(handle, (struct rrr_mqtt_p *) pingresp);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(pingresp);
	return ret;
}

static int __rrr_mqtt_broker_handle_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) packet;

	(void)(mqtt_data);

	int ret = RRR_MQTT_OK;

	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	RRR_DBG_2(">>>X DISCONNECT from client '%s' in MQTT broker reason %u\n",
			(connection->client_id != NULL ? connection->client_id : ""), disconnect->reason_v5);

	RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, disconnect->reason_v5);

	ret = rrr_mqtt_common_update_conn_state_upon_disconnect(connection, disconnect);

	return ret;
}

static int __rrr_mqtt_broker_handle_auth (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	(void)(connection);
	(void)(mqtt_data);
	(void)(packet);

	// AUTH not supported

	return RRR_MQTT_SOFT_ERROR;
}

static const struct rrr_mqtt_type_handler_properties handler_properties[] = {
	{NULL},
	{__rrr_mqtt_broker_handle_connect},
	{NULL},
	{rrr_mqtt_common_handle_publish},
	{rrr_mqtt_common_handle_puback_pubcomp},
	{rrr_mqtt_common_handle_pubrec},
	{rrr_mqtt_common_handle_pubrel},
	{rrr_mqtt_common_handle_puback_pubcomp},
	{__rrr_mqtt_broker_handle_subscribe},
	{NULL},
	{__rrr_mqtt_broker_handle_unsubscribe},
	{NULL},
	{__rrr_mqtt_broker_handle_pingreq},
	{NULL},
	{__rrr_mqtt_broker_handle_disconnect},
	{__rrr_mqtt_broker_handle_auth}
};

static void __rrr_mqtt_broker_publish_notify_callback (
		void *arg
) {
	struct rrr_mqtt_broker_data *data = arg;
	rrr_mqtt_transport_notify_tick(data->mqtt_data.transport);
}

static int __rrr_mqtt_broker_event_handler (
		struct rrr_mqtt_conn *connection,
		int event,
		void *static_arg,
		void *arg
) {
	struct rrr_mqtt_broker_data *data = static_arg;

	(void)(connection);
	(void)(arg);

	int ret = RRR_MQTT_OK;

	switch (event) {
		case RRR_MQTT_CONN_EVENT_DISCONNECT:
			data->stats.total_connections_closed++;
			break;
		default:
			break;
	};

	return ret;
}

static int __rrr_mqtt_broker_acl_handler_subscribe (
		struct rrr_mqtt_broker_data *broker,
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p_subscribe *subscribe
) {
	// We don't disallow the whole subscription packet, only
	// set for each subscription

	RRR_LL_ITERATE_BEGIN(subscribe->subscriptions, struct rrr_mqtt_subscription);
		int ret_tmp = rrr_mqtt_acl_check_access (
				broker->acl,
				node->token_tree,
				RRR_MQTT_ACL_ACTION_RO,
				connection->username,
				rrr_mqtt_topic_match_tokens_recursively_acl
		);
		if (ret_tmp == RRR_MQTT_ACL_RESULT_ALLOW) {
			RRR_DBG_2("ACL: Subscription '%s' for client '%s' allowed\n", node->topic_filter, connection->client_id);
		}
		else {
			RRR_DBG_2("ACL: Subscription '%s' for client '%s' denied\n", node->topic_filter, connection->client_id);
			node->qos_or_reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
		}
	RRR_LL_ITERATE_END();

	return RRR_MQTT_ACL_RESULT_ALLOW;
}

static int __rrr_mqtt_broker_acl_handler_publish (
		struct rrr_mqtt_broker_data *broker,
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = rrr_mqtt_acl_check_access (
			broker->acl,
			publish->token_tree_,
			RRR_MQTT_ACL_ACTION_RW,
			connection->username,
			rrr_mqtt_topic_match_tokens_recursively
	);

	if (ret == RRR_MQTT_ACL_RESULT_DENY && !RRR_MQTT_P_IS_V5(publish) && broker->disconnect_on_v31_publish_deny != 0) {
		ret = RRR_MQTT_ACL_RESULT_DISCONNECT;
	}

	return ret;
}

static int __rrr_mqtt_broker_acl_handler (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		void *arg
) {
	struct rrr_mqtt_broker_data *broker = arg;

	int ret = RRR_MQTT_ACL_RESULT_DENY;

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		ret = __rrr_mqtt_broker_acl_handler_publish(broker, connection, (struct rrr_mqtt_p_publish *) packet);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE) {
		ret = __rrr_mqtt_broker_acl_handler_subscribe(broker, connection, (struct rrr_mqtt_p_subscribe *) packet);
	}
	else {
		ret = RRR_MQTT_ACL_RESULT_ALLOW;
	}

	return ret;
}

void rrr_mqtt_broker_destroy (struct rrr_mqtt_broker_data *broker) {
	/* Caller should make sure that no more connections are accepted at this point */
	rrr_mqtt_common_data_destroy(&broker->mqtt_data);
	rrr_free(broker);
}

void rrr_mqtt_broker_notify_pthread_cancel (struct rrr_mqtt_broker_data *broker) {
	rrr_mqtt_common_data_notify_pthread_cancel(&broker->mqtt_data);
}

static int __rrr_mqtt_broker_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
) {
	struct rrr_mqtt_broker_data *data = arg;

	int ret = 0;
	int ret_from_read = 0;

	struct rrr_mqtt_session_iterate_send_queue_counters session_iterate_counters = {0};

	if ((ret = ret_from_read = rrr_mqtt_common_read_parse_single_handle (
			&session_iterate_counters,
			&data->mqtt_data,
			handle,
			NULL,
			NULL
	)) != 0) {
		if (ret == RRR_MQTT_SOFT_ERROR) {
			// Mayble client sent a PUBLISH followed by DISCONNECT, process
			// PUBLISH forwarding below.
		}
		else {
			// Ensure INCOMPLETE propagates
			goto out;
		}
	}

	out:
	return ret | ret_from_read;
}

int rrr_mqtt_broker_new (
		struct rrr_mqtt_broker_data **broker,
		const struct rrr_mqtt_common_init_data *init_data,
		struct rrr_event_queue *queue,
		uint16_t max_keep_alive,
		const char *password_file,
		const char *permission_name,
		const struct rrr_mqtt_acl *acl,
		int disallow_anonymous_logins,
		int disconnect_on_v31_publish_deny,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg
) {
	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_broker_data *res = NULL;

	if (max_keep_alive == 0) {
		RRR_DBG_1("Setting max keep alive to 1 in %s\n", __func__);
		max_keep_alive = 1;
	}

	if ((res = rrr_allocate_zero(sizeof(*res))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_mqtt_common_data_init (
			&res->mqtt_data,
			handler_properties,
			init_data,
			queue,
			session_initializer,
			session_initializer_arg,
			__rrr_mqtt_broker_event_handler,
			res,
			__rrr_mqtt_broker_acl_handler,
			res,
			__rrr_mqtt_broker_read_callback,
			res
	)) != 0) {
		RRR_MSG_0("Could not initialize mqtt data in %s\n", __func__);
		goto out_free;
	}

	res->max_clients = rrr_length_sub_bug_const(init_data->max_socket_connections, 10);
	res->max_keep_alive = max_keep_alive;
	res->disallow_anonymous_logins = disallow_anonymous_logins;
	res->disconnect_on_v31_publish_deny = disconnect_on_v31_publish_deny;
	res->password_file = password_file;
	res->permission_name = permission_name;
	res->acl = acl;

	MQTT_COMMON_CALL_SESSION_REGISTER_CALLBACKS(&res->mqtt_data, __rrr_mqtt_broker_publish_notify_callback, res);

	*broker = res;
	goto out;
//	out_destroy_data:
//		rrr_mqtt_common_data_destroy(&res->mqtt_data);
	out_free:
		RRR_FREE_IF_NOT_NULL(res);
	out:
		return ret;
}

void rrr_mqtt_broker_get_stats (
		struct rrr_mqtt_broker_stats *target,
		struct rrr_mqtt_broker_data *data
) {
	if (data->mqtt_data.sessions->methods->get_stats (
			&data->stats.session_stats,
			data->mqtt_data.sessions
	) != 0) {
		RRR_MSG_0("Warning: Failed to get session stats in %s\n", __func__);
	}

	data->stats.connections_active = rrr_mqtt_transport_client_count_get(data->mqtt_data.transport);

	*target = data->stats;
}
