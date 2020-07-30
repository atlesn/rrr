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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../log.h"

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

#define RRR_MQTT_BROKER_CLIENT_PREFIX "mqtt-client-"
#define RRR_MQTT_BROKER_MAX_GENERATED_CLIENT_IDS 65535

#define RRR_MQTT_BROKER_MAX_IN_FLIGHT 	125
#define RRR_MQTT_BROKER_COMPLETE_PUBLISH_GRACE_TIME_S 2

struct rrr_mqtt_broker_listen_ipv4_and_ipv6_callback_data {
	int transport_handle;
};

void __rrr_mqtt_broker_listen_ipv4_and_ipv6_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_mqtt_broker_listen_ipv4_and_ipv6_callback_data *callback_data = arg;
	callback_data->transport_handle = handle->handle;
}

static int __rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		int *listen_handle,
		struct rrr_net_transport *transport,
		int port
) {
	int ret = 0;

	*listen_handle = 0;

	struct rrr_mqtt_broker_listen_ipv4_and_ipv6_callback_data callback_data = { 0 };
	if ((ret = rrr_net_transport_bind_and_listen (
			transport,
			port,
			__rrr_mqtt_broker_listen_ipv4_and_ipv6_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not listen on port %i in __rrr_mqtt_broker_listen_ipv4_and_ipv6\n", port);
		ret = 1;
		goto out;
	}

	*listen_handle = callback_data.transport_handle;

	out:
	return ret;
}

int rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		int *listen_handle,
		struct rrr_mqtt_broker_data *broker,
		const struct rrr_net_transport_config *net_transport_config,
		int port
) {
	int ret = 0;

	*listen_handle = 0;

	// TODO : For multiple ports, transport may be re-used

	if ((ret = rrr_mqtt_transport_start (
			broker->mqtt_data.transport,
			net_transport_config
	)) != 0) {
		RRR_MSG_0("Could not start plain transport in rrr_mqtt_broker_listen_ipv4_and_ipv6_tls\n");
		ret = 1;
		goto out;
	}

	ret = __rrr_mqtt_broker_listen_ipv4_and_ipv6 (
			listen_handle,
			rrr_mqtt_transport_get_latest(broker->mqtt_data.transport),
			port
	);

	out:
	return ret;
}

struct validate_client_id_callback_data {
	const struct rrr_mqtt_conn *orig_connection;
	const char *client_id;
	int disconnect_other_client;
	int name_was_taken;
};

static int __rrr_mqtt_broker_check_unique_client_id_callback (struct rrr_net_transport_handle *handle, void *arg) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK_NO_ERROR;

	struct validate_client_id_callback_data *data = arg;

	if (data->orig_connection == connection) {
		// Don't validate ourselves (would have been stupid)
		return RRR_MQTT_OK;
	}

	int ret = RRR_MQTT_OK;

	if (!RRR_MQTT_CONN_STATE_SEND_IS_BUSY_CLIENT_ID(connection)) {
		// Equal name with a CLOSED connection is OK
		ret = RRR_MQTT_OK;
		goto out;
	}

	/* client_id is not set in the connection until CONNECT packet is handled */
	if (connection->client_id != NULL && strcmp(connection->client_id, data->client_id) == 0) {
		data->name_was_taken = 1;

		if (data->disconnect_other_client == 0) {
			goto out;
		}

		RRR_DBG_1("Disconnecting existing client with client ID %s\n", connection->client_id);

		RRR_MQTT_CONN_SET_DISCONNECT_REASON_V5(connection, RRR_MQTT_P_5_REASON_SESSION_TAKEN_OVER);
		int ret_tmp = rrr_mqtt_conn_iterator_ctx_send_disconnect(handle);

		// On soft error, we cannot be sure that the existing client was actually
		// disconnected, and we must disallow the new connection
		if ((ret_tmp & RRR_MQTT_SOFT_ERROR) != 0) {
			RRR_MSG_0("Soft error while disconnecting existing client in __rrr_mqtt_broker_check_unique_client_id_or_disconnect_callback\n");
			ret_tmp = ret & ~RRR_MQTT_SOFT_ERROR;
			ret |= RRR_MQTT_SOFT_ERROR;
		}

		// We are not allowed to destroy the connection here, it must be done by housekeeping
		ret_tmp = ret_tmp & ~RRR_MQTT_SOFT_ERROR;

		if (ret_tmp != RRR_MQTT_OK) {
			RRR_MSG_0("Internal error while disconnecting existing client in __rrr_mqtt_broker_check_unique_client_id_or_disconnect_callback return was %i\n",
					ret_tmp);
			ret |= RRR_MQTT_INTERNAL_ERROR;
		}
	}

	out:
	// DO NOT return anything else but OK and internal error as this might
	// cause the connection to become destroyed in the net transport loop. The
	// connection is being used by client id generator.
	return ((ret & RRR_MQTT_INTERNAL_ERROR) == RRR_MQTT_INTERNAL_ERROR
			? RRR_NET_TRANSPORT_READ_HARD_ERROR
			: RRR_NET_TRANSPORT_READ_OK
	);
}

/* If the client specifies a Client ID, we do not accept duplicates or IDs beginning
 * with RRR_MQTT_BROKER_CLIENT_PREFIX. We do, however, accept IDs beginning with the
 * prefix if a session with this prefix already exists. If a new connection with an
 * existing client ID appears, the old client is to be disconnected. */
static int __rrr_mqtt_broker_check_unique_client_id (
		int *name_was_taken,
		int *other_client_was_disconnected,
		const char *client_id,
		const struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *broker,
		int disconnect_other_client
) {
	int ret = 0;

	*name_was_taken = 0;
	*other_client_was_disconnected = 0;

	struct validate_client_id_callback_data callback_data = {
			connection,
			client_id,
			disconnect_other_client,
			0
	};

	ret = rrr_mqtt_transport_iterate(
			broker->mqtt_data.transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_mqtt_broker_check_unique_client_id_callback,
			&callback_data
	);

	*name_was_taken = callback_data.name_was_taken;

	// Do not replace error handling with macro, special case
	if (ret != RRR_MQTT_OK) {
		if (callback_data.name_was_taken != 0 && disconnect_other_client != 0) {
			RRR_DBG_1("Client id %s was already used in an active connection, the old one was disconnected\n", client_id);
			*other_client_was_disconnected = 1;
		}

		int old_ret = ret;
		if ((ret & RRR_MQTT_SOFT_ERROR) != 0) {
			RRR_MSG_0("Soft error while checking for unique client ID %s, must disconnect the client\n", client_id);
			ret = (ret & ~RRR_MQTT_SOFT_ERROR);
		}
		if (ret != 0) {
			RRR_MSG_0("Internal error while checking for unique client ID %s, must close the server.\n", client_id);
			ret = RRR_MQTT_INTERNAL_ERROR;
		}
		ret |= old_ret;
	}

	return ret;
}

static int __rrr_mqtt_broker_generate_unique_client_id_unlocked (
		char **final_result,
		const struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *broker
) {
	int ret = 0;
	uint32_t serial = 0;
	char *result = NULL;

	*final_result = NULL;

	// On error, the connection destroy function will free this memory, The
	// current connection is locked since we come from packet handler context
	// and it is not possible for others to read our unfinished client id, they
	// will of course lock the connection before trying that.
	//connection->client_id = result;

	int retries = RRR_MQTT_BROKER_MAX_GENERATED_CLIENT_IDS;
	while (--retries >= 0) {
		// We let the serial overflow
		serial = ++(broker->client_serial);

		RRR_FREE_IF_NOT_NULL(result);

		if (rrr_asprintf(&result, RRR_MQTT_BROKER_CLIENT_PREFIX "%u", serial) < 0) {
			RRR_MSG_0("Could not allocate memory in __rrr_mqtt_broker_generate_unique_client_id_unlocked\n");
			ret = RRR_MQTT_INTERNAL_ERROR;
			goto out;
		}

		int name_was_taken = 0;
		int dummy = 0;

		ret = __rrr_mqtt_broker_check_unique_client_id (
				&name_was_taken,
				&dummy,
				result,
				connection,
				broker,
				0 // = do not disconnect other client with equal name
		);

		if (dummy != 0) {
			RRR_BUG("dummy was not 0 in __rrr_mqtt_broker_generate_unique_client_id_unlocked\n");
		}

		if (ret != 0) {
			RRR_MSG_0("Error while validating client ID in __rrr_mqtt_broker_generate_unique_client_id_unlocked: %i\n", ret);
			goto out;
		}

		if (name_was_taken == 0) {
			break;
		}
	}

	if (retries <= 0) {
		RRR_MSG_0("Number of generated client IDs reached maximum in __rrr_mqtt_broker_generate_unique_client_id_unlocked\n");
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	*final_result = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);

	return ret;
}

static int __rrr_mqtt_broker_generate_unique_client_id (
		char **final_result,
		const struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *data
) {
	int ret = 0;

	if (*final_result != NULL) {
		RRR_BUG("final_result was not NULL in __rrr_mqtt_broker_generate_unique_client_id\n");
	}

	// We must hold this lock to check for unique ID, if not, it is possible to deadlock
	// if two connections try to check each others ID at the same time. We must also
	// protect the serial counter
	RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO(ret = __rrr_mqtt_broker_generate_unique_client_id_unlocked (
			final_result,
			connection,
			data)
	);

	return ret;
}

// TODO : Try to split this up into multiple functions

static int __rrr_mqtt_broker_handle_connect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;
	int ret_destroy = 0;

	struct rrr_mqtt_broker_data *data = (struct rrr_mqtt_broker_data *) mqtt_data;
	struct rrr_mqtt_p_connect *connect = (struct rrr_mqtt_p_connect *) packet;

	struct rrr_mqtt_session_properties session_properties = rrr_mqtt_common_default_session_properties;

//	RRR_MQTT_P_LOCK(packet);

	int client_id_was_assigned = 0;
	int session_present = 0;

	int name_was_taken = 0;
	int other_client_was_disconnected = 0;

	uint8_t reason_v5 = 0;
	struct rrr_mqtt_session *session = NULL;
	struct rrr_mqtt_p_connack *connack = NULL;

	if (connection->client_id != NULL) {
		RRR_BUG("Connection client ID was not NULL in rrr_mqtt_p_handler_connect\n");
	}

	connack = (struct rrr_mqtt_p_connack *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_CONNACK, connect->protocol_version);
	if (connack == NULL) {
		RRR_MSG_0("Could not allocate CONNACK packet in rrr_mqtt_p_handler_connect\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	rrr_mqtt_conn_update_state (connection, packet, RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_IN);

	if (connect->username != NULL && *(connect->username) != '\0') {
		if (connect->password == NULL || *(connect->password) == '\0') {
			RRR_DBG_1("Invalid CONNECT, username given but no password. The RRR MQTT broker requires passwords.\n");
			ret = RRR_MQTT_SOFT_ERROR;
			reason_v5 = RRR_MQTT_P_5_REASON_IMPL_SPECIFIC_ERROR;
			goto out_send_connack;
		}

		if (data->password_file == NULL) {
			RRR_DBG_1("Received CONNECT with username and password but no password file is defined in configuration.\n");
			ret = RRR_MQTT_SOFT_ERROR;
			reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
			goto out_send_connack;
		}

		if (rrr_passwd_authenticate (
				data->password_file,
				connect->username,
				connect->password,
				data->permission_name // May be NULL which means permissions are not checked
		) != 0) {
			RRR_DBG_1("Received CONNECT with username '%s' but authentication failed\n", connect->username);
			ret = RRR_MQTT_SOFT_ERROR;
			reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
			goto out_send_connack;
		}
	}
	else if (data->disallow_anonymous_logins != 0) {
		RRR_DBG_1("Received CONNECT without username but anonymous login is disabled by configuration\n");
		ret = RRR_MQTT_SOFT_ERROR;
		reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
		goto out_send_connack;
	}

	if (connect->client_identifier == NULL || *(connect->client_identifier) == '\0') {
		// Note: Write ID to connectION, not the connect packet
		RRR_FREE_IF_NOT_NULL(connection->client_id);
		if ((ret = __rrr_mqtt_broker_generate_unique_client_id (&connection->client_id, connection, data)) != 0) {
			if (ret == RRR_MQTT_SOFT_ERROR) {
				reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
				goto out_send_connack;
			}
			RRR_MSG_0("Could not generate client identifier in rrr_mqtt_p_handler_connect");
			goto out;
		}
		client_id_was_assigned = 1;
	}
	else {
		if (strlen(connect->client_identifier) >= strlen(RRR_MQTT_BROKER_CLIENT_PREFIX)) {
			char buf[strlen(RRR_MQTT_BROKER_CLIENT_PREFIX)+1];
			strncpy(buf, connect->client_identifier, strlen(RRR_MQTT_BROKER_CLIENT_PREFIX));
			buf[strlen(RRR_MQTT_BROKER_CLIENT_PREFIX)] = '\0';

			// Disallow client ID prefix which we use for generating random client IDs unless session already exists
			if (strcmp(buf, RRR_MQTT_BROKER_CLIENT_PREFIX) == 0) {
				if ((ret = mqtt_data->sessions->methods->get_session (
						&session,
						mqtt_data->sessions,
						connect->client_identifier,
						&session_present,
						1 // No creation if non-existent client ID
				)) != RRR_MQTT_SESSION_OK) {
					ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
					RRR_MSG_0("Internal error getting session in rrr_mqtt_p_handler_connect A\n");
					goto out;
				}
				if (session == NULL) {
					RRR_MSG_0("Client ID cannot begin with '" RRR_MQTT_BROKER_CLIENT_PREFIX "'\n");
					ret = RRR_MQTT_SOFT_ERROR;
					reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
					goto out_send_connack;
				}
			}
		}

		// If client ID is already used for active connection, disconnect the old one
		if ((ret = __rrr_mqtt_broker_check_unique_client_id (
				&name_was_taken,
				&other_client_was_disconnected,
				connect->client_identifier,
				connection,
				data,
				1 // Disconnect existing client with same ID
		)) != 0) {
			 ret = ret & ~RRR_MQTT_SOFT_ERROR;
			 if (ret != 0) {
					RRR_MSG_0("Error while checking for unique client ID in rrr_mqtt_p_handler_connect\n");
					goto out;
			 }
			 RRR_MSG_0("Error while checking if client id '%s' was unique\n", connect->client_identifier);
			 ret = RRR_MQTT_SOFT_ERROR;
			 reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
			 goto out_send_connack;
		}

		if ((connection->client_id = strdup(connect->client_identifier)) == NULL) {
			RRR_MSG_0("Could not allocate memory for client ID in __rrr_mqtt_broker_handle_connect\n");
			ret = RRR_MQTT_INTERNAL_ERROR;
			goto out;
		}
	}

	// Below this point, only access client identifier through connection struct, not connect struct (might be NULL)

	int client_count = 0;
	RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO(client_count = data->client_count);

	// If max clients are reached, we only allow connection if another client with
	// the same ID got disconnected. To disconnect it will of course cause the client
	// count to decrement, but there might be a delay before this happens.
	if (other_client_was_disconnected == 0 && client_count >= data->max_clients) {
		RRR_MSG_0("Maximum number of clients (%i) reached in rrr_mqtt_p_handler_connect\n",
				data->max_clients);
		reason_v5 = RRR_MQTT_P_5_REASON_SERVER_BUSY;
		ret = RRR_MQTT_SOFT_ERROR;
		goto out_send_connack;
	}

	RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO(data->client_count++);

	RRR_DBG_1 ("CONNECT: Using client ID '%s'%s username '%s' client count is %i\n",
			(connection->client_id != NULL ? connection->client_id : "(empty)"),
			(client_id_was_assigned ? " (generated)"  : ""),
			(connect->username != NULL ? connect->username : ""),
			client_count + 1
	);

	if (session == NULL) {
		if ((ret = mqtt_data->sessions->methods->get_session (
				&session,
				mqtt_data->sessions,
				connection->client_id,
				&session_present,
				0 // Create if non-existent client ID
		)) != RRR_MQTT_SESSION_OK || session == NULL) {
			ret = RRR_MQTT_INTERNAL_ERROR;
			RRR_MSG_0("Internal error getting session in rrr_mqtt_p_handler_connect B\n");
			goto out;
		}
	}

	if (!RRR_MQTT_P_IS_V5(packet)) {
		// Default for version 3.1 is that sessions do not expire,
		// only use clean session to control this
		session_properties.numbers.session_expiry = 0xffffffff;
	}

	struct rrr_mqtt_common_parse_properties_data_connect callback_data = {
			&connect->properties,
			RRR_MQTT_P_5_REASON_OK,
			&session_properties,
			{0}
	};

	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&connect->properties,
			connect,
			rrr_mqtt_common_handler_connect_handle_properties_callback,
			goto out_send_connack
	);

	if ((ret = mqtt_data->sessions->methods->init_session (
			mqtt_data->sessions,
			&session,
			callback_data.session_properties,
			mqtt_data->retry_interval_usec,
			RRR_MQTT_BROKER_MAX_IN_FLIGHT,
			RRR_MQTT_BROKER_COMPLETE_PUBLISH_GRACE_TIME_S,
			RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect),
			0, // No local delivery (forward publish to other sessions)
			&session_present
	)) != RRR_MQTT_SESSION_OK) {
		if ((ret & RRR_MQTT_SESSION_DELETED) != 0) {
			RRR_MSG_0("New session was deleted in rrr_mqtt_p_handler_connect\n");
		}
		else {
			RRR_MSG_0("Error while initializing session in rrr_mqtt_p_handler_connect, return was %i\n", ret);
		}

		ret = RRR_MQTT_SOFT_ERROR;
		reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		goto out_send_connack;
	}

	connack->ack_flags = session_present;

	uint16_t use_keep_alive = connect->keep_alive;
	if ((data->max_keep_alive > 0 && use_keep_alive > data->max_keep_alive) || use_keep_alive == 0) {
		use_keep_alive = data->max_keep_alive;
	}

	if ((ret = rrr_mqtt_conn_set_data_from_connect_and_connack (
			connection,
			use_keep_alive,
			connect->protocol_version,
			session,
			connect->username
	)) != 0) {
		RRR_MSG_0("Could not set connection data in  __rrr_mqtt_broker_handle_connect\n");
		goto out;
	}

	// Remove session from any old connections not yet destroyed
	if (rrr_mqtt_common_clear_session_from_connections (
			&data->mqtt_data,
			session,
			handle->handle
	) != 0) {
		RRR_MSG_0("Could not clear session from other connections in  __rrr_mqtt_broker_handle_connect\n");
		goto out;
	}

	RRR_DBG_2("Setting keep-alive to %u in __rrr_mqtt_broker_handle_connect\n", use_keep_alive);

	if (rrr_mqtt_property_collection_add_uint32 (
			&connack->properties,
			RRR_MQTT_PROPERTY_SERVER_KEEP_ALIVE,
			use_keep_alive
	) != 0) {
		RRR_MSG_0("Could not set server keep-alive of CONNACK");
		reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		goto out_send_connack;
	}

	if (client_id_was_assigned != 0) {
		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&connack->properties,
				RRR_MQTT_PROPERTY_ASSIGNED_CLIENT_ID,
				connection->client_id,
				strlen(connection->client_id)
		) != 0) {
			RRR_MSG_0("Could not set assigned client-ID of CONNACK");
			reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
			goto out_send_connack;
		}
	}

	out_send_connack:

	if ((ret & RRR_MQTT_SOFT_ERROR) != 0 && reason_v5 == 0) {
		RRR_BUG("Reason was not set on soft error in rrr_mqtt_p_handler_connect\n");
	}
	RRR_DBG_2("Setting connection disconnect reason to %u in __rrr_mqtt_broker_handle_connect\n", reason_v5);
	connack->reason_v5 = reason_v5;
	RRR_MQTT_CONN_SET_DISCONNECT_REASON_V5(connection, reason_v5);

	if (connack->protocol_version->id < 5) {
		uint8_t v31_reason = rrr_mqtt_p_translate_reason_from_v5(connack->reason_v5);
		if (v31_reason == RRR_MQTT_P_31_REASON_NO_CONNACK) {
			goto out;
		}
		else if (v31_reason > 5) {
			RRR_BUG("Unknown V3.1 CONNECT reason code %u in rrr_mqtt_p_handler_connect, v5 code was %u\n",
					v31_reason, connack->reason_v5);
		}
		// DO NOT store the v31 reason, assembler will convert the v5 reason again later
	}

	RRR_MQTT_P_LOCK(connack);
	ret = rrr_mqtt_conn_iterator_ctx_send_packet(handle, (struct rrr_mqtt_p *) connack);
	RRR_MQTT_P_UNLOCK(connack);

	if ((ret & RRR_MQTT_SOFT_ERROR) != 0) {
		ret = ret & ~RRR_MQTT_SOFT_ERROR;
		RRR_DBG_1("CONNACK which was sent had non-zero reason, destroying connection\n");
		ret_destroy = RRR_MQTT_SOFT_ERROR;
	}

	if (ret != 0) {
		RRR_MSG_0("Error occured while sending CONNACK for sending in rrr_mqtt_p_handler_connect\n");
		ret_destroy = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	out:

	rrr_mqtt_session_properties_clear(&session_properties);
//	RRR_MQTT_P_UNLOCK(packet);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(connack);
	return ret | ret_destroy;
}

static int __rrr_mqtt_broker_handle_subscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) packet;

	struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_SUBACK, packet->protocol_version);
	if (suback == NULL) {
		RRR_MSG_0("Could not allocate SUBACK packet in rrr_mqtt_p_handler_subscribe\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	// This will set reason in subscriptions which are not allowed
	ret = mqtt_data->acl_handler(connection, packet, mqtt_data->acl_handler_arg);
	ret &= ~(RRR_MQTT_ACL_RESULT_ALLOW|RRR_MQTT_ACL_RESULT_DENY);

	if (ret != 0) {
		RRR_MSG_0("Error while checking ACL rules in __rrr_mqtt_broker_handle_subscribe, return was %i\n", ret);
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	unsigned int dummy;
	// TODO : Check valid subscriptions (is done now while adding to session), set max QoS etc.

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->receive_packet(
					mqtt_data->sessions,
					&connection->session,
					packet,
					&dummy
			),
			goto out,
			" while sending SUBSCRIBE message to session in rrr_mqtt_p_handler_subscribe"
	);

	RRR_MQTT_P_LOCK(suback);
	suback->packet_identifier = subscribe->packet_identifier;
	suback->subscriptions_ = subscribe->subscriptions;
	subscribe->subscriptions = NULL;
	RRR_MQTT_P_UNLOCK(suback);

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->send_packet(
					mqtt_data->sessions,
					&connection->session,
					(struct rrr_mqtt_p *) suback,
					0
			),
			goto out,
			" while sending SUBACK to session in rrr_mqtt_p_handler_subscribe"
	);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(suback);
	return ret;
}

static int __rrr_mqtt_broker_handle_unsubscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_p_unsubscribe *unsubscribe = (struct rrr_mqtt_p_unsubscribe *) packet;

	struct rrr_mqtt_p_unsuback *unsuback = (struct rrr_mqtt_p_unsuback *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_UNSUBACK, packet->protocol_version);
	if (unsuback == NULL) {
		RRR_MSG_0("Could not allocate UNSUBACK packet in __rrr_mqtt_broker_handle_unsubscribe \n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	unsigned int dummy;

	// Session subsystem will update the subscription list and set reason codes for each topic
	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->receive_packet(
					mqtt_data->sessions,
					&connection->session,
					packet,
					&dummy
			),
			goto out,
			" while sending UNSUBSCRIBE message to session in __rrr_mqtt_broker_handle_unsubscribe "
	);

	RRR_MQTT_P_LOCK(unsuback);
	unsuback->packet_identifier = unsubscribe->packet_identifier;
	unsuback->subscriptions_ = unsubscribe->subscriptions;
	unsubscribe->subscriptions = NULL;
	RRR_MQTT_P_UNLOCK(unsuback);

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			mqtt_data->sessions->methods->send_packet(
					mqtt_data->sessions,
					&connection->session,
					(struct rrr_mqtt_p *) unsuback,
					0
			),
			goto out,
			" while sending UNSUBACK to session in __rrr_mqtt_broker_handle_unsubscribe"
	);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(unsuback);
	return ret;
}

static int __rrr_mqtt_broker_handle_pingreq (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = 0;
	struct rrr_mqtt_p_pingresp *pingresp = NULL;

	(void)(mqtt_data);

	pingresp = (struct rrr_mqtt_p_pingresp *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_PINGRESP, packet->protocol_version);
	if (pingresp == NULL) {
		RRR_MSG_0("Could not allocate CONNACK packet in rrr_mqtt_p_handler_connect\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	RRR_MQTT_P_LOCK(pingresp);
	ret = rrr_mqtt_conn_iterator_ctx_send_packet(handle, (struct rrr_mqtt_p *) pingresp);
	RRR_MQTT_P_UNLOCK(pingresp);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(pingresp);
	return ret;
}

static int __rrr_mqtt_broker_handle_auth (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;
	int ret = 0;
	return ret;
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
	{rrr_mqtt_common_handle_disconnect},
	{__rrr_mqtt_broker_handle_auth}
};

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
			RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO (
				data->client_count--;
				data->stats.total_connections_closed++;
				if (data->client_count < 0) {
					RRR_BUG("client count was < 0 in __rrr_mqtt_broker_event_handler\n");
				}
			);
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
	// We don't disallow the whole subscription, only set reason inside
	// each subscription
	int ret = RRR_MQTT_ACL_RESULT_ALLOW;

	RRR_LL_ITERATE_BEGIN(subscribe->subscriptions, struct rrr_mqtt_subscription);
		int ret_tmp = rrr_mqtt_acl_check_access(
				broker->acl,
				node->token_tree,
				RRR_MQTT_ACL_ACTION_RO,
				connection->username,
				rrr_mqtt_topic_match_tokens_recursively_acl
		);
		if (ret_tmp != RRR_MQTT_ACL_RESULT_ALLOW) {
			node->qos_or_reason_v5 = RRR_MQTT_P_5_REASON_NOT_AUTHORIZED;
		}
	RRR_LL_ITERATE_END();

	return ret;
}

static int __rrr_mqtt_broker_acl_handler_publish (
		struct rrr_mqtt_broker_data *broker,
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_ACL_RESULT_DENY;

	ret = rrr_mqtt_acl_check_access (
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
	pthread_mutex_destroy(&broker->client_serial_stats_lock);
	free(broker);
}

void rrr_mqtt_broker_notify_pthread_cancel (struct rrr_mqtt_broker_data *broker) {
	rrr_mqtt_common_data_notify_pthread_cancel(&broker->mqtt_data);
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
) {
	int ret = 0;

	if (max_keep_alive == 0) {
		RRR_DBG_1("Setting max keep alive to 1 in rrr_mqtt_broker_new\n");
		max_keep_alive = 1;
	}

	struct rrr_mqtt_broker_data *res = NULL;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_broker_new\n");
		ret = 1;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = rrr_mqtt_common_data_init (
			&res->mqtt_data,
			handler_properties,
			init_data,
			session_initializer,
			session_initializer_arg,
			__rrr_mqtt_broker_event_handler,
			res,
			__rrr_mqtt_broker_acl_handler,
			res
	)) != 0) {
		RRR_MSG_0("Could not initialize mqtt data in rrr_mqtt_broker_new\n");
		goto out_free;
	}

	if ((ret = pthread_mutex_init(&res->client_serial_stats_lock, 0)) != 0) {
		RRR_MSG_0("Could not initialize lock for client serial number in rrr_mqtt_broker_new\n");
		goto out_destroy_data;
	}

	res->max_clients = init_data->max_socket_connections - 10;
	res->max_keep_alive = max_keep_alive;
	res->disallow_anonymous_logins = disallow_anonymous_logins;
	res->disconnect_on_v31_publish_deny = disconnect_on_v31_publish_deny;
	res->password_file = password_file;
	res->permission_name = permission_name;
	res->acl = acl;

	goto out_success;

	out_destroy_data:
		rrr_mqtt_common_data_destroy(&res->mqtt_data);
	out_free:
		RRR_FREE_IF_NOT_NULL(res);
	out_success:
		*broker = res;
	out:
		return ret;
}

int rrr_mqtt_broker_accept_connections (
		struct rrr_mqtt_broker_data *data,
		int listen_handle
) {
	int ret = 0;

	unsigned int accepted_count = 0;

	int new_handle = 0;

	do {
		new_handle = 0;
		ret = rrr_mqtt_transport_accept (
				&new_handle,
				data->mqtt_data.transport,
				listen_handle,
				rrr_mqtt_conn_accept_and_connect_callback
		);
		if (new_handle != 0) {
			accepted_count++;
		}
	} while (new_handle != 0 && (ret & RRR_MQTT_INTERNAL_ERROR) == 0);

	// Do this also upon errors
	if (accepted_count > 0) {
		RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO (
				data->stats.total_connections_accepted += accepted_count
		);
	}

	if ((ret & RRR_MQTT_INTERNAL_ERROR) != 0) {
		RRR_MSG_0("Internal error in rrr_mqtt_broker_accept_connections while accepting connections\n");
		ret = 1;
		goto out;
	}

	if (ret != 0) {
		RRR_MSG_0("Error while accepting connections in rrr_mqtt_broker_accept_connections\n");
	}

	out:
	return ((ret & RRR_MQTT_INTERNAL_ERROR) != 0) ? 1 : 0;
}

int rrr_mqtt_broker_synchronized_tick (
		int *something_happened,
		struct rrr_mqtt_broker_data *data,
		int listen_handle
) {
	int ret = 0;

	if ((ret = rrr_mqtt_broker_accept_connections (
			data,
			listen_handle
	)) != 0) {
		goto out;
	}

	struct rrr_mqtt_session_iterate_send_queue_counters session_iterate_counters = {0};

	if ((ret = rrr_mqtt_common_read_parse_handle (
			&session_iterate_counters,
			something_happened,
			&data->mqtt_data,
			NULL,
			NULL
	)) != 0) {
		goto out;
	}

	if ((ret = data->mqtt_data.sessions->methods->maintain (
			data->mqtt_data.sessions
	)) != 0) {
		goto out;
	}

	out:
	// Always update. Connection framework might successfully close connections before producing errors,
	// in which the counter will have been incremented.
	RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO(data->stats.total_connections_closed += 0);

	return ret;
}

void rrr_mqtt_broker_get_stats (
		struct rrr_mqtt_broker_stats *target,
		struct rrr_mqtt_broker_data *data
) {
	RRR_MQTT_BROKER_WITH_SERIAL_LOCK_DO (
			if (data->mqtt_data.sessions->methods->get_stats (
					&data->stats.session_stats,
					data->mqtt_data.sessions
			) != 0) {
				RRR_MSG_0("Warning: Failed to get session stats in rrr_mqtt_broker_get_stats\n");
			}

			data->stats.connections_active = data->client_count;

			*target = data->stats;
	);
}
