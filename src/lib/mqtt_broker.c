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

#include "../global.h"
#include "mqtt_packet.h"
#include "mqtt_common.h"
#include "mqtt_broker.h"
#include "mqtt_session.h"
#include "mqtt_property.h"
#include "linked_list.h"

const struct rrr_mqtt_session_properties default_session_properties = {
		session_expiry:					RRR_MQTT_BROKER_SESSION_EXPIRY,
		receive_maximum:				0,
		maximum_packet_size:			0,
		topic_alias_maximum:			0,
		request_response_information:	0,
		request_problem_information:	0,
		{0},
		NULL,
		NULL
};

static void __rrr_mqtt_broker_destroy_listen_fd (struct rrr_mqtt_listen_fd *fd) {
	VL_DEBUG_MSG_1 ("mqtt broker close listen fd %i\n", fd->ip.fd);
	ip_network_cleanup(&fd->ip);
	free(fd);
}

static void __rrr_mqtt_broker_destroy_listen_fds_elements (struct rrr_mqtt_listen_fd_collection *fds) {
	pthread_mutex_lock(&fds->lock);

	RRR_LINKED_LIST_DESTROY(fds, struct rrr_mqtt_listen_fd, __rrr_mqtt_broker_destroy_listen_fd(node));

	pthread_mutex_unlock(&fds->lock);
}

static void __rrr_mqtt_broker_destroy_listen_fds (struct rrr_mqtt_listen_fd_collection *fds) {
	__rrr_mqtt_broker_destroy_listen_fds_elements(fds);
	pthread_mutex_destroy(&fds->lock);
}

static int __rrr_mqtt_broker_init_listen_fds (struct rrr_mqtt_listen_fd_collection *fds) {
	memset(fds, '\0', sizeof(*fds));
	return pthread_mutex_init(&fds->lock, 0);
}

static struct rrr_mqtt_listen_fd *__rrr_mqtt_broker_listen_fd_allocate_unlocked (
		struct rrr_mqtt_listen_fd_collection *fds
) {
	struct rrr_mqtt_listen_fd *ret = malloc (sizeof(*ret));
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_broker_listen_fd_allocate_unlocked\n");
		goto out;
	}

	memset (ret, '\0', sizeof(*ret));

	RRR_LINKED_LIST_APPEND(fds, ret);

	out:
	return ret;
}

static void __rrr_mqtt_broker_listen_fd_remove_unlocked (
		struct rrr_mqtt_listen_fd_collection *fds,
		struct rrr_mqtt_listen_fd *fd
) {
	int old_count = RRR_LINKED_LIST_COUNT(fds);

	RRR_LINKED_LIST_REMOVE_NODE(fds, struct rrr_mqtt_listen_fd, fd, __rrr_mqtt_broker_destroy_listen_fd(node));

	if (old_count == RRR_LINKED_LIST_COUNT(fds)) {
		VL_BUG("FD not found in __rrr_mqtt_broker_listen_fd_destroy_unlocked\n");
	}
}

static int __rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		struct rrr_mqtt_listen_fd_collection *fds,
		int port,
		int max_connections
) {
	int ret = 0;

	pthread_mutex_lock(&fds->lock);

	struct rrr_mqtt_listen_fd *fd = __rrr_mqtt_broker_listen_fd_allocate_unlocked(fds);
	if (fd == NULL) {
		ret = 1;
		goto out_unlock;
	}

	fd->ip.port = port;

	if ((ret = ip_network_start_tcp_ipv4_and_ipv6(&fd->ip, max_connections)) != 0) {
		VL_MSG_ERR("Could not start network in __rrr_mqtt_broker_listen_ipv4_and_ipv6\n");
		goto out_destroy_fd;
	}

	goto out_unlock;

	out_destroy_fd:
	__rrr_mqtt_broker_listen_fd_remove_unlocked(fds, fd);

	out_unlock:
	pthread_mutex_unlock(&fds->lock);

	return ret;
}

static int __rrr_mqtt_broker_listen_fd_accept_connections (
		struct rrr_mqtt_listen_fd *fd,
		const char *creator,
		int (*callback)(const struct ip_accept_data *accept_data, void *arg),
		void *callback_arg
) {
	struct ip_accept_data *accept_data = NULL;

	int ret = 0;

	do {
		if ((ret = ip_accept(&accept_data, &fd->ip, creator, 1)) != 0) {
			VL_MSG_ERR("Error from ip_accept in __rrr_mqtt_broker_listen_fd_accept_connections\n");
			break;
		}

		if (accept_data != NULL) {
			ret = callback(accept_data, callback_arg);
			if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0) {
				VL_MSG_ERR("Soft error while accepting connection\n");
				ret = ret & ~(RRR_MQTT_CONN_SOFT_ERROR);
			}
			if (ret != 0) {
				VL_MSG_ERR("Error from callback function in __rrr_mqtt_broker_listen_fd_accept_connections\n");
				break;
			}
		}

		RRR_FREE_IF_NOT_NULL(accept_data);
	} while (accept_data != NULL);

	RRR_FREE_IF_NOT_NULL(accept_data);

	return ret;
}

static int __rrr_mqtt_broker_listen_fds_accept_connections (
		struct rrr_mqtt_listen_fd_collection *fds,
		const char *creator,
		int (*callback)(const struct ip_accept_data *accept_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&fds->lock);

	RRR_LINKED_LIST_ITERATE_BEGIN(fds, struct rrr_mqtt_listen_fd);
		/* Save the error flag but loop the rest of the FDs even if one FD fails */
		int ret_tmp = __rrr_mqtt_broker_listen_fd_accept_connections(node, creator, callback, callback_arg);
		if (ret_tmp != 0) {
			VL_MSG_ERR("Error while accepting connections in __rrr_mqtt_broker_listen_fds_accept_connections\n");
			ret = 1;
		}
	RRR_LINKED_LIST_ITERATE_END();

	pthread_mutex_unlock(&fds->lock);

	return ret;
}

int rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		struct rrr_mqtt_broker_data *broker,
		int port,
		int max_connections
) {
	return __rrr_mqtt_broker_listen_ipv4_and_ipv6(&broker->listen_fds, port, max_connections);
}

void rrr_mqtt_broker_stop_listening (struct rrr_mqtt_broker_data *broker) {
	__rrr_mqtt_broker_destroy_listen_fds_elements (&broker->listen_fds);
}

struct validate_client_id_callback_data {
	struct rrr_mqtt_conn *orig_connection;
	const char *client_id;
	int disconnect_other_client;
};

static int __rrr_mqtt_broker_check_unique_client_id_callback (struct rrr_mqtt_conn *connection, void *arg) {
	struct validate_client_id_callback_data *data = arg;

	if (data->orig_connection == connection) {
		// Don't validate ourselves (would have been stupid)
		return RRR_MQTT_CONN_OK;
	}

	int ret = RRR_MQTT_CONN_OK;

	RRR_MQTT_CONN_LOCK(connection);

	if (!RRR_MQTT_CONN_STATE_SEND_IS_BUSY_CLIENT_ID(connection)) {
		// Equal name with a CLOSED connection is OK
		ret = RRR_MQTT_CONN_OK;
		goto out;
	}

	/* client_id is not set in the connection until CONNECT packet is handled */
	if (connection->client_id != NULL && strcmp(connection->client_id, data->client_id) == 0) {
		ret |= RRR_MQTT_CONN_ITERATE_STOP;

		if (data->disconnect_other_client == 0) {
			goto out;
		}

		VL_DEBUG_MSG_1("Disconnecting existing client with client ID %s\n", connection->client_id);

		int ret_tmp = rrr_mqtt_conn_iterator_ctx_send_disconnect(connection, RRR_MQTT_P_5_REASON_SESSION_TAKEN_OVER);

		// On soft error, we cannot be sure that the existing client was actually
		// disconnected, and we must disallow the new connection
		if ((ret_tmp & RRR_MQTT_CONN_SOFT_ERROR) != 0) {
			VL_MSG_ERR("Soft error while disconnecting existing client in __rrr_mqtt_broker_check_unique_client_id_or_disconnect_callback\n");
			ret_tmp = ret & ~RRR_MQTT_CONN_SOFT_ERROR;
			ret |= RRR_MQTT_CONN_SOFT_ERROR;
		}

		// We are not allowed to destroy the connection inside the read_to_write-iterator, it must be done by housekeeping
		ret_tmp = ret_tmp & ~RRR_MQTT_CONN_DESTROY_CONNECTION;

		if (ret_tmp != RRR_MQTT_CONN_OK) {
			VL_MSG_ERR("Internal error while disconnecting existing client in __rrr_mqtt_broker_check_unique_client_id_or_disconnect_callback\n");
			ret |= RRR_MQTT_CONN_INTERNAL_ERROR;
		}
	}

	out:
	RRR_MQTT_CONN_UNLOCK(connection);

	return ret;
}

/* If the client specifies a Client ID, we do not accept duplicates or IDs beginning
 * with RRR_MQTT_BROKER_CLIENT_PREFIX. We do, however, accept IDs beginning with the
 * prefix if a session with this prefix already exists. If a new connection with an
 * existing client ID appears, the old client is to be disconnected. */
static int __rrr_mqtt_broker_check_unique_client_id (
		const char *client_id,
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *broker,
		int disconnect_other_client,
		int *other_client_was_disconnected
) {
	int ret = 0;

	struct validate_client_id_callback_data callback_data = { connection, client_id, disconnect_other_client };

	/* We need to hold write lock to verify the client ID to avoid races*/
	ret = rrr_mqtt_conn_collection_iterate_reenter_read_to_write (
			&broker->mqtt_data.connections,
			__rrr_mqtt_broker_check_unique_client_id_callback,
			&callback_data
	);

	if (ret != RRR_MQTT_CONN_OK) {
		if ((ret & RRR_MQTT_CONN_ITERATE_STOP) != 0) {
			VL_DEBUG_MSG_1("Client id %s was already used in an active connection, the old one was disconnected\n", client_id);
			ret = (ret & ~RRR_MQTT_CONN_ITERATE_STOP);
			*other_client_was_disconnected = 1;
		}

		int old_ret = ret;
		if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0) {
			VL_MSG_ERR("Soft error while checking for unique client ID %s, must disconnect the client\n", client_id);
			ret = (ret & ~RRR_MQTT_CONN_SOFT_ERROR);
		}
		if (ret != 0) {
			VL_MSG_ERR("Internal error while checking for unique client ID %s, must close the server.\n", client_id);
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		}
		ret |= old_ret;
	}

	return ret;
}

static int __rrr_mqtt_broker_generate_unique_client_id (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_broker_data *broker
) {
	int ret = 0;
	uint32_t serial = 0;

	// We must hold this lock to check for unique ID, if not, it is possible to deadlock
	// if two connections try to check each others ID at the same time. We must also
	// protect the serial counter
	pthread_mutex_lock(&broker->client_serial_and_count_lock);

	char *result = malloc(64);
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_broker_generate_client_id\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}
	memset (result, '\0', 64);

	// On error, the connection destroy function will free this memory, The
	// current connection is locked since we come from packet handler context
	// and it is not possible for others to read our unfinished client id, they
	// will of course lock the connection before trying that.
	connection->client_id = result;

	int retries = RRR_MQTT_BROKER_MAX_GENERATED_CLIENT_IDS;
	while (--retries >= 0) {
		// We let the serial overflow
		serial = ++(broker->client_serial);

		sprintf(result, RRR_MQTT_BROKER_CLIENT_PREFIX "%u", serial);

		int dummy = 0;
		ret = __rrr_mqtt_broker_check_unique_client_id (result, connection, broker, 0, &dummy);

		if (dummy != 0) {
			VL_BUG("dummy was not 0 in __rrr_mqtt_broker_generate_unique_client_id\n");
		}

		if (ret != 0) {
			ret = ret & ~RRR_MQTT_CONN_SOFT_ERROR;
			if (ret == 0) {
				continue;
			}

			VL_MSG_ERR("Error while validating client ID in __rrr_mqtt_broker_generate_unique_client_id: %i\n", ret);
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
			goto out;
		}
	}

	if (retries <= 0) {
		VL_MSG_ERR("Number of generated client IDs reached maximum in __rrr_mqtt_broker_generate_unique_client_id\n");
		ret = RRR_MQTT_CONN_SOFT_ERROR;
		goto out;
	}

	out:
	pthread_mutex_unlock(&broker->client_serial_and_count_lock);

	return RRR_MQTT_CONN_OK;
}

#define HANDLE_PROPERTIES_CALLBACK_DATA_HEAD			\
	const struct rrr_mqtt_property_collection *source;	\
	uint8_t reason_v5

struct parse_properties_data {
	HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
};

struct parse_properties_data_connect {
	HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_session_properties session_properties;
};

#define HANDLE_PROPERTIES(target,callback,action_on_error)											\
	do {if ((ret = __rrr_mqtt_p_handle_properties (													\
			(target),																				\
			callback,																			\
			(struct parse_properties_data*) &callback_data,											\
			&reason_v5																				\
	)) != 0) {																						\
		if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0) {												\
			VL_MSG_ERR("Soft error while iterating %s source_properties\n",							\
					RRR_MQTT_P_GET_TYPE_NAME(packet));												\
			ret = ret & ~(RRR_MQTT_CONN_SOFT_ERROR);												\
		}																							\
		if (ret != 0) {																				\
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;														\
			VL_MSG_ERR("Internal error while iterating %s source_properties, return was %i\n",		\
					RRR_MQTT_P_GET_TYPE_NAME(packet), ret);											\
			goto out;																				\
		}																							\
																									\
		ret = RRR_MQTT_CONN_SOFT_ERROR;																\
		action_on_error;																			\
	}} while(0)

#define HANDLE_PROPERTY_CHECK_DUP()																				\
	do {unsigned int dup_count = 0;																				\
	if (	RRR_MQTT_PROPERTY_GET_ID(property) != RRR_MQTT_PROPERTY_USER_PROPERTY &&							\
			(dup_count = rrr_mqtt_property_collection_count_duplicates(callback_data->source, property)) != 0	\
	) {																											\
		VL_MSG_ERR("Property '%s' was specified more than once (%u times) in packet\n",							\
				RRR_MQTT_PROPERTY_GET_NAME(property), dup_count + 1);											\
		goto out_reason_protocol_error;																			\
	}} while (0)

#define HANDLE_PROPERTY_SWITCH_BEGIN()										\
	int ret = RRR_MQTT_CONN_OK;												\
	HANDLE_PROPERTY_CHECK_DUP();											\
	do { switch (RRR_MQTT_PROPERTY_GET_ID(property)) {						\
		case 0:																\
			VL_BUG("Property id was 0 in HANDLE_PROPERTY_SWITCH_BEGIN\n");	\
			break

#define HANDLE_PROPERTY_UINT32_UNCHECKED(target,id) 						\
		case id:															\
			(target) = rrr_mqtt_property_get_uint32(property);				\
			break

#define HANDLE_PROPERTY_UINT32_NON_ZERO(target,id,error_msg)				\
		case id:															\
			(target) = rrr_mqtt_property_get_uint32(property);				\
			if ((target) == 0) {											\
				VL_MSG_ERR(error_msg "\n");									\
				goto out_reason_protocol_error;								\
			}																\
			break

#define HANDLE_PROPERTY_UINT32_ON_OFF(target,id,error_msg)					\
		case id:															\
			(target) = rrr_mqtt_property_get_uint32(property);				\
			if ((target) > 1) {												\
				VL_MSG_ERR(error_msg "\n");									\
				goto out_reason_protocol_error;								\
			}																\
			break

#define HANDLE_PROPERTY_USER_PROPERTY(target,id)													\
		case id:																					\
			ret = rrr_mqtt_property_collection_add_cloned((target), property);						\
			if (ret != 0) {																			\
				VL_MSG_ERR("Error while cloning user property in HANDLE_PROPERTY_USER_PROPERTY\n");	\
				goto out_internal_error;															\
			}																						\
			break

#define HANDLE_PROPERTY_CLONE(target,id)															\
		case id:																					\
			if (rrr_mqtt_property_clone((target), property) != 0) {									\
				VL_MSG_ERR("Could not clone property HANDLE_PROPERTY_USER_PROPERTY\n");				\
				goto out_internal_error;															\
			}																						\
			break;

// We do not return error as we want to parse the rest of the source_properties to check
// for more errors. Caller checks for non-zero reason.
#define HANDLE_PROPERTY_SWITCH_END_AND_RETURN() 													\
		default:																					\
			VL_MSG_ERR("Unknown property '%s' for packet", RRR_MQTT_PROPERTY_GET_NAME(property));	\
			goto out_reason_protocol_error;															\
	};																								\
	goto out;																						\
	out_internal_error:																				\
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;															\
		return ret;																					\
	out_reason_protocol_error:																		\
		callback_data->reason_v5 = RRR_MQTT_P_5_REASON_PROTOCOL_ERROR;								\
	out:																							\
		return ret;																					\
	} while (0)

int __handler_connect_parse_properties_callback (const struct rrr_mqtt_property *property, void *arg) {
	struct parse_properties_data_connect *callback_data = arg;
	struct rrr_mqtt_session_properties *session_properties = &callback_data->session_properties;

	HANDLE_PROPERTY_SWITCH_BEGIN();
		HANDLE_PROPERTY_UINT32_UNCHECKED (
				session_properties->session_expiry,
				RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL
		);
		HANDLE_PROPERTY_UINT32_NON_ZERO (
				session_properties->receive_maximum,
				RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM,
				"Receive maximum was 0 in CONNECT packet"
		);
		HANDLE_PROPERTY_UINT32_NON_ZERO (
				session_properties->maximum_packet_size,
				RRR_MQTT_PROPERTY_MAXIMUM_PACKET_SIZE,
				"Maximum packet size was 0 in CONNECT packet"
		);
		HANDLE_PROPERTY_UINT32_UNCHECKED (
				session_properties->topic_alias_maximum,
				RRR_MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM
		);
		HANDLE_PROPERTY_UINT32_ON_OFF (
				session_properties->request_response_information,
				RRR_MQTT_PROPERTY_REQUEST_RESPONSE_INFO,
				"Request response information field in CONNECT packet was not 0 or 1"
		);
		HANDLE_PROPERTY_UINT32_ON_OFF (
				session_properties->request_problem_information,
				RRR_MQTT_PROPERTY_REQUEST_PROBLEM_INFO,
				"Request problem information field in CONNECT packet was not 0 or 1"
		);
		HANDLE_PROPERTY_USER_PROPERTY (
				&session_properties->user_properties,
				RRR_MQTT_PROPERTY_USER_PROPERTY
		);
		HANDLE_PROPERTY_CLONE (
				&session_properties->auth_method,
				RRR_MQTT_PROPERTY_AUTH_METHOD
		);
		HANDLE_PROPERTY_CLONE (
				&session_properties->auth_data,
				RRR_MQTT_PROPERTY_AUTH_DATA
		);
	HANDLE_PROPERTY_SWITCH_END_AND_RETURN();
}

static int __rrr_mqtt_p_handle_properties (
		const struct rrr_mqtt_property_collection *source,
		int (*callback)(const struct rrr_mqtt_property *property, void *arg),
		struct parse_properties_data *callback_data,
		uint8_t *reason_v5
) {
	int ret = RRR_MQTT_CONN_OK;

	*reason_v5 = RRR_MQTT_P_5_REASON_OK;

	if ((ret = rrr_mqtt_property_collection_iterate (
		source,
		callback,
		&callback_data
	)) != 0 || callback_data->reason_v5 != RRR_MQTT_P_5_REASON_OK) {
		if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0) {
			VL_MSG_ERR("Soft error while iterating properties\n");
			ret = ret & ~(RRR_MQTT_CONN_SOFT_ERROR);
		}
		if (ret != 0) {
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
			VL_MSG_ERR("Internal error while iterating properties, return was %i\n", ret);
			goto out;
		}

		if (callback_data->reason_v5 == RRR_MQTT_P_5_REASON_OK) {
			VL_BUG("Callback return error in __rrr_mqtt_p_handle_propertie returned but no reason was set\n");
		}

		ret = RRR_MQTT_CONN_SOFT_ERROR;
		*reason_v5 = callback_data->reason_v5;
	}

	out:
	return ret;
}

static int rrr_mqtt_p_handler_connect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = RRR_MQTT_CONN_OK;
	int ret_destroy = 0;

	struct rrr_mqtt_broker_data *broker = (struct rrr_mqtt_broker_data *) mqtt_data;
	struct rrr_mqtt_p_connect *connect = (struct rrr_mqtt_p_connect *) packet;

	RRR_MQTT_P_LOCK(packet);

	int session_present = 0;
	int other_client_was_disconnected = 0;
	uint8_t reason_v5 = 0;
	struct rrr_mqtt_session *session = NULL;
	struct rrr_mqtt_p_connack *connack = NULL;

	if (connection->client_id != NULL) {
		VL_BUG("Connection client ID was not NULL in rrr_mqtt_p_handler_connect\n");
	}

	rrr_mqtt_conn_iterator_ctx_set_protocol_version_and_keep_alive(connection, packet);

	connack = (struct rrr_mqtt_p_connack *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_CONNACK, connect->protocol_version);
	if (connack == NULL) {
		VL_MSG_ERR("Could not allocate CONNACK packet in rrr_mqtt_p_handler_connect\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	rrr_mqtt_conn_iterator_ctx_update_state (connection, packet, RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_IN);

	if (connect->client_identifier == NULL || *(connect->client_identifier) == '\0') {
		RRR_FREE_IF_NOT_NULL(connect->client_identifier);
		ret = __rrr_mqtt_broker_generate_unique_client_id (connection, broker);
		if (ret != RRR_MQTT_CONN_OK) {
			ret = ret & ~RRR_MQTT_CONN_SOFT_ERROR;
			if (ret == 0) {
				ret = RRR_MQTT_CONN_SOFT_ERROR;
				reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
				goto out_send_connack;
			}
			else {
				VL_MSG_ERR("Could not generate client identifier in rrr_mqtt_p_handler_connect, result is %i\n", ret);
				ret = RRR_MQTT_CONN_INTERNAL_ERROR;
			}
			goto out;
		}
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
						1  // No creation if non-existent client ID
				)) != RRR_MQTT_SESSION_OK) {
					ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
					VL_MSG_ERR("Internal error getting session in rrr_mqtt_p_handler_connect A\n");
					goto out;
				}
				if (session == NULL) {
					VL_MSG_ERR("Client ID cannot begin with '" RRR_MQTT_BROKER_CLIENT_PREFIX "'\n");
					ret = RRR_MQTT_CONN_SOFT_ERROR;
					reason_v5 = RRR_MQTT_P_5_REASON_CLIENT_ID_REJECTED;
					goto out_send_connack;
				}
			}
		}

		// If client ID is already used for active connection, disconnect the old one
		if ((ret = __rrr_mqtt_broker_check_unique_client_id (
				connect->client_identifier,
				connection,
				broker,
				1, // Disconnect existing client with same ID
				&other_client_was_disconnected
		)) != 0) {
			 ret = ret & ~RRR_MQTT_CONN_SOFT_ERROR;
			 if (ret != 0) {
					VL_MSG_ERR("Error while checking for unique client ID in rrr_mqtt_p_handler_connect\n");
					goto out;
			 }
			 VL_MSG_ERR("Error while checking if client id '%s' was unique\n", connect->client_identifier);
			 ret = RRR_MQTT_CONN_SOFT_ERROR;
			 reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
			 goto out_send_connack;
		}

		connection->client_id = malloc(strlen(connect->client_identifier) + 1);
		strcpy(connection->client_id, connect->client_identifier);
	}

	int client_count = 0;
	pthread_mutex_lock(&broker->client_serial_and_count_lock);
	client_count = broker->client_count;
	pthread_mutex_unlock(&broker->client_serial_and_count_lock);

	// If max clients are reached, we only allow connection if another client with
	// the same ID got disconnected. To disconnect it will of course cause the client
	// count to decrement, but there might be a delay before this happens.
	if (other_client_was_disconnected == 0 && client_count >= broker->max_clients) {
		VL_MSG_ERR("Maximum number of clients (%i) reached in rrr_mqtt_p_handler_connect\n",
				broker->max_clients);
		reason_v5 = RRR_MQTT_P_5_REASON_SERVER_BUSY;
		ret = RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out_send_connack;
	}

	pthread_mutex_lock(&broker->client_serial_and_count_lock);
	broker->client_count++;
	pthread_mutex_unlock(&broker->client_serial_and_count_lock);

	VL_DEBUG_MSG_1 ("CONNECT: Using client ID %s client count is %i\n",
			connect->client_identifier, client_count + 1);

	if (session == NULL) {
		if ((ret = mqtt_data->sessions->methods->get_session (
				&session,
				mqtt_data->sessions,
				connect->client_identifier,
				&session_present,
				0 // Create if non-existent client ID
		)) != RRR_MQTT_SESSION_OK || session == NULL) {
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
			VL_MSG_ERR("Internal error getting session in rrr_mqtt_p_handler_connect B\n");
			goto out;
		}
	}

	struct parse_properties_data_connect callback_data = {
			&connect->properties,
			RRR_MQTT_P_5_REASON_OK,
			default_session_properties
	};

	HANDLE_PROPERTIES(&connect->properties, __handler_connect_parse_properties_callback, goto out_send_connack);

	if ((ret = mqtt_data->sessions->methods->init_session (
			mqtt_data->sessions,
			&session,
			&callback_data.session_properties,
			RRR_MQTT_BROKER_RETRY_INTERVAL,
			RRR_MQTT_BROKER_MAX_IN_FLIGHT,
			RRR_MQTT_P_CONNECT_GET_FLAG_CLEAN_START(connect),
			&session_present
	)) != RRR_MQTT_SESSION_OK) {
		if ((ret & RRR_MQTT_SESSION_DELETED) != 0) {
			VL_MSG_ERR("New session was deleted in rrr_mqtt_p_handler_connect\n");
		}
		else {
			VL_MSG_ERR("Error while initializing session in rrr_mqtt_p_handler_connect, return was %i\n", ret);
		}

		ret = RRR_MQTT_CONN_SOFT_ERROR;
		reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
		goto out_send_connack;
	}
	connack->ack_flags = session_present;
	connection->session = session;

	out_send_connack:

	if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0 && reason_v5 == 0) {
		VL_BUG("Reason was not set on soft error in rrr_mqtt_p_handler_connect\n");
	}
	connack->reason_v5 = reason_v5;

	if (connack->protocol_version->id < 5) {
		uint8_t v31_reason = rrr_mqtt_p_translate_reason_from_v5(connack->reason_v5);
		if (v31_reason == RRR_MQTT_P_31_REASON_NO_CONNACK) {
			goto out;
		}
		else if (v31_reason > 5) {
			VL_BUG("Unknown V3.1 CONNECT reason code %u in rrr_mqtt_p_handler_connect, v5 code was %u\n",
					v31_reason, connack->reason_v5);
		}
		// DO NOT store the v31 reason, assembler will convert the v5 reason again later
	}

	RRR_MQTT_P_LOCK(connack);
	ret = rrr_mqtt_conn_iterator_ctx_send_packet(connection, (struct rrr_mqtt_p *) connack);
	RRR_MQTT_P_UNLOCK(connack);

	if ((ret & RRR_MQTT_CONN_DESTROY_CONNECTION) != 0) {
		ret = ret & ~RRR_MQTT_CONN_DESTROY_CONNECTION;
		VL_DEBUG_MSG_1("CONNACK which was sent had non-zero reason, destroying connection\n");
		ret_destroy = RRR_MQTT_CONN_DESTROY_CONNECTION;
	}

	if (ret != 0) {
		VL_MSG_ERR("Error occured while sending CONNACK for sending in rrr_mqtt_p_handler_connect\n");
		goto out;
	}

	out:

	RRR_MQTT_P_UNLOCK(packet);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(connack);
	return ret | ret_destroy;
}

static int rrr_mqtt_p_handler_publish (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = RRR_MQTT_CONN_OK;
	RRR_MQTT_P_LOCK(packet);

	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;

	if (publish->qos == 0) {
		if (publish->reason_v5 != RRR_MQTT_P_5_REASON_OK) {
			VL_MSG_ERR("Closing connection due to malformed PUBLISH packet with QoS 0\n");
			ret = RRR_MQTT_CONN_SOFT_ERROR|RRR_MQTT_CONN_DESTROY_CONNECTION;
			goto out;
		}
	}
	else {
		VL_MSG_ERR("QoS > 0 not implemented in rrr_mqtt_p_handler_publish\n");
		ret = RRR_MQTT_CONN_SOFT_ERROR|RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out;
	}

/*	else if (publish->qos == 1) {
		struct rrr_mqtt_p_puback *puback = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_SUBACK);
	}

	if (publish->reason_v5 != RRR_MQTT_P_5_REASON_OK) {
	}
	else {
	}
*/
	ret = mqtt_data->sessions->methods->receive_publish(mqtt_data->sessions, &connection->session, publish);

	out:
	RRR_MQTT_P_UNLOCK(packet);
	return ret;
}
static int rrr_mqtt_p_handler_puback (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubrec (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubrel (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubcomp (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}

static int rrr_mqtt_p_handler_subscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = RRR_MQTT_CONN_OK;

	//struct rrr_mqtt_broker_data *broker = (struct rrr_mqtt_broker_data *) mqtt_data;
	struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) packet;

	struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_SUBACK, packet->protocol_version);
	if (suback == NULL) {
		VL_MSG_ERR("Could not allocate SUBACK packet in rrr_mqtt_p_handler_subscribe\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	// TODO : Check valid subscriptions (is done now while adding to session), set max QoS etc.

	int ret_tmp = MQTT_COMMON_CALL_SESSION_ADD_SUBSCRIPTIONS(mqtt_data, connection->session, subscribe->subscriptions);
	if (ret_tmp != RRR_MQTT_SESSION_OK) {
		if ((ret_tmp & RRR_MQTT_SESSION_DELETED) != 0) {
			VL_MSG_ERR("Session was deleted in rrr_mqtt_p_handler_subscribe\n");
			ret |= RRR_MQTT_CONN_DESTROY_CONNECTION;
		}
		if ((ret_tmp & RRR_MQTT_SESSION_ERROR) != 0) {
			VL_MSG_ERR("Soft error from session while adding subscriptions in rrr_mqtt_p_handler_subscribe\n");
			ret |= RRR_MQTT_CONN_SOFT_ERROR;
		}
		ret_tmp = ret_tmp & ~(RRR_MQTT_SESSION_DELETED|RRR_MQTT_SESSION_ERROR);

		if (ret_tmp != 0) {
			VL_MSG_ERR("Internal error while adding subscriptions in rrr_mqtt_p_handler_subscribe\n");
			ret |= RRR_MQTT_CONN_INTERNAL_ERROR;
		}
		goto out;
	}

	RRR_MQTT_P_LOCK(suback);

	suback->packet_identifier = subscribe->packet_identifier;
	suback->subscriptions = subscribe->subscriptions;
	subscribe->subscriptions = NULL;

	RRR_MQTT_P_INCREF(suback);
	ret = rrr_mqtt_conn_iterator_ctx_queue_outbound_packet(connection, (struct rrr_mqtt_p *) suback);
	RRR_MQTT_P_UNLOCK(suback);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(suback);
	return ret;
}

static int rrr_mqtt_p_handler_unsubscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}

static int rrr_mqtt_p_handler_pingreq (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	struct rrr_mqtt_p_pingresp *pingresp = NULL;

	(void)(mqtt_data);

	RRR_MQTT_P_LOCK(packet);

	pingresp = (struct rrr_mqtt_p_pingresp *) rrr_mqtt_p_allocate (RRR_MQTT_P_TYPE_PINGRESP, packet->protocol_version);
	if (pingresp == NULL) {
		VL_MSG_ERR("Could not allocate CONNACK packet in rrr_mqtt_p_handler_connect\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	RRR_MQTT_P_LOCK(pingresp);
	ret = rrr_mqtt_conn_iterator_ctx_send_packet(connection, (struct rrr_mqtt_p *) pingresp);
	RRR_MQTT_P_UNLOCK(pingresp);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(pingresp);
	RRR_MQTT_P_UNLOCK(packet);
	return ret;
}

static int rrr_mqtt_p_handler_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;

	(void)(mqtt_data);

	RRR_MQTT_P_LOCK(packet);

	if ((ret = rrr_mqtt_conn_iterator_ctx_update_state (
			connection,
			packet,
			RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_IN
	)) != RRR_MQTT_CONN_OK) {
		VL_MSG_ERR("Could not update connection state in rrr_mqtt_p_handler_disconnect\n");
		goto out;
	}

	out:
	RRR_MQTT_P_UNLOCK(packet);
	return ret | RRR_MQTT_CONN_DESTROY_CONNECTION;
}

static int rrr_mqtt_p_handler_auth (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;

}

static const struct rrr_mqtt_type_handler_properties handler_properties[] = {
	{NULL},
	{rrr_mqtt_p_handler_connect},
	{NULL},
	{rrr_mqtt_p_handler_publish},
	{rrr_mqtt_p_handler_puback},
	{rrr_mqtt_p_handler_pubrec},
	{rrr_mqtt_p_handler_pubrel},
	{rrr_mqtt_p_handler_pubcomp},
	{rrr_mqtt_p_handler_subscribe},
	{NULL},
	{rrr_mqtt_p_handler_unsubscribe},
	{NULL},
	{rrr_mqtt_p_handler_pingreq},
	{NULL},
	{rrr_mqtt_p_handler_disconnect},
	{rrr_mqtt_p_handler_auth}
};

static int __rrr_mqtt_broker_event_handler (struct rrr_mqtt_conn *connection, int event, void *arg) {
	struct rrr_mqtt_broker_data *data = arg;

	(void)(connection);

	int ret = RRR_MQTT_CONN_OK;

	switch (event) {
		case RRR_MQTT_CONN_EVENT_DISCONNECT:
			pthread_mutex_lock(&data->client_serial_and_count_lock);
			data->client_count--;
			if (data->client_count < 0) {
				VL_BUG("client count was < 0 in __rrr_mqtt_broker_event_handler\n");
			}
			pthread_mutex_unlock(&data->client_serial_and_count_lock);
			break;
		default:
			break;
	};

	return ret;
}

void rrr_mqtt_broker_destroy (struct rrr_mqtt_broker_data *broker) {
	/* Caller should make sure that no more connections are accepted at this point */
	__rrr_mqtt_broker_destroy_listen_fds(&broker->listen_fds);
	rrr_mqtt_common_data_destroy(&broker->mqtt_data);
	pthread_mutex_destroy(&broker->client_serial_and_count_lock);
	free(broker);
}

int rrr_mqtt_broker_new (
		struct rrr_mqtt_broker_data **broker,
		const char *client_name,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg
) {
	int ret = 0;

	struct rrr_mqtt_broker_data *res = NULL;

	// The max_clients is a soft limit which is checked when handling
	// CONNECT packets, and CONNACKs with a reason is sent back if this.
	// limit is reached. The max_socket_connections-limit is a harder
	// limit which makes the connection framework close new connections
	// when it is reached.
	int max_socket_connections = RRR_MQTT_BROKER_MAX_SOCKETS;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_broker_new\n");
		ret = 1;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = rrr_mqtt_common_data_init (
			&res->mqtt_data,
			client_name,
			handler_properties,
			session_initializer,
			session_initializer_arg,
			__rrr_mqtt_broker_event_handler,
			res,
			RRR_MQTT_BROKER_CLOSE_WAIT_TIME * 1000000,
			max_socket_connections
	)) != 0) {
		VL_MSG_ERR("Could not initialize mqtt data in rrr_mqtt_broker_new\n");
		goto out_free;
	}

	if ((ret = __rrr_mqtt_broker_init_listen_fds(&res->listen_fds)) != 0) {
		VL_MSG_ERR("Could not initialize listen FD collection in rrr_mqtt_broker_new\n");
		goto out_destroy_data;
	}

	if ((ret = pthread_mutex_init(&res->client_serial_and_count_lock, 0)) != 0) {
		VL_MSG_ERR("Could not initialize lock for client serial number in rrr_mqtt_broker_new\n");
		goto out_destroy_listen_fds;
	}

	res->max_clients = RRR_MQTT_BROKER_MAX_CLIENTS;

	goto out_success;

	out_destroy_listen_fds:
		__rrr_mqtt_broker_destroy_listen_fds(&res->listen_fds);
	out_destroy_data:
		rrr_mqtt_common_data_destroy(&res->mqtt_data);
	out_free:
		RRR_FREE_IF_NOT_NULL(res);
	out_success:
		*broker = res;
	out:
		return ret;
}

struct accept_connections_callback_data {
	struct rrr_mqtt_broker_data *data;
	int connection_count;
};

static int __rrr_mqtt_broker_accept_connections_callback (
		const struct ip_accept_data *accept_data,
		void *callback_arg
) {
	struct accept_connections_callback_data *callback_data = callback_arg;
	struct rrr_mqtt_broker_data *data = callback_data->data;

	int ret = 0;
	int ret_tmp = 0;

	if ((ret_tmp = rrr_mqtt_common_data_register_connection(&data->mqtt_data, accept_data)) != RRR_MQTT_CONN_OK) {
		if ((ret_tmp & RRR_MQTT_CONN_BUSY) != 0) {
			VL_MSG_ERR("Too many connections was open in __rrr_mqtt_broker_accept_connections_callback\n");
			ret_tmp = ret_tmp & ~(RRR_MQTT_CONN_BUSY);
			ret |= RRR_MQTT_CONN_SOFT_ERROR;
		}
		if (ret_tmp != RRR_MQTT_CONN_OK) {
			VL_MSG_ERR("Could not register new connection in __rrr_mqtt_broker_accept_connections_callback\n");
		}
	}
	else {
		callback_data->connection_count++;
	}

	return ret;
}

int rrr_mqtt_broker_accept_connections (struct rrr_mqtt_broker_data *data) {
	int ret = 0;

	struct accept_connections_callback_data callback_data = {
			data, 0
	};

	ret = __rrr_mqtt_broker_listen_fds_accept_connections (
			&data->listen_fds,
			data->mqtt_data.client_name,
			__rrr_mqtt_broker_accept_connections_callback,
			&callback_data
	);

	if (ret != 0) {
		VL_MSG_ERR("Error while acceptign connections in rrr_mqtt_broker_accept_connections\n");
	}

	if (callback_data.connection_count > 0) {
		printf ("rrr_mqtt_broker_accept_connections: accepted %i connections\n",
				callback_data.connection_count);
	}

	return ret;
}

int rrr_mqtt_broker_synchronized_tick (struct rrr_mqtt_broker_data *data) {
	int ret = 0;

	if ((ret = rrr_mqtt_broker_accept_connections(data)) != 0) {
		goto out;
	}

	if ((ret = rrr_mqtt_common_read_parse_handle (&data->mqtt_data)) != 0) {
		goto out;
	}
/*
 * 			struct rrr_mqtt_session_collection *,
			int (*send_callback)(struct rrr_mqtt_p *packet, void *arg),
			void *send_callback_arg
 */
	if ((ret = data->mqtt_data.sessions->methods->maintain (
			data->mqtt_data.sessions
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
