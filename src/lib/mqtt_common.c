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

#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_session.h"

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data) {
	if (data == NULL) {
		return;
	}

	if (data->connections.invalid == 0) {
		rrr_mqtt_conn_collection_destroy(&data->connections);
	}

	if (data->sessions != NULL) {
		data->sessions->methods->destroy(data->sessions);
	}

	*(data->client_name) = '\0';
	data->handler_properties = NULL;
}

/*
 * We are called in here from the connection framework on packet events as it
 * is unaware of sessions. We assess here whether something needs to be updated
 * in the sessions or not. The downstream session storage engine
 * is also called as it might have stuff to maintain. Packets which come in
 * and are handled by the broker or client, are NOT passed to the
 * session framework through this function. The packet handlers notify the sessions
 * directly. This goes for PUBLISH and SUBSCRIBE.
 */
static int __rrr_mqtt_common_connection_event_handler (
		struct rrr_mqtt_conn *connection,
		int event,
		void *static_arg,
		void *arg
) {
	struct rrr_mqtt_data *data = static_arg;

	int ret = 0;
	int ret_tmp = 0;

	// session is NULL for instance after parsing CONNECT packet
	if (connection->session == NULL) {
		goto out;
	}

	// Call downstream event handler (broker/client), must be called first in
	// case session-stuff fails due to client counters
	ret_tmp = data->event_handler(connection, event, data->event_handler_static_arg, arg);
	if (ret_tmp != 0) {
		if ((ret_tmp & RRR_MQTT_CONN_SOFT_ERROR) != 0) {
			ret |= RRR_MQTT_CONN_SOFT_ERROR;
		}
		if ((ret_tmp & RRR_MQTT_CONN_DESTROY_CONNECTION) != 0) {
			ret |= RRR_MQTT_CONN_DESTROY_CONNECTION;
		}

		ret_tmp = ret_tmp & ~(RRR_MQTT_CONN_SOFT_ERROR|RRR_MQTT_CONN_DESTROY_CONNECTION);

		if (ret_tmp != 0) {
			VL_MSG_ERR("Internal error while calling downstream event handler in __rrr_mqtt_common_connection_event_handler with event %i return was %i\n",
					event, ret_tmp);
			ret |= RRR_MQTT_CONN_INTERNAL_ERROR;
			goto out;
		}
	}

	switch (event) {
		case RRR_MQTT_CONN_EVENT_DISCONNECT:
			ret_tmp = MQTT_COMMON_CALL_SESSION_NOTIFY_DISCONNECT(data, connection->session, connection->disconnect_reason_v5_);
			break;
		case RRR_MQTT_CONN_EVENT_PACKET_PARSED:
			ret_tmp = MQTT_COMMON_CALL_SESSION_HEARTBEAT(data, connection->session);
			break;
		case RRR_MQTT_CONN_EVENT_ACK_SENT:
			// Nothing to do
			ret_tmp = RRR_MQTT_CONN_OK;
			break;
		default:
			VL_BUG("Unknown event %i in __rrr_mqtt_common_connection_event_handler\n", event);
	}
	if (ret_tmp != 0) {
		if ((ret_tmp & RRR_MQTT_SESSION_DELETED) != 0) {
			// It is normal to return DELETED from disconnect event
			if (event != RRR_MQTT_CONN_EVENT_DISCONNECT) {
				VL_MSG_ERR("Session was deleted while calling session storage engine in __rrr_mqtt_common_connection_event_handler with event %i\n", event);
			}
			ret |= RRR_MQTT_CONN_DESTROY_CONNECTION;
		}
		if ((ret_tmp & RRR_MQTT_SESSION_ERROR) != 0) {
			VL_MSG_ERR("Session error while calling session storage engine in __rrr_mqtt_common_connection_event_handler with event %i\n", event);
			ret |= RRR_MQTT_CONN_SOFT_ERROR;
		}

		ret_tmp = ret_tmp & ~(RRR_MQTT_SESSION_ERROR|RRR_MQTT_SESSION_DELETED);

		if (ret_tmp != 0) {
			VL_MSG_ERR("Internal error while calling session storage engine in __rrr_mqtt_common_connection_event_handler with event %i return was %i\n",
					event, ret_tmp);
			ret |= RRR_MQTT_CONN_INTERNAL_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_mqtt_common_data_init (struct rrr_mqtt_data *data,
		const char *client_name,
		const struct rrr_mqtt_type_handler_properties *handler_properties,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_static_arg,
		uint64_t retry_interval_usec,
		uint64_t close_wait_time_usec,
		int max_socket_connections
) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	if (strlen(client_name) > RRR_MQTT_DATA_CLIENT_NAME_LENGTH) {
		VL_MSG_ERR("Client name was too long in rrr_mqtt_data_init\n");
		ret = 1;
		goto out;
	}

	data->event_handler = event_handler;
	data->event_handler_static_arg = event_handler_static_arg;
	data->retry_interval_usec = retry_interval_usec;
	data->close_wait_time_usec = close_wait_time_usec;
	data->handler_properties = handler_properties;
	strcpy(data->client_name, client_name);

	if (rrr_mqtt_conn_collection_init (
			&data->connections,
			max_socket_connections,
			__rrr_mqtt_common_connection_event_handler,
			data
	) != 0) {
		VL_MSG_ERR("Could not initialize connection collection in rrr_mqtt_data_new\n");
		ret = 1;
		goto out;
	}

	if (session_initializer (&data->sessions, session_initializer_arg) != 0) {
		VL_MSG_ERR("Could not initialize session data in rrr_mqtt_data_new\n");
		ret = 1;
		goto out_destroy_connections;
	}

	goto out;

	out_destroy_connections:
		rrr_mqtt_conn_collection_destroy(&data->connections);

	out:
		return ret;
}

int rrr_mqtt_common_register_connection (
		struct rrr_mqtt_common_remote_handle *target_handle,
		struct rrr_mqtt_data *data,
		const struct ip_accept_data *accept_data
) {
	int ret = 0;
	int ret_tmp = 0;

	memset(target_handle, '\0', sizeof(*target_handle));

	struct rrr_mqtt_conn *connection;

	if ((ret_tmp = rrr_mqtt_conn_collection_new_connection (
			&connection,
			&data->connections,
			&accept_data->ip_data,
			&accept_data->addr,
			data->retry_interval_usec,
			data->close_wait_time_usec
	)) != RRR_MQTT_CONN_OK) {
		if ((ret_tmp & RRR_MQTT_CONN_BUSY) != 0) {
			VL_MSG_ERR("Too many connections was open in rrr_mqtt_common_register_connection\n");
			ret_tmp = ret_tmp & ~(RRR_MQTT_CONN_BUSY);
			ret |= RRR_MQTT_CONN_SOFT_ERROR;
		}
		if (ret_tmp != RRR_MQTT_CONN_OK) {
			VL_MSG_ERR("Could not register new connection in rrr_mqtt_common_register_connection\n");
		}
	}
	else {
		target_handle->connection = connection;
	}

	return ret;
}

#define HANDLE_PROPERTY_CHECK_DUP()																				\
	do {unsigned int dup_count = 0;																				\
	if (	RRR_MQTT_PROPERTY_GET_ID(property) != RRR_MQTT_PROPERTY_USER_PROPERTY &&							\
			RRR_MQTT_PROPERTY_GET_ID(property) != RRR_MQTT_PROPERTY_SUBSCRIPTION_ID &&							\
			(dup_count = rrr_mqtt_property_collection_count_duplicates(callback_data->source, property)) != 0	\
	) {																											\
		VL_MSG_ERR("Property '%s' was specified more than once (%u times) in packet\n",							\
				RRR_MQTT_PROPERTY_GET_NAME(property), dup_count + 1);											\
		goto out_reason_protocol_error;																			\
	}} while (0)

#define HANDLE_PROPERTY_SWITCH_BEGIN()										\
	int ret = RRR_MQTT_CONN_OK;												\
	HANDLE_PROPERTY_CHECK_DUP();											\
	uint32_t tmp_u32 = 0; (void)(tmp_u32);									\
	do { switch (RRR_MQTT_PROPERTY_GET_ID(property)) {						\
		case 0:																\
			VL_BUG("Property id was 0 in HANDLE_PROPERTY_SWITCH_BEGIN\n");	\
			break

#define HANDLE_PROPERTY_U32_UNCHECKED(target,id) 							\
		case id:															\
			(target) = rrr_mqtt_property_get_uint32(property);				\
			break

#define HANDLE_PROPERTY_U32_NON_ZERO(target,id,error_msg)					\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 == 0) {												\
				VL_MSG_ERR(error_msg "\n");									\
				goto out_reason_protocol_error;								\
			}																\
			(target) = tmp_u32;												\
			break

#define HANDLE_PROPERTY_U32_ON_OFF_TO_U8(target,id,error_msg)				\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 > 1) {												\
				VL_MSG_ERR(error_msg "\n");									\
				goto out_reason_protocol_error;								\
			}																\
			(target) = tmp_u32;												\
			break

#define HANDLE_PROPERTY_U32_TO_U8(target,id)								\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 > 0xff) {											\
				VL_BUG("U8 property overflow in HANDLE_PROPERTY_U32_TO_U8\n");\
			}																\
			(target) = tmp_u32;												\
			break

#define HANDLE_PROPERTY_U32_TO_U16(target,id)								\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 > 0xffff) {											\
				VL_BUG("U16 property overflow in HANDLE_PROPERTY_U32_TO_U8\n");\
			}																\
			(target) = tmp_u32;												\
			break

#define HANDLE_PROPERTY_TO_COLLECTION(target,id)													\
		case id:																					\
			ret = rrr_mqtt_property_collection_add_cloned((target), property);						\
			if (ret != 0) {																			\
				VL_MSG_ERR("Error while cloning property in HANDLE_PROPERTY_TO_COLLECTION\n");		\
				goto out_internal_error;															\
			}																						\
			break

#define HANDLE_PROPERTY_TO_COLLECTION_NON_ZERO(target,id,error_msg)									\
		case id:																					\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);										\
			if (tmp_u32 == 0) {																		\
				VL_MSG_ERR(error_msg "\n");															\
				goto out_reason_protocol_error;														\
			}																						\
			ret = rrr_mqtt_property_collection_add_cloned((target), property);						\
			if (ret != 0) {																			\
				VL_MSG_ERR("Error while cloning property in HANDLE_PROPERTY_TO_COLLECTION\n");		\
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

#define HANDLE_PROPERTY_COPY_POINTER_DANGEROUS(target,id)											\
		case id:																					\
			(target) = property;																	\
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
		ret = RRR_MQTT_CONN_SOFT_ERROR;																\
		callback_data->reason_v5 = RRR_MQTT_P_5_REASON_PROTOCOL_ERROR;								\
	out:																							\
		return ret;																					\
	} while (0)

int rrr_mqtt_common_handler_connect_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
) {
	struct rrr_mqtt_common_parse_properties_data_connect *callback_data = arg;
	struct rrr_mqtt_session_properties *session_properties = &callback_data->session_properties;

	HANDLE_PROPERTY_SWITCH_BEGIN();
		HANDLE_PROPERTY_U32_UNCHECKED (
				session_properties->session_expiry,
				RRR_MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL
		);
		HANDLE_PROPERTY_U32_NON_ZERO (
				session_properties->receive_maximum,
				RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM,
				"Receive maximum was 0 in CONNECT packet"
		);
		HANDLE_PROPERTY_U32_NON_ZERO (
				session_properties->maximum_packet_size,
				RRR_MQTT_PROPERTY_MAXIMUM_PACKET_SIZE,
				"Maximum packet size was 0 in CONNECT packet"
		);
		HANDLE_PROPERTY_U32_UNCHECKED (
				session_properties->topic_alias_maximum,
				RRR_MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM
		);
		HANDLE_PROPERTY_U32_ON_OFF_TO_U8 (
				session_properties->request_response_information,
				RRR_MQTT_PROPERTY_REQUEST_RESPONSE_INFO,
				"Request response information field in CONNECT packet was not 0 or 1"
		);
		HANDLE_PROPERTY_U32_ON_OFF_TO_U8 (
				session_properties->request_problem_information,
				RRR_MQTT_PROPERTY_REQUEST_PROBLEM_INFO,
				"Request problem information field in CONNECT packet was not 0 or 1"
		);
		HANDLE_PROPERTY_TO_COLLECTION (
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

int rrr_mqtt_common_handler_publish_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
) {
	struct rrr_mqtt_common_parse_properties_data_publish *callback_data = arg;
	struct rrr_mqtt_p_publish *publish = callback_data->publish;

	HANDLE_PROPERTY_SWITCH_BEGIN();
		HANDLE_PROPERTY_U32_ON_OFF_TO_U8 (
				publish->payload_format_indicator,
				RRR_MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR,
				"Payload format indicator field in PUBLISH packet was not 0 or 1"
		);
		HANDLE_PROPERTY_U32_UNCHECKED (
				publish->message_expiry_interval,
				RRR_MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL
		);
		HANDLE_PROPERTY_U32_TO_U16 (
				publish->topic_alias,
				RRR_MQTT_PROPERTY_TOPIC_ALIAS
		);
		HANDLE_PROPERTY_COPY_POINTER_DANGEROUS (
				publish->response_topic,
				RRR_MQTT_PROPERTY_RESPONSE_TOPIC
		);
		HANDLE_PROPERTY_COPY_POINTER_DANGEROUS (
				publish->correlation_data,
				RRR_MQTT_PROPERTY_CORRELATION_DATA
		);
		HANDLE_PROPERTY_TO_COLLECTION (
				&publish->user_properties,
				RRR_MQTT_PROPERTY_USER_PROPERTY
		);
		HANDLE_PROPERTY_TO_COLLECTION_NON_ZERO (
				&publish->subscription_ids,
				RRR_MQTT_PROPERTY_SUBSCRIPTION_ID,
				"Subscription id was zero in PUBLISH properties"
		);
		HANDLE_PROPERTY_COPY_POINTER_DANGEROUS (
				publish->content_type,
				RRR_MQTT_PROPERTY_CONTENT_TYPE
		);
	HANDLE_PROPERTY_SWITCH_END_AND_RETURN();
}

int rrr_mqtt_common_handle_properties (
		const struct rrr_mqtt_property_collection *source,
		int (*callback)(const struct rrr_mqtt_property *property, void *arg),
		struct rrr_mqtt_common_parse_properties_data *callback_data,
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

int rrr_mqtt_common_handle_publish (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = RRR_MQTT_CONN_OK;
	RRR_MQTT_P_LOCK(packet);

	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;
	struct rrr_mqtt_p *ack = NULL;
	uint8_t reason_v5 = 0;

	if (publish->reason_v5 != RRR_MQTT_P_5_REASON_OK) {
		if (publish->qos == 0) {
			VL_MSG_ERR("Closing connection due to malformed PUBLISH packet with QoS 0\n");
			ret = RRR_MQTT_CONN_SOFT_ERROR|RRR_MQTT_CONN_DESTROY_CONNECTION;
			goto out;
		}

		VL_MSG_ERR("Sending ACK for malformed PUBLISH packet with QoS %u, reason was %u\n",
				publish->qos, publish->reason_v5);

		reason_v5 = publish->reason_v5;
		goto out_generate_ack;
	}

	struct rrr_mqtt_common_parse_properties_data_publish callback_data = {
			&publish->properties,
			0,
			publish
	};

	RRR_MQTT_COMMON_HANDLE_PROPERTIES (
			&publish->properties,
			rrr_mqtt_common_handler_publish_handle_properties_callback,
			goto out_generate_ack
	);

	RRR_MQTT_P_UNLOCK(packet);
	RRR_MQTT_P_INCREF(packet);
	int ret_from_receive_publish = mqtt_data->sessions->methods->receive_publish(
			mqtt_data->sessions,
			&connection->session,
			publish
	);
	RRR_MQTT_P_DECREF(packet);
	RRR_MQTT_P_LOCK(packet);

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			ret_from_receive_publish,
			goto out,
			" in session receive publish function in rrr_mqtt_common_handle_publish"
	);

	out_generate_ack:
	if (publish->qos == 1) {
		struct rrr_mqtt_p_puback *puback = (struct rrr_mqtt_p_puback *) rrr_mqtt_p_allocate (
						RRR_MQTT_P_TYPE_PUBACK, publish->protocol_version
		);
		ack = (struct rrr_mqtt_p *) puback;
		if (puback == NULL) {
			VL_MSG_ERR("Could not allocate PUBACK in __rrr_mqtt_broker_handle_publish\n");
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
			goto out;
		}

		RRR_MQTT_P_LOCK(puback);
		puback->reason_v5 = reason_v5;
		puback->packet_identifier = publish->packet_identifier;
	}
	else if (publish->qos == 2) {
		struct rrr_mqtt_p_pubrec *pubrec = (struct rrr_mqtt_p_pubrec *) rrr_mqtt_p_allocate (
						RRR_MQTT_P_TYPE_PUBREC, publish->protocol_version
		);
		ack = (struct rrr_mqtt_p *) pubrec;
		if (pubrec == NULL) {
			VL_MSG_ERR("Could not allocate PUBREC in __rrr_mqtt_broker_handle_publish\n");
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
			goto out;
		}

		RRR_MQTT_P_LOCK(pubrec);
		pubrec->reason_v5 = reason_v5;
		pubrec->packet_identifier = publish->packet_identifier;
	}
	else if (publish->qos != 0) {
		VL_BUG("Invalid QoS (%u) in rrr_mqtt_common_handle_publish\n", publish->qos);
	}

	if (ack != NULL) {
		// NOTE : Connection subsystem will notify session system when ACK is successfully
		//        sent. We also need to unlock the packet because the original publish needs
		//        to be locked when the ACK notification is processed.
		RRR_MQTT_P_UNLOCK(packet);
		if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet(connection, ack)) != 0) {
			RRR_MQTT_P_UNLOCK(ack);
			VL_MSG_ERR("Error while sending ACK for PUBLISH packet in __rrr_mqtt_broker_handle_publish\n");
			goto out_nolock;
		}
		RRR_MQTT_P_UNLOCK(ack);
		RRR_MQTT_P_LOCK(packet);
	}

	out:
		RRR_MQTT_P_UNLOCK(packet);
	out_nolock:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(ack);
		return ret;
}

static int __rrr_mqtt_common_handle_general_ack (
		unsigned int *match_count,
		uint8_t *reason_v5,
		RRR_MQTT_TYPE_HANDLER_DEFINITION
) {
	int ret = RRR_MQTT_CONN_OK;

	*reason_v5 = RRR_MQTT_P_5_REASON_OK;

	int ret_from_notify = mqtt_data->sessions->methods->notify_ack_received (
			match_count,
			mqtt_data->sessions,
			&connection->session,
			packet
	);

	// It is possible to receive PUBREC and PUBACK with unknown packet IDs (remains from
	// older QoS handshake which only remote knows about). If the ID used happens to be
	// available, we can continue. If not, it is a session error.

	if (*match_count != 1) {
		*reason_v5 = RRR_MQTT_P_5_REASON_PACKET_IDENTIFIER_NOT_FOUND;
	}

	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			ret_from_notify,
			goto out,
			" while handling packet"
	);

	out:
	return ret;
}

int rrr_mqtt_common_handle_puback_pubcomp (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = RRR_MQTT_CONN_OK;

	unsigned int match_count = 0;
	uint8_t reason_v5 = 0;
	ret = __rrr_mqtt_common_handle_general_ack (
			&match_count,
			&reason_v5,
			mqtt_data,
			connection,
			packet
	);

	RRR_MQTT_P_LOCK(packet);

	if (ret != 0) {
		if (ret == RRR_MQTT_CONN_INTERNAL_ERROR) {
			goto out;
		}
		if (reason_v5 == RRR_MQTT_P_5_REASON_OK) {
			VL_DEBUG_MSG_1("Setting disconnect reason to 0x80 in rrr_mqtt_common_handle_puback_pubcomp\n");
			reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR_;
		}
		VL_MSG_ERR("Error while handling received %s packet, reason: %u\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet), reason_v5);
		ret = RRR_MQTT_CONN_SOFT_ERROR;
		goto out;
	}

	if (match_count != 1) {
		VL_DEBUG_MSG_1("No match for ACK of type %s id %u, possibly old packet\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet), RRR_MQTT_P_GET_IDENTIFIER(packet));
	}

	out:
	RRR_MQTT_P_UNLOCK(packet);
	return ret;
}

// See explanation of operation in mqtt_session.h
static int __rrr_mqtt_common_handle_pubrec_pubrel (
		struct rrr_mqtt_data *mqtt_data,
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		uint8_t next_ack_type
) {
	int ret = RRR_MQTT_CONN_OK;

	struct rrr_mqtt_p *next_ack = NULL;

	uint8_t reason_v5;
	unsigned int match_count = 0;

	ret = __rrr_mqtt_common_handle_general_ack (
			&match_count,
			&reason_v5,
			mqtt_data,
			connection,
			packet
	);

	RRR_MQTT_P_LOCK(packet);

	if (ret != 0) {
		if (ret == RRR_MQTT_CONN_INTERNAL_ERROR) {
			goto out;
		}
		if (reason_v5 == RRR_MQTT_P_5_REASON_OK) {
			VL_DEBUG_MSG_1("Setting disconnect reason to 0x80 in rrr_mqtt_common_handle_pubrec_pubrel\n");
			reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR_;
		}

		// For version 5, send a response with the error specified. For version 3.1,
		// we must close the connection.
		if (RRR_MQTT_P_IS_V5(packet)) {
			ret = RRR_MQTT_CONN_OK;
			goto out_send_ack;
		}
		goto out;
	}

	// TODO : Check if it's OK just to continue a QoS2 handshake which we did not know about
/*	if (match_count != 1) {
		VL_BUG("match_count was not 1 in __rrr_mqtt_broker_handle_pubrec_pubrel, session system should have triggered an error\n");
	}*/

	out_send_ack:
	next_ack = rrr_mqtt_p_allocate (
			next_ack_type,
			packet->protocol_version
	);
	if (next_ack == NULL) {
		VL_MSG_ERR("Could not allocate %s in __rrr_mqtt_broker_handle_pubrec_pubrel\n",
				RRR_MQTT_P_GET_TYPE_NAME_RAW(next_ack_type));
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	RRR_MQTT_P_LOCK(next_ack);

	next_ack->reason_v5 = reason_v5;
	next_ack->packet_identifier = packet->packet_identifier;

	if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet(connection, next_ack)) != 0) {
		VL_MSG_ERR("Error while sending ACK for %s packet (%s) in __rrr_mqtt_broker_handle_pubrec_pubrel\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet), RRR_MQTT_P_GET_TYPE_NAME_RAW(next_ack_type));
		goto out_unlock_next_ack;
	}

	/*
	TODO : Check if it's OK not to close a connection when we receive QoS2 handshake packets we don't know about
	if (next_ack->reason_v5 != RRR_MQTT_P_5_REASON_OK) {
		ret = RRR_MQTT_CONN_SOFT_ERROR | RRR_MQTT_CONN_DESTROY_CONNECTION;
	}
*/
	out_unlock_next_ack:
		RRR_MQTT_P_UNLOCK(next_ack);
	out:
		RRR_MQTT_P_DECREF_IF_NOT_NULL(next_ack);
		RRR_MQTT_P_UNLOCK(packet);
	return ret;
}

int rrr_mqtt_common_handle_pubrec (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	return __rrr_mqtt_common_handle_pubrec_pubrel (
			mqtt_data,
			connection,
			packet,
			RRR_MQTT_P_TYPE_PUBREL
	);
}

int rrr_mqtt_common_handle_pubrel (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	return __rrr_mqtt_common_handle_pubrec_pubrel (
			mqtt_data,
			connection,
			packet,
			RRR_MQTT_P_TYPE_PUBCOMP
	);
}

int rrr_mqtt_common_handle_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
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

struct handle_packets_callback {
	struct rrr_mqtt_data *data;
	struct rrr_mqtt_conn *connection;
};

static int __rrr_mqtt_common_handle_packets_callback (struct fifo_callback_args *callback_data, char *data, unsigned long int size) {
	// Remember to ALWAYS return FIFO_SEARCH_FREE
	int ret = FIFO_SEARCH_FREE;

	(void)(size);

	struct handle_packets_callback *handle_packets_data = callback_data->private_data;
	struct rrr_mqtt_data *mqtt_data = handle_packets_data->data;
	struct rrr_mqtt_conn *connection = handle_packets_data->connection;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_CONNECT) {
		if (!RRR_MQTT_CONN_STATE_RECEIVE_CONNECT_IS_ALLOWED(connection)) {
			VL_MSG_ERR("Received a CONNECT packet while not allowed in __rrr_mqtt_common_handle_packets_callback\n");
			ret |= FIFO_CALLBACK_ERR|FIFO_SEARCH_STOP;
			goto out;
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_CONNACK) {
		if (!RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_IS_ALLOWED(connection)) {
			VL_MSG_ERR("Received a CONNACK packet while not allowed in __rrr_mqtt_common_handle_packets_callback\n");
			ret |= FIFO_CALLBACK_ERR|FIFO_SEARCH_STOP;
			goto out;
		}
	}
	else if (!RRR_MQTT_CONN_STATE_RECEIVE_ANY_IS_ALLOWED(connection)) {
		VL_MSG_ERR("Received a %s packet while only CONNECT was allowed in __rrr_mqtt_common_handle_packets_callback\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet));
		ret |= FIFO_CALLBACK_ERR|FIFO_SEARCH_STOP;
		goto out;
	}

	if (mqtt_data->handler_properties[RRR_MQTT_P_GET_TYPE(packet)].handler == NULL) {
		VL_MSG_ERR("No handler specified for packet type %i\n", RRR_MQTT_P_GET_TYPE(packet));
		ret |= FIFO_CALLBACK_ERR|FIFO_SEARCH_STOP;
		goto out;
	}

	VL_DEBUG_MSG_3 ("Handling packet of type %s id %u dup %u\n",
			RRR_MQTT_P_GET_TYPE_NAME(packet), RRR_MQTT_P_GET_IDENTIFIER(packet), packet->dup);

	RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_TO_FIFO_ERRORS_GENERAL(
			mqtt_data->handler_properties[RRR_MQTT_P_GET_TYPE(packet)].handler(mqtt_data, connection, packet),
			goto out,
			"while handing packet in __rrr_mqtt_common_handle_packets_callback"
	);

	out:
	return ret | FIFO_SEARCH_FREE;
}

static int __rrr_mqtt_common_handle_packets (
		struct rrr_mqtt_conn *connection,
		void *arg
) {
	int ret = RRR_MQTT_CONN_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONN_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}

	if (	!RRR_MQTT_CONN_STATE_RECEIVE_ANY_IS_ALLOWED(connection) &&
			!RRR_MQTT_CONN_STATE_RECEIVE_CONNECT_IS_ALLOWED(connection) &&
			!RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_IS_ALLOWED(connection)
	) {
		goto out;
	}

	struct rrr_mqtt_data *data = arg;

	struct handle_packets_callback callback_data = {
			data, connection
	};

	struct fifo_callback_args fifo_callback_data = {
			NULL, &callback_data, 0
	};

	RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			fifo_read_clear_forward (
					&connection->receive_queue.buffer,
					NULL,
					__rrr_mqtt_common_handle_packets_callback,
					&fifo_callback_data,
					0
			),
			goto out,
			"while handling packets from MQTT remote"
	);

	out:
	RRR_MQTT_CONN_UNLOCK(connection);

	out_nolock:
	return ret;
}

static int __rrr_mqtt_common_read_and_parse (
		struct rrr_mqtt_conn *connection,
		void *arg
) {
	int ret = RRR_MQTT_CONN_OK;

	struct rrr_mqtt_data *data = arg;
	(void)(data);

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out;
	}

	// TODO : Make this better
	// Do this 60 times as we send 50 packets at a time (10 more)
	for (int i = 0; i < 60; i++) {
		// Do not block while reading a large message, read only 4K each time. This also
		// goes for threaded reading, the connection lock must be released often to allow
		// for other iterators to check stuff.
		RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_GENERAL(
				rrr_mqtt_conn_iterator_ctx_read (connection, RRR_MQTT_SYNCHRONIZED_READ_STEP_MAX_SIZE),
				goto out,
				"while reading data from mqtt client"
		);
		RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_GENERAL(
				rrr_mqtt_conn_iterator_ctx_parse (connection),
				goto out,
				"while parsing data from mqtt client"
		);
		RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_GENERAL(
				rrr_mqtt_conn_iterator_ctx_check_finalize (connection),
				goto out,
				"while finalizing data from mqtt client"
		);

		if (connection->protocol_version == NULL) {
			// Possible need of handling CONNECT packet
			break;
		}
	}

	out:
	return ret;
}

int rrr_mqtt_common_send_from_sessions_callback (
		struct rrr_mqtt_p *packet,
		void *arg
) {
	// context is FIFO-buffer
	int ret = FIFO_OK;

	struct rrr_mqtt_send_from_sessions_callback_data *callback_data = arg;
	struct rrr_mqtt_conn *connection = callback_data->connection;

	RRR_MQTT_P_LOCK(packet);
	if (
			RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_PUBLISH &&
			RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_PUBREL &&
			RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_PUBREC
	) {
		VL_BUG ("Unsupported packet of type %s in __rrr_mqtt_common_send_from_sessions_callback\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet));
	}

	if (rrr_mqtt_conn_iterator_ctx_send_packet(connection, packet) != 0) {
		VL_MSG_ERR("Could not send outbound packet in __rrr_mqtt_common_send_from_sessions_callback\n");
		// Do not delete packet on error, retry with new connection if client reconnects.
		ret = FIFO_CALLBACK_ERR | FIFO_SEARCH_STOP;
	}

	RRR_MQTT_P_UNLOCK(packet);

	// This function guarantees to always decref a packet it receives, also on error.
/*	RRR_MQTT_P_INCREF(packet);
	if (rrr_mqtt_conn_iterator_ctx_queue_outbound_packet(connection, packet) != RRR_MQTT_CONN_OK) {
		VL_MSG_ERR("Could not queue outbound packet in __rrr_mqtt_common_send_from_sessions_callback\n");
		ret = ret | FIFO_GLOBAL_ERR;
	}*/

	return ret;
}

static int __rrr_mqtt_common_send (
		struct rrr_mqtt_conn *connection,
		void *arg
) {
	int ret = RRR_MQTT_CONN_OK;

	struct rrr_mqtt_data *data = arg;

	(void)(data);

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONN_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}
	if (connection->session == NULL) {
		// No CONNECT yet
		goto out_unlock;
	}
	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out_unlock;
	}

	struct rrr_mqtt_send_from_sessions_callback_data callback_data = {
			connection
	};
	RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(
			data->sessions->methods->iterate_send_queue (
					data->sessions,
					&connection->session,
					rrr_mqtt_common_send_from_sessions_callback,
					&callback_data,
					50	// <-- max count
			),
			goto out_unlock,
			"while iterating session send queue"
	);

	out_unlock:
		RRR_MQTT_CONN_UNLOCK(connection);
	out_nolock:
		return ret;
}

int rrr_mqtt_common_read_parse_handle (struct rrr_mqtt_data *data) {
	int ret = 0;

	RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN(
			rrr_mqtt_conn_collection_iterate(&data->connections, __rrr_mqtt_common_read_and_parse, data),
			ret,
			goto housekeeping,
			goto out,
			"in rrr_mqtt_common_read_parse_handle while reading and parsing"
	);

	RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN(
			rrr_mqtt_conn_collection_iterate(&data->connections, __rrr_mqtt_common_handle_packets, data),
			ret,
			goto housekeeping,
			goto out,
			"in rrr_mqtt_common_read_parse_handle while handling packets"
	);

	RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN(
			rrr_mqtt_conn_collection_iterate(&data->connections, __rrr_mqtt_common_send, data),
			ret,
			goto housekeeping,
			goto out,
			"in rrr_mqtt_common_read_parse_handle while sending packets"
	);

	housekeeping:
	RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN(
			rrr_mqtt_conn_collection_iterate(&data->connections, rrr_mqtt_conn_iterator_ctx_housekeeping, data),
			ret,
			goto out,
			goto out,
			"in rrr_mqtt_common_read_parse_handle while doing housekeeping"
	);

	out:
	// Only let internal error propagate
	return ret & RRR_MQTT_CONN_INTERNAL_ERROR;
}

int rrr_mqtt_common_iterate_and_clear_local_delivery (
		struct rrr_mqtt_data *data,
		int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(
			data->sessions->methods->iterate_and_clear_local_delivery(data->sessions, callback, callback_arg),
			goto out,
			" while iterating local delivery queue in rrr_mqtt_common_iterate_and_clear_local_delivery"
	);

	out:
	return ret & RRR_MQTT_SESSION_INTERNAL_ERROR;
}
