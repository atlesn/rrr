/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MQTT_COMMON_H
#define RRR_MQTT_COMMON_H

#include <stdio.h>

#include "mqtt_connection.h"
#include "mqtt_session.h"

#define RRR_MQTT_DATA_CLIENT_NAME_LENGTH 64
#define RRR_MQTT_SYNCHRONIZED_READ_STEP_MAX_SIZE 4096

struct ip_accept_data;
struct rrr_mqtt_data;
struct rrr_mqtt_p_publish;

#define RRR_MQTT_TYPE_HANDLER_DEFINITION \
		struct rrr_mqtt_data *mqtt_data, \
		struct rrr_mqtt_conn *connection, \
		struct rrr_mqtt_p *packet

struct rrr_mqtt_type_handler_properties {
	int (*handler)(RRR_MQTT_TYPE_HANDLER_DEFINITION);
};

struct rrr_mqtt_data {
	struct rrr_mqtt_conn_collection connections;
	char client_name[RRR_MQTT_DATA_CLIENT_NAME_LENGTH + 1];
	const struct rrr_mqtt_type_handler_properties *handler_properties;
	int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *arg);
	void *event_handler_arg;
	struct rrr_mqtt_session_collection *sessions;
	uint64_t close_wait_time_usec;
};

#define MQTT_COMMON_CALL_SESSION_HEARTBEAT(mqtt,session) \
		(mqtt)->sessions->methods->heartbeat((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_NOTIFY_DISCONNECT(mqtt,session) \
		(mqtt)->sessions->methods->notify_disconnect((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_ADD_SUBSCRIPTIONS(mqtt,session,subscriptions) \
		(mqtt)->sessions->methods->add_subscriptions((mqtt)->sessions, &(session), (subscriptions))

#define MQTT_COMMON_CALL_SESSION_RECEIVE_PUBLISH(mqtt,session,publish) \
		(mqtt)->sessions->methods->receive_publish((mqtt)->sessions, &(session), (publish))

#define MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD	\
	const struct rrr_mqtt_property_collection *source;		\
	uint8_t reason_v5

struct rrr_mqtt_common_parse_properties_data {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
};

struct rrr_mqtt_common_parse_properties_data_connect {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_session_properties session_properties;
};

struct rrr_mqtt_common_parse_properties_data_publish {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_p_publish *publish;
};

#define MQTT_COMMON_HANDLE_PROPERTIES(target,callback,action_on_error)								\
	do {if ((ret = rrr_mqtt_common_handle_properties (												\
			(target),																				\
			callback,																				\
			(struct rrr_mqtt_common_parse_properties_data*) &callback_data,							\
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

#define MQTT_COMMON_HANDLE_PROPERTY_CHECK_DUP()																	\
	do {unsigned int dup_count = 0;																				\
	if (	RRR_MQTT_PROPERTY_GET_ID(property) != RRR_MQTT_PROPERTY_USER_PROPERTY &&							\
			RRR_MQTT_PROPERTY_GET_ID(property) != RRR_MQTT_PROPERTY_SUBSCRIPTION_ID &&							\
			(dup_count = rrr_mqtt_property_collection_count_duplicates(callback_data->source, property)) != 0	\
	) {																											\
		VL_MSG_ERR("Property '%s' was specified more than once (%u times) in packet\n",							\
				RRR_MQTT_PROPERTY_GET_NAME(property), dup_count + 1);											\
		goto out_reason_protocol_error;																			\
	}} while (0)

#define MQTT_COMMON_HANDLE_PROPERTY_SWITCH_BEGIN()										\
	int ret = RRR_MQTT_CONN_OK;															\
	MQTT_COMMON_HANDLE_PROPERTY_CHECK_DUP();											\
	uint32_t tmp_u32 = 0; (void)(tmp_u32);												\
	do { switch (RRR_MQTT_PROPERTY_GET_ID(property)) {									\
		case 0:																			\
			VL_BUG("Property id was 0 in MQTT_COMMON_HANDLE_PROPERTY_SWITCH_BEGIN\n");	\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_U32_UNCHECKED(target,id) 				\
		case id:															\
			(target) = rrr_mqtt_property_get_uint32(property);				\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_U32_NON_ZERO(target,id,error_msg)		\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 == 0) {												\
				VL_MSG_ERR(error_msg "\n");									\
				goto out_reason_protocol_error;								\
			}																\
			(target) = tmp_u32;												\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_U32_ON_OFF_TO_U8(target,id,error_msg)	\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 > 1) {												\
				VL_MSG_ERR(error_msg "\n");									\
				goto out_reason_protocol_error;								\
			}																\
			(target) = tmp_u32;												\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_U32_TO_U8(target,id)					\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 > 0xff) {											\
				VL_BUG("U8 property overflow in MQTT_COMMON_HANDLE_PROPERTY_U32_TO_U8\n");\
			}																\
			(target) = tmp_u32;												\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_U32_TO_U16(target,id)					\
		case id:															\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);				\
			if (tmp_u32 > 0xffff) {											\
				VL_BUG("U16 property overflow in MQTT_COMMON_HANDLE_PROPERTY_U32_TO_U8\n");\
			}																\
			(target) = tmp_u32;												\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_TO_COLLECTION(target,id)										\
		case id:																					\
			ret = rrr_mqtt_property_collection_add_cloned((target), property);						\
			if (ret != 0) {																			\
				VL_MSG_ERR("Error while cloning property in MQTT_COMMON_HANDLE_PROPERTY_TO_COLLECTION\n");\
				goto out_internal_error;															\
			}																						\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_TO_COLLECTION_NON_ZERO(target,id,error_msg)						\
		case id:																					\
			tmp_u32 = rrr_mqtt_property_get_uint32(property);										\
			if (tmp_u32 == 0) {																		\
				VL_MSG_ERR(error_msg "\n");															\
				goto out_reason_protocol_error;														\
			}																						\
			ret = rrr_mqtt_property_collection_add_cloned((target), property);						\
			if (ret != 0) {																			\
				VL_MSG_ERR("Error while cloning property in MQTT_COMMON_HANDLE_PROPERTY_TO_COLLECTION\n");\
				goto out_internal_error;															\
			}																						\
			break

#define MQTT_COMMON_HANDLE_PROPERTY_CLONE(target,id)												\
		case id:																					\
			if (rrr_mqtt_property_clone((target), property) != 0) {									\
				VL_MSG_ERR("Could not clone property HANDLE_PROPERTY_USER_PROPERTY\n");				\
				goto out_internal_error;															\
			}																						\
			break;

#define MQTT_COMMON_HANDLE_PROPERTY_COPY_POINTER_DANGEROUS(target,id)								\
		case id:																					\
			(target) = property;																	\
			break;

// We do not return error as we want to parse the rest of the source_properties to check
// for more errors. Caller checks for non-zero reason.
#define MQTT_COMMON_HANDLE_PROPERTY_SWITCH_END_AND_RETURN() 										\
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

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data);
int rrr_mqtt_common_data_init (struct rrr_mqtt_data *data,
		const char *client_name,
		const struct rrr_mqtt_type_handler_properties *handler_properties,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *arg),
		void *event_handler_arg,
		uint64_t close_wait_time_usec,
		int max_socket_connections
);
int rrr_mqtt_common_data_register_connection (
		struct rrr_mqtt_data *data,
		const struct ip_accept_data *accept_data
);
int rrr_mqtt_common_handler_connect_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
);
int rrr_mqtt_common_handler_publish_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
);
int rrr_mqtt_common_handle_properties (
		const struct rrr_mqtt_property_collection *source,
		int (*callback)(const struct rrr_mqtt_property *property, void *arg),
		struct rrr_mqtt_common_parse_properties_data *callback_data,
		uint8_t *reason_v5
);
int rrr_mqtt_common_read_parse_handle (struct rrr_mqtt_data *data);

#endif /* RRR_MQTT_COMMON_H */
