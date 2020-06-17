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

#define RRR_MQTT_SYNCHRONIZED_READ_STEP_MAX_SIZE 4096
#define RRR_MQTT_COMMON_CLOSE_WAIT_TIME 3
#define RRR_MQTT_COMMON_RETRY_INTERVAL 5
#define RRR_MQTT_COMMON_MAX_CONNECTIONS 260

#define RRR_MQTT_COMMON_CONN_CHECK_RETURN(ret_final,msg_on_err,goto_or_break_soft,goto_or_break_hard,ret_destroy,ret_soft,ret_hard) \
	do {if (ret_tmp != RRR_MQTT_CONN_OK) {							\
		if ((ret_tmp & RRR_MQTT_CONN_DESTROY_CONNECTION) != 0) {	\
			ret_tmp &= ~RRR_MQTT_CONN_DESTROY_CONNECTION;			\
			ret_final |= ret_destroy;								\
		}															\
		if ((ret_tmp & RRR_MQTT_CONN_SOFT_ERROR) != 0) {			\
			RRR_MSG_0("Soft connection error " msg_on_err "\n");	\
			ret_tmp &= ~RRR_MQTT_CONN_SOFT_ERROR;					\
			ret_final |= ret_soft;									\
		}															\
		if ((ret_tmp & RRR_MQTT_CONN_BUSY) != 0) {					\
			ret_tmp &= ~RRR_MQTT_CONN_BUSY;							\
		}															\
		if (ret_tmp != RRR_MQTT_CONN_OK) {							\
			RRR_MSG_0("Internal connection error " msg_on_err		\
				" (return was %i)\n", ret_tmp);						\
			ret_final |= ret_hard;									\
			goto_or_break_hard;										\
		}															\
		goto_or_break_soft;											\
	}} while(0)

#define RRR_MQTT_COMMON_SESSION_CHECK_RETURN(ret_final,msg_on_err,goto_or_break_soft,goto_or_break_hard,ret_soft,ret_deleted,ret_hard) \
	do {if (ret_tmp != 0) {											\
		if ((ret_tmp & RRR_MQTT_SESSION_ERROR) != 0) {				\
			RRR_MSG_0("Soft session error " msg_on_err "\n");		\
			ret_tmp = ret_tmp & ~RRR_MQTT_SESSION_ERROR;			\
			ret_final |= ret_soft;									\
		}															\
		if ((ret_tmp & RRR_MQTT_SESSION_DELETED) != 0) {			\
			RRR_MSG_0("Session was deleted " msg_on_err "\n");		\
			ret_tmp = ret_tmp & ~RRR_MQTT_SESSION_DELETED;			\
			ret_final |= ret_deleted;								\
		}															\
		if (ret_tmp != RRR_MQTT_SESSION_OK) {						\
			RRR_MSG_0("Internal error " msg_on_err					\
				" (return was %i)\n", ret_tmp);						\
			ret_final |= ret_hard;									\
			goto_or_break_hard;										\
		}															\
		goto_or_break_soft;											\
	}} while(0)

#define RRR_MQTT_COMMON_FIFO_CHECK_RETURN(ret_final,msg_on_err,goto_or_break_soft,goto_or_break_hard,ret_soft,ret_hard) \
	do {if (ret_tmp != 0) {											\
		if ((ret_tmp & RRR_FIFO_CALLBACK_ERR) != 0) {				\
			RRR_MSG_0("FIFO callback error " msg_on_err "\n");	\
			ret_tmp = ret_tmp & ~RRR_FIFO_CALLBACK_ERR;				\
			ret_final |= ret_soft;									\
		}															\
		if (ret_tmp != RRR_FIFO_OK) {								\
			RRR_MSG_0("FIFO internal error " msg_on_err			\
				" (return was %i)\n", ret_tmp);						\
			ret_final |= ret_hard;									\
			goto_or_break_hard;										\
		}															\
		goto_or_break_soft;											\
	}} while(0)

#define RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN(function,ret_final,goto_or_break_soft,goto_or_break_hard,msg_on_err) \
	do { int ret_tmp = function;									\
		RRR_MQTT_COMMON_CONN_CHECK_RETURN(							\
			ret_final,												\
			msg_on_err,												\
			goto_or_break_soft,										\
			goto_or_break_hard,										\
			RRR_MQTT_CONN_DESTROY_CONNECTION,						\
			RRR_MQTT_CONN_SOFT_ERROR,								\
			RRR_MQTT_CONN_INTERNAL_ERROR							\
		);															\
	} while(0)

#define RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN(function,ret_final,goto_or_break_soft,goto_or_break_hard,msg_on_err) \
	do { int ret_tmp = function;									\
		RRR_MQTT_COMMON_SESSION_CHECK_RETURN(						\
			ret_final,												\
			msg_on_err,												\
			goto_or_break_soft,										\
			goto_or_break_hard,										\
			RRR_MQTT_SESSION_DELETED,								\
			RRR_MQTT_SESSION_ERROR,									\
			RRR_MQTT_SESSION_INTERNAL_ERROR							\
		);															\
	} while(0)

#define RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_TO_FIFO_ERRORS(function,ret_final,goto_or_break_soft,goto_or_break_hard,msg_on_err) \
	do { int ret_tmp = function;									\
		RRR_MQTT_COMMON_CONN_CHECK_RETURN(							\
			ret_final,												\
			msg_on_err,												\
			goto_or_break_soft,										\
			goto_or_break_hard,										\
			RRR_FIFO_CALLBACK_ERR|RRR_FIFO_SEARCH_STOP,				\
			RRR_FIFO_CALLBACK_ERR|RRR_FIFO_SEARCH_STOP,				\
			RRR_FIFO_SEARCH_STOP|RRR_FIFO_GLOBAL_ERR				\
		);															\
	} while(0)

#define RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS(function,ret_final,goto_or_break_soft,goto_or_break_hard,msg_on_err) \
	do { int ret_tmp = function;									\
	RRR_MQTT_COMMON_SESSION_CHECK_RETURN(							\
		ret_final,													\
		msg_on_err,													\
		goto_or_break_soft,											\
		goto_or_break_hard,											\
		RRR_MQTT_CONN_DESTROY_CONNECTION|RRR_MQTT_CONN_SOFT_ERROR,	\
		RRR_MQTT_CONN_DESTROY_CONNECTION|RRR_MQTT_CONN_SOFT_ERROR,	\
		RRR_MQTT_CONN_INTERNAL_ERROR								\
	); } while(0)

#define RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_CONN_ERRORS(function,ret_final,goto_or_break_soft,goto_or_break_hard,msg_on_err) \
	do { int ret_tmp = function;									\
		RRR_MQTT_COMMON_FIFO_CHECK_RETURN(							\
			ret_final,												\
			msg_on_err,												\
			goto_or_break_soft,										\
			goto_or_break_hard,										\
			RRR_MQTT_CONN_DESTROY_CONNECTION|RRR_MQTT_CONN_SOFT_ERROR,\
			RRR_MQTT_CONN_INTERNAL_ERROR							\
		);															\
	} while(0)

#define RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_SESSION_ERRORS(function,ret_final,goto_or_break_soft,goto_or_break_hard,msg_on_err) \
	do { int ret_tmp = function;									\
		RRR_MQTT_COMMON_FIFO_CHECK_RETURN(							\
			ret_final,												\
			msg_on_err,												\
			goto_or_break_soft,										\
			goto_or_break_hard,										\
			RRR_MQTT_SESSION_ERROR,									\
			RRR_MQTT_SESSION_INTERNAL_ERROR							\
		);															\
	} while(0)

#define RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_GENERAL(function,goto,msg_on_err) \
		RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN(function,ret,goto,goto,msg_on_err)

#define RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN_GENERAL(function,goto,msg_on_err) \
		RRR_MQTT_COMMON_CALL_SESSION_AND_CHECK_RETURN(function,ret,goto,goto,msg_on_err)

#define RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_TO_FIFO_ERRORS_GENERAL(function,goto,msg_on_err) \
		RRR_MQTT_COMMON_CALL_CONN_AND_CHECK_RETURN_TO_FIFO_ERRORS(function,ret,goto,goto,msg_on_err)

#define RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(function,goto,msg_on_err) \
		RRR_MQTT_COMMON_CALL_SESSION_CHECK_RETURN_TO_CONN_ERRORS(function,ret,goto,goto,msg_on_err)

#define RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_CONN_ERRORS_GENERAL(function,goto,msg_on_err) \
		RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_CONN_ERRORS(function,ret,goto,goto,msg_on_err)

#define RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_SESSION_ERRORS_GENERAL(function,goto,msg_on_err) \
		RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_SESSION_ERRORS(function,ret,goto,goto,msg_on_err)

struct rrr_ip_accept_data;
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
	const struct rrr_mqtt_type_handler_properties *handler_properties;
	char *client_name;
	int (*event_handler)(
			struct rrr_mqtt_conn *connection,
			int event,
			void *static_arg,
			void *arg
	);
	void *event_handler_static_arg;
	int (*acl_handler)(
			struct rrr_mqtt_conn *connection,
			struct rrr_mqtt_p *packet,
			void *arg
	);
	void *acl_handler_arg;
	struct rrr_mqtt_session_collection *sessions;
	uint64_t retry_interval_usec;
	uint64_t close_wait_time_usec;
};

struct rrr_mqtt_common_init_data {
	const char *client_name;
	uint64_t retry_interval_usec;
	uint64_t close_wait_time_usec;
	unsigned int max_socket_connections;
};

struct rrr_mqtt_send_from_sessions_callback_data {
	struct rrr_mqtt_conn *connection;
};

#define MQTT_COMMON_CALL_SESSION_HEARTBEAT(mqtt,session) \
		(mqtt)->sessions->methods->heartbeat((mqtt)->sessions, &(session))

#define MQTT_COMMON_CALL_SESSION_NOTIFY_DISCONNECT(mqtt,session,reason_v5) \
		(mqtt)->sessions->methods->notify_disconnect((mqtt)->sessions, &(session), reason_v5)

#define MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD	\
	const struct rrr_mqtt_property_collection *source;		\
	uint8_t reason_v5

struct rrr_mqtt_common_parse_properties_data {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
};

struct rrr_mqtt_common_parse_properties_data_connect {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_session_properties *session_properties;
};

struct rrr_mqtt_common_parse_properties_data_publish {
	MQTT_COMMON_HANDLE_PROPERTIES_CALLBACK_DATA_HEAD;
	struct rrr_mqtt_p_publish *publish;
};

extern const struct rrr_mqtt_session_properties rrr_mqtt_common_default_session_properties;

void rrr_mqtt_common_data_destroy (struct rrr_mqtt_data *data);
void rrr_mqtt_common_data_notify_pthread_cancel (struct rrr_mqtt_data *data);
int rrr_mqtt_common_clear_session_from_connections_reenter (
		struct rrr_mqtt_data *data,
		const struct rrr_mqtt_session *session_to_remove,
		const struct rrr_mqtt_conn *disregard_connection
);
int rrr_mqtt_common_clear_session_from_connections (
		struct rrr_mqtt_data *data,
		const struct rrr_mqtt_session *session_to_remove,
		const struct rrr_mqtt_conn *disregard_connection
);
int rrr_mqtt_common_data_init (
		struct rrr_mqtt_data *data,
		const struct rrr_mqtt_type_handler_properties *handler_properties,
		const struct rrr_mqtt_common_init_data *init_data,
		int (*session_initializer)(struct rrr_mqtt_session_collection **sessions, void *arg),
		void *session_initializer_arg,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_static_arg,
		int (*acl_handler)(struct rrr_mqtt_conn *connection, struct rrr_mqtt_p *packet, void *arg),
		void *acl_handler_arg
);
int rrr_mqtt_common_handler_connect_handle_properties_callback (
		const struct rrr_mqtt_property *property,
		void *arg
);
int rrr_mqtt_common_handler_connack_handle_properties_callback (
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

#define RRR_MQTT_COMMON_HANDLE_PROPERTIES(target,packet,callback,action_on_error)					\
	do {if ((ret = rrr_mqtt_common_handle_properties (												\
			(target),																				\
			callback,																				\
			(struct rrr_mqtt_common_parse_properties_data*) &callback_data,							\
			&reason_v5																				\
	)) != 0) {																						\
		if ((ret & RRR_MQTT_CONN_SOFT_ERROR) != 0) {												\
			RRR_MSG_0("Soft error while iterating %s properties\n",								\
					RRR_MQTT_P_GET_TYPE_NAME(packet));												\
			ret = ret & ~(RRR_MQTT_CONN_SOFT_ERROR);												\
		}																							\
		if (ret != 0) {																				\
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;														\
			RRR_MSG_0("Internal error while iterating %s properties, return was %i\n",				\
					RRR_MQTT_P_GET_TYPE_NAME(packet), ret);											\
			goto out;																				\
		}																							\
																									\
		ret = RRR_MQTT_CONN_SOFT_ERROR;																\
		action_on_error;																			\
	}} while(0)

int rrr_mqtt_common_handle_publish (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_puback_pubcomp (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_pubrec (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_pubrel (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_handle_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION);
int rrr_mqtt_common_send_from_sessions_callback (
		struct rrr_mqtt_p *packet,
		void *arg
);
int rrr_mqtt_common_read_parse_handle (
		struct rrr_mqtt_data *data,
		int (*exceeded_keep_alive_callback)(struct rrr_mqtt_conn *connection, void *arg),
		void *callback_arg
);
int rrr_mqtt_common_iterate_and_clear_local_delivery (
		struct rrr_mqtt_data *data,
		int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *callback_arg
);

#endif /* RRR_MQTT_COMMON_H */
