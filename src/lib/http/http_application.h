/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_APPLICATION_H
#define RRR_HTTP_APPLICATION_H

#include "http_common.h"

#include "../rrr_types.h"

#define RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_COMMON_ARGS      \
    struct rrr_net_transport_handle *handle,                   \
    struct rrr_http_transaction *transaction,                  \
    const char *data_ptr,                                      \
    rrr_biglength overshoot_bytes,                                   \
    enum rrr_http_application_type next_application_type

#define RRR_HTTP_APPLICATION_ASYNC_RESPONSE_GET_CALLBACK_ARGS  \
    struct rrr_http_transaction *transaction,                  \
    void *arg

#define RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS      \
    int *do_upgrade,                                           \
    enum rrr_http_application_type from,                       \
    enum rrr_http_upgrade_mode to,                             \
    void *arg

#define RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS \
    int *do_websocket,                                         \
    char **application_topic,                                  \
    RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_COMMON_ARGS,         \
    void *arg 

#define RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS   \
    const char *application_topic,                                  \
    void **data, rrr_biglength *data_len, int *is_binary, rrr_http_unique_id unique_id, void *arg

#define RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS     \
    const char *application_topic,                             \
    struct rrr_net_transport_handle *handle,                   \
    const struct rrr_nullsafe_str *payload, int is_binary, rrr_http_unique_id unique_id, void *arg

#define RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS             \
    RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_COMMON_ARGS,         \
    void *arg

#define RRR_HTTP_APPLICATION_FAILURE_CALLBACK_ARGS             \
    struct rrr_net_transport_handle *handle,                   \
    struct rrr_http_transaction *transaction,                  \
    const char *error_msg,                                     \
    void *arg

#define RRR_HTTP_APPLICATION_RECEIVE_RAW_CALLBACK_ARGS         \
    RRR_HTTP_COMMON_RECEIVE_RAW_CALLBACK_ARGS

#define RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS \
    RRR_HTTP_COMMON_UNIQUE_ID_GENERATOR_CALLBACK_ARGS

struct rrr_http_application;
struct rrr_net_transport_handle;
struct rrr_http_transaction;
struct rrr_nullsafe_str;
struct rrr_http_rules;

struct rrr_http_application_callbacks {
	int (*unique_id_generator_callback)(RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS);
	void *unique_id_generator_callback_arg;
	int (*upgrade_verify_callback)(RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS);
	void *upgrade_verify_callback_arg;
	int (*websocket_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS);
	void *websocket_callback_arg;
	int (*get_response_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS);
	void *get_response_callback_arg;
	int (*frame_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *frame_callback_arg;
	int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
	int (*failure_callback)(RRR_HTTP_APPLICATION_FAILURE_CALLBACK_ARGS);
	void *failure_callback_arg;
	int (*async_response_get_callback)(RRR_HTTP_APPLICATION_ASYNC_RESPONSE_GET_CALLBACK_ARGS);
	void *async_response_get_callback_arg;
};

void rrr_http_application_destroy_if_not_null (
		struct rrr_http_application **app
);
void rrr_http_application_destroy_if_not_null_void (
		void *app_double_ptr
);
uint64_t rrr_http_application_active_transaction_count_get_and_maintain (
		struct rrr_http_application *app
);
int rrr_http_application_new (
		struct rrr_http_application **target,
		enum rrr_http_application_type type,
		int is_server,
		const struct rrr_http_application_callbacks *callbacks
);
int rrr_http_application_transport_ctx_request_send_possible (
		int *is_possible,
		struct rrr_http_application *app
);
int rrr_http_application_transport_ctx_request_send (
		struct rrr_http_application **upgraded_app,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		const char *user_agent,
		const char *host,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		struct rrr_http_transaction *transaction
);
void rrr_http_application_transport_ctx_need_tick (
		enum rrr_http_tick_speed *speed,
		struct rrr_http_application *app
);
int rrr_http_application_transport_ctx_tick (
		rrr_biglength *received_bytes,
		struct rrr_http_application **upgraded_app,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size,
		const struct rrr_http_rules *rules
);
int rrr_http_application_alpn_protos_with_all_do (
		int (*callback)(const char *alpn_protos, unsigned int alpn_protos_length, void *callback_arg),
		void *callback_arg
);
void rrr_http_application_polite_close (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle
);
enum rrr_http_application_type rrr_http_application_type_get (
		struct rrr_http_application *app
);

#endif /* RRR_HTTP_APPLICATION_H */
