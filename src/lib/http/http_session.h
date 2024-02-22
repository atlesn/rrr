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

#ifndef RRR_HTTP_SESSION_H
#define RRR_HTTP_SESSION_H

#include <sys/socket.h>

#include "http_common.h"
#include "http_fields.h"
#include "http_part.h"
#include "http_application.h"
#include "../rrr_types.h"
#include "../net_transport/net_transport_defines.h"

#define RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS

#define RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS

#define RRR_HTTP_SESSION_ASYNC_RESPONSE_GET_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_ASYNC_RESPONSE_GET_CALLBACK_ARGS

#define RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS

#define RRR_HTTP_SESSION_RESPONSE_POSTPROCESS_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_RESPONSE_POSTPROCESS_CALLBACK_ARGS

#define RRR_HTTP_SESSION_HTTP2_RECEIVE_CALLBACK_ARGS           \
    struct rrr_net_transport_handle *handle,                   \
    const struct rrr_http_part *request_part,                  \
    struct rrr_http_part *response_part,                       \
    const char *data_ptr,                                      \
    size_t data_size,                                          \
    void *arg,                                                 \
    rrr_http_unique_id unique_id                               \

#define RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS

#define RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS

#define RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS

#define RRR_HTTP_SESSION_FAILURE_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_FAILURE_CALLBACK_ARGS

#define RRR_HTTP_SESSION_RECEIVE_RAW_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_RECEIVE_RAW_CALLBACK_ARGS

#ifdef RRR_WITH_NGHTTP2
struct rrr_http2_session;
#endif

struct rrr_http_application;

struct rrr_http_session {
	struct rrr_http_application *application;

	char *user_agent;

#ifdef RRR_WITH_NGHTTP2
	struct rrr_http2_session *http2_session;
#endif

	// Used when ticking
	uint64_t prev_complete_transaction_time;
	uint64_t prev_complete_transaction_count;
};

struct rrr_net_transport;
struct rrr_net_transport_handle;
struct rrr_http_transaction;

void rrr_http_session_transport_ctx_application_set (
		struct rrr_http_application **application,
		struct rrr_net_transport_handle *handle
);
int rrr_http_session_transport_ctx_server_new (
		struct rrr_http_application **application,
		struct rrr_net_transport_handle *handle
);
int rrr_http_session_transport_ctx_client_new_or_clean (
		enum rrr_http_application_type application_type,
		struct rrr_net_transport_handle *handle,
		const char *user_agent,
		int (*websocket_callback)(RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS),
		int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS),
		int (*failure_callback)(RRR_HTTP_SESSION_FAILURE_CALLBACK_ARGS),
		int (*get_response_callback)(RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		int (*frame_callback)(RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *callback_arg
);
int rrr_http_session_transport_ctx_request_send_possible (
		int *is_possible,
		struct rrr_net_transport_handle *handle
);
int rrr_http_session_transport_ctx_request_send (
		struct rrr_http_application **upgraded_app,
		struct rrr_net_transport_handle *handle,
		const char *host,
		struct rrr_http_transaction *transaction,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version
);
uint64_t rrr_http_session_transport_ctx_active_transaction_count_get_and_maintain (
		struct rrr_net_transport_handle *handle
);
void rrr_http_session_transport_ctx_websocket_response_available_notify (
		struct rrr_net_transport_handle *handle
);
void rrr_http_session_transport_ctx_need_tick (
		enum rrr_http_tick_speed *speed,
		struct rrr_net_transport_handle *handle
);
int rrr_http_session_transport_ctx_tick_client (
		rrr_biglength *received_bytes,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size
); 
int rrr_http_session_transport_ctx_tick_server (
		rrr_biglength *received_bytes,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size,
		const struct rrr_http_rules *rules
);
int rrr_http_session_transport_ctx_close_if_open (
		struct rrr_net_transport_handle *handle,
		void *arg
);
int rrr_http_session_transport_ctx_stream_open (
		void (**stream_data),
		void (**stream_data_destroy)(void *stream_data),
		int (**cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS),
		int (**cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS),
		int (**cb_shutdown_read)(RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS),
		int (**cb_shutdown_write)(RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS),
		int (**cb_close)(RRR_NET_TRANSPORT_STREAM_CLOSE_CALLBACK_ARGS),
		int (**cb_ack)(RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS),
		void **cb_arg,
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		int flags,
		void *stream_open_callback_arg_local
);

#endif /* RRR_HTTP_SESSION_H */
