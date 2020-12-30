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

#ifndef RRR_HTTP_SESSION_H
#define RRR_HTTP_SESSION_H

#include <stdint.h>
#include <sys/socket.h>

#include "http_common.h"
#include "http_fields.h"
#include "http_part.h"
#include "http_application.h"
#include "../net_transport/net_transport_defines.h"

#define RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS

#define RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS

#define RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS	\
	rrr_http_unique_id *result,								\
	void *arg

#define RRR_HTTP_SESSION_HTTP2_RECEIVE_CALLBACK_ARGS		\
	struct rrr_net_transport_handle *handle,				\
	const struct rrr_http_part *request_part,				\
	struct rrr_http_part *response_part,					\
	const char *data_ptr,									\
	size_t data_size,										\
	void *arg,												\
	rrr_http_unique_id unique_id

#define RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS

#define RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS

#define RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS \
	RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS

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
		const char *user_agent
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
		enum rrr_http_upgrade_mode upgrade_mode
);
int rrr_http_session_transport_ctx_request_raw_send (
		struct rrr_net_transport_handle *handle,
		const char *raw_request_data,
		size_t raw_request_size
);
int rrr_http_session_transport_ctx_tick (
		ssize_t *received_bytes,
		uint64_t *comlete_transactions_count,
		struct rrr_net_transport_handle *handle,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int is_client,
		int (*upgrade_verify_callback)(RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS),
		void *upgrade_verify_callback_arg,
		int (*websocket_callback)(RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS),
		void *websocket_callback_arg,
		int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS),
		void *callback_arg,
		int (*get_response_callback)(RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg,
		int (*raw_callback)(RRR_HTTP_SESSION_RECEIVE_RAW_CALLBACK_ARGS),
		void *raw_callback_arg
);
int rrr_http_session_transport_ctx_close_if_open (
		struct rrr_net_transport_handle *handle,
		void *arg
);

#endif /* RRR_HTTP_SESSION_H */
