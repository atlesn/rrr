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

#include <stdlib.h>

#include "../log.h"
#include "http_application.h"
#include "http_application_internals.h"
#ifdef RRR_WITH_NGHTTP2
#	include "http_application_http2.h"
#endif
#include "http_application_http1.h"

void rrr_http_application_destroy_if_not_null (
		struct rrr_http_application **app
) {
	if (app == NULL) {
		RRR_BUG("BUG: Double pointer was NULL in rrr_http_application_destroy_if_not_null, must pass pointer reference\n");
	}
	if (*app == NULL) {
		return;
	}
	(*app)->constants->destroy(*app);
	*app = NULL;
}

void rrr_http_application_destroy_if_not_null_void (
		void *app_double_ptr
) {
	rrr_http_application_destroy_if_not_null((struct rrr_http_application **) app_double_ptr);
}

int rrr_http_application_new (
		struct rrr_http_application **target,
		enum rrr_http_application_type type,
		int is_server
) {
	if (type == RRR_HTTP_APPLICATION_HTTP1) {
		return rrr_http_application_http1_new(target);
	}
#ifdef RRR_WITH_NGHTTP2
	else if (type == RRR_HTTP_APPLICATION_HTTP2) {
		return rrr_http_application_http2_new(target, is_server, NULL, 0);
	}
#endif
	RRR_BUG("BUG: Unknown application type %i to rrr_http_application_new\n", type);
	return 1;
}

int rrr_http_application_transport_ctx_request_send (
		struct rrr_http_application **upgraded_app,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		const char *user_agent,
		const char *host,
		enum rrr_http_upgrade_mode upgrade_mode,
		struct rrr_http_transaction *transaction
) {
	return app->constants->request_send(upgraded_app, app, handle, user_agent, host, upgrade_mode, transaction);
}

int rrr_http_application_transport_ctx_tick (
		ssize_t *received_bytes,
		struct rrr_http_application **upgraded_app,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int is_client,
		int (*upgrade_verify_callback)(RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS),
		void *upgrade_verify_callback_arg,
		int (*websocket_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS),
		void *websocket_callback_arg,
		int (*get_response_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg,
		int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS),
		void *callback_arg,
		int (*raw_callback)(RRR_HTTP_APPLICATION_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_arg
) {
	return app->constants->tick (
			received_bytes,
			upgraded_app,
			app,
			handle,
			read_max_size,
			unique_id,
			is_client,
			upgrade_verify_callback,
			upgrade_verify_callback_arg,
			websocket_callback,
			websocket_callback_arg,
			get_response_callback,
			get_response_callback_arg,
			frame_callback,
			frame_callback_arg,
			callback,
			callback_arg,
			raw_callback,
			raw_callback_arg
	);
}

int rrr_http_application_alpn_protos_with_all_do (
		int (*callback)(const char *alpn_protos, unsigned int alpn_protos_length, void *callback_arg),
		void *callback_arg
) {
	const char *alpn_protos = NULL;
	unsigned int alpn_protos_length = 0;

#ifdef RRR_WITH_NGHTTP2
	rrr_http_application_http2_alpn_protos_get(&alpn_protos, &alpn_protos_length);
#endif

	return callback(alpn_protos, alpn_protos_length, callback_arg);
}

void rrr_http_application_polite_close (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle
) {
	app->constants->polite_close(app, handle);
}

enum rrr_http_application_type rrr_http_application_type_get (
		struct rrr_http_application *app
) {
	return app->constants->type;
}
