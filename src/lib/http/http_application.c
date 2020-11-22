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
#include "http_application_http2.h"
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

int rrr_http_application_new (
		struct rrr_http_application **target,
		enum rrr_http_application_type type
) {
	if (type == RRR_HTTP_APPLICATION_HTTP1) {
		return rrr_http_application_http1_new(target);
	}
	RRR_BUG("BUG: Unknown application type %i to rrr_http_application_new\n", type);
	return 1;
}

int rrr_http_application_transport_ctx_request_send (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		const char *user_agent,
		const char *host,
		enum rrr_http_upgrade_mode upgrade_mode,
		struct rrr_http_transaction *transaction
) {
	return app->constants->request_send(app, handle, user_agent, host, upgrade_mode, transaction);
}

int rrr_http_application_transport_ctx_response_send (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_transaction *transaction
) {
	return app->constants->response_send(app, handle, transaction);
}

int rrr_http_application_transport_ctx_tick (
		ssize_t *received_bytes,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int is_client,
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
			app,
			handle,
			read_max_size,
			unique_id,
			is_client,
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
