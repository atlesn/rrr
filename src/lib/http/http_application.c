/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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
#include "../allocator.h"
#include "http_application.h"
#include "http_application_internals.h"
#ifdef RRR_WITH_NGHTTP2
#	include "http_application_http2.h"
#endif
#ifdef RRR_WITH_HTTP3
#	include "http_application_http3.h"
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

uint64_t rrr_http_application_active_transaction_count_get_and_maintain (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle
) {
	return app->constants->active_transaction_count_get_and_maintain(app, handle);
}

int rrr_http_application_new (
		struct rrr_http_application **target,
		enum rrr_http_application_type type,
		int is_server,
		const struct rrr_http_application_callbacks *callbacks
) {
#if !defined(RRR_WITH_NGHTTP2) && !defined(RRR_WITH_HTTP3)
	(void)(is_server);
#endif
	if (type == RRR_HTTP_APPLICATION_HTTP1) {
		return rrr_http_application_http1_new(target, callbacks);
	}
#ifdef RRR_WITH_NGHTTP2
	else if (type == RRR_HTTP_APPLICATION_HTTP2) {
		return rrr_http_application_http2_new(target, is_server, NULL, 0, callbacks);
	}
#endif
#ifdef RRR_WITH_HTTP3
	else if (type == RRR_HTTP_APPLICATION_HTTP3) {
		return rrr_http_application_http3_new(target, is_server, callbacks);
	}
#endif
	RRR_BUG("BUG: Unknown application type %i to rrr_http_application_new\n", type);
	return 1;
}

int rrr_http_application_transport_ctx_request_send_possible (
		int *is_possible,
		struct rrr_http_application *app
) {
	return app->constants->request_send_possible(is_possible, app);
}

int rrr_http_application_transport_ctx_request_send (
		struct rrr_http_application **upgraded_app,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		const char *user_agent,
		const char *host,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		struct rrr_http_transaction *transaction
) {
	return app->constants->request_send(upgraded_app, app, handle, user_agent, host, upgrade_mode, protocol_version, transaction);
}

int rrr_http_application_transport_ctx_need_tick (
		struct rrr_http_application *app
) {
	return app->constants->need_tick(app);
}

int rrr_http_application_transport_ctx_tick (
		rrr_biglength *received_bytes,
		struct rrr_http_application **upgraded_app,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size,
		const struct rrr_http_rules *rules
) {
	return app->constants->tick (
			received_bytes,
			upgraded_app,
			app,
			handle,
			read_max_size,
			rules
	);
}

int rrr_http_application_transport_ctx_stream_open (
		void (**stream_data),
		void (**stream_data_destroy)(void *stream_data),
		int (**cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS),
		int (**cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS),
		int (**cb_shutdown_read)(RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS),
		int (**cb_shutdown_write)(RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS),
		int (**cb_close)(RRR_NET_TRANSPORT_STREAM_CLOSE_CALLBACK_ARGS),
		int (**cb_ack)(RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS),
		void **cb_arg,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		int flags,
		void *stream_open_callback_arg_local
) {
	return app->constants->stream_open (
			stream_data,
			stream_data_destroy,
			cb_get_message,
			cb_blocked,
			cb_shutdown_read,
			cb_shutdown_write,
			cb_close,
			cb_ack,
			cb_arg,
			app,
			handle,
			stream_id,
			flags,
			stream_open_callback_arg_local
	);
}

int rrr_http_application_alpn_protos_with_all_tcp_do (
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

#ifdef RRR_WITH_HTTP3
int rrr_http_application_alpn_protos_with_http3_do (
		int (*callback)(const char *alpn_protos, unsigned int alpn_protos_length, void *callback_arg),
		void *callback_arg
) {
	const char *alpn_protos = NULL;
	unsigned int alpn_protos_length = 0;

	rrr_http_application_http3_alpn_protos_get(&alpn_protos, &alpn_protos_length);

	return callback(alpn_protos, alpn_protos_length, callback_arg);
}
#endif

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
