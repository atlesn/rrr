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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../log.h"
#include "../allocator.h"
#include "../util/rrr_time.h"
#include "http_session.h"
#include "http_transaction.h"
#include "http_application.h"

#include "../net_transport/net_transport.h"

#ifdef RRR_WITH_NGHTTP2
#include "../http2/http2.h"
#endif

#ifdef RRR_WITH_NGHTTP2
const char rrr_http_session_alpn_protos_http2_priority[] = {
	     6, 'h', 't', 't', 'p', '/', '2',
	     8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};
#endif /* RRR_WITH_NGHTTP2 */

static void __rrr_http_session_destroy (struct rrr_http_session *session) {
	RRR_FREE_IF_NOT_NULL(session->user_agent);
	rrr_http_application_destroy_if_not_null(&session->application);
#ifdef RRR_WITH_NGHTTP2
	rrr_http2_session_destroy_if_not_null(&session->http2_session);
#endif
	rrr_free(session);
}

static void __rrr_http_session_destroy_void (void *ptr) {
	__rrr_http_session_destroy(ptr);
}

static int __rrr_http_session_allocate (struct rrr_http_session **target) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_session *session = rrr_allocate(sizeof(*session));
	if (session == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_session_allocate\n");
		ret = 1;
		goto out;
	}

	memset(session, '\0', sizeof(*session));

	// Response and request parts are allocated when needed

	*target = session;

	out:
		return ret;
}

void rrr_http_session_transport_ctx_application_set (
		struct rrr_http_application **application,
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	if (application != NULL && *application != NULL) {
		rrr_http_application_destroy_if_not_null(&session->application);
		session->application = *application;
		*application = NULL;
	}

	if (session->application == NULL) {
		RRR_BUG("BUG: Application pointer was NULL at end of rrr_http_session_transport_ctx_application_set, maybe caller forgot to create it for us\n");
	}
}

int rrr_http_session_transport_ctx_server_new (
		struct rrr_http_application **application,
		struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	struct rrr_http_session *session = NULL;

	if ((__rrr_http_session_allocate(&session)) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_http_session_server_new\n");
		ret = 1;
		goto out;
	}

	// DO NOT STORE HANDLE POINTER

	// Transport framework responsible for cleaning up
	rrr_net_transport_handle_ptr_application_data_bind (
			handle,
			session,
			__rrr_http_session_destroy_void
	);
	session = NULL;

	rrr_http_session_transport_ctx_application_set(application, handle);

	out:
	if (session != NULL) {
		__rrr_http_session_destroy(session);
	}
	return ret;
}

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
) {
	int ret = 0;

	struct rrr_http_session *session;

	// With keepalive connections, structures are already present in transport handle
	if (!rrr_net_transport_ctx_handle_has_application_data(handle)) {
		if ((ret = __rrr_http_session_allocate(&session)) != 0) {
			RRR_MSG_0("Could not allocate memory for session in %s\n", __func__);
			goto out;
		}

		const struct rrr_http_application_callbacks callbacks = {
			NULL,
			NULL,
			websocket_callback,
			get_response_callback,
			frame_callback,
			callback,
			failure_callback,
			NULL,
			NULL,
			callback_arg
		};

		if ((ret = rrr_http_application_new (
				&session->application,
				application_type,
				0, // Is not server
				&callbacks
		)) != 0) {
			goto out_destroy_session;
		}

		if (user_agent != NULL && *user_agent != '\0') {
			session->user_agent = rrr_strdup(user_agent);
			if (session->user_agent == NULL) {
				RRR_MSG_0("Could not allocate memory for user agent in %s\n");
				ret = 1;
				goto out_destroy_session;
			}
		}

		// Transport framework responsible for cleaning up
		rrr_net_transport_handle_ptr_application_data_bind (
				handle,
				session,
				__rrr_http_session_destroy_void
		);
	}

	goto out;
	out_destroy_session:
		__rrr_http_session_destroy(session);
	out:
		return ret;
}

int rrr_http_session_transport_ctx_request_send_possible (
		int *is_possible,
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	if (session == NULL) {
		// OK, no application created yet (hence it can't be busy)
		return 0;
	}

	return rrr_http_application_transport_ctx_request_send_possible (
			is_possible,
			session->application
	);
}

int rrr_http_session_transport_ctx_request_send (
		struct rrr_http_application **upgraded_app,
		struct rrr_net_transport_handle *handle,
		const char *host,
		struct rrr_http_transaction *transaction,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);
	return rrr_http_application_transport_ctx_request_send (
			upgraded_app,
			session->application,
			handle,
			session->user_agent,
			host,
			upgrade_mode,
			protocol_version,
			transaction
	);
}

uint64_t rrr_http_session_transport_ctx_active_transaction_count_get_and_maintain (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	return rrr_http_application_active_transaction_count_get_and_maintain(session->application, handle);
}

void rrr_http_session_transport_ctx_websocket_response_available_notify (
		struct rrr_net_transport_handle *handle
) {
	rrr_net_transport_ctx_notify_read_fast(handle);
}

void rrr_http_session_transport_ctx_need_tick (
		enum rrr_http_tick_speed *speed,
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	*speed = RRR_HTTP_TICK_SPEED_NO_TICK;

	if (session == NULL) {
		return;
	}

	rrr_http_application_transport_ctx_need_tick(speed, session->application);
}

static int __rrr_http_session_transport_ctx_tick (
		rrr_biglength *received_bytes,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size,
		const struct rrr_http_rules *rules
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	int ret = 0;

	if (session == NULL) {
		goto out_final;
	}

	struct rrr_http_application *upgraded_app = NULL;

	pthread_cleanup_push(rrr_http_application_destroy_if_not_null_void, &upgraded_app);

	if  (session->application == NULL) {
		RRR_BUG("BUG: Application was NULL in rrr_http_session_transport_ctx_tick\n");
	}

	if ((ret = rrr_http_application_transport_ctx_tick (
			received_bytes,
			&upgraded_app,
			session->application,
			handle,
			read_max_size,
			rules
	)) != 0) {
		goto out;
	}

	if (upgraded_app) {
		RRR_DBG_3("HTTP upgrade transition from %s to %s fd %i h %i\n",
				RRR_HTTP_APPLICATION_TO_STR(rrr_http_application_type_get(session->application)),
				RRR_HTTP_APPLICATION_TO_STR(rrr_http_application_type_get (upgraded_app)),
				RRR_NET_TRANSPORT_CTX_FD(handle),
				RRR_NET_TRANSPORT_CTX_HANDLE(handle)
		);
		rrr_http_session_transport_ctx_application_set(&upgraded_app, handle);
		rrr_net_transport_ctx_notify_read_fast(handle);
	}

	out:
		pthread_cleanup_pop(1);
	out_final:
		return ret;
}

int rrr_http_session_transport_ctx_tick_client (
		rrr_biglength *received_bytes,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size
) {
	struct rrr_http_rules rules_dummy = {0};

	return __rrr_http_session_transport_ctx_tick (
			received_bytes,
			handle,
			read_max_size,
			&rules_dummy
	);
}

int rrr_http_session_transport_ctx_tick_server (
		rrr_biglength *received_bytes,
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_max_size,
		const struct rrr_http_rules *rules
) {
	return __rrr_http_session_transport_ctx_tick (
			received_bytes,
			handle,
			read_max_size,
			rules
	);
}

int rrr_http_session_transport_ctx_close_if_open (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	(void)(arg);
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	if (session != NULL) {
		RRR_DBG_3("HTTP polite close fd %i h %i session %p\n",
				RRR_NET_TRANSPORT_CTX_FD(handle),
				RRR_NET_TRANSPORT_CTX_HANDLE(handle),
				session
		);

		rrr_http_application_polite_close(session->application, handle);
	}
	else {
		RRR_DBG_3("HTTP non-polite close fd %i h %i (session does not yet exist)\n",
				RRR_NET_TRANSPORT_CTX_FD(handle),
				RRR_NET_TRANSPORT_CTX_HANDLE(handle)
		);
		rrr_net_transport_ctx_close_now_set(handle);
	}

	return 0; // Always return 0
}

int rrr_http_session_transport_ctx_stream_open (
		void (**stream_data),
		void (**stream_data_destroy)(void *stream_data),
		int (**cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS),
		int (**cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS),
		int (**cb_shutdown_read)(RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS),
		int (**cb_shutdown_write)(RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS),
		int (**cb_close)(RRR_NET_TRANSPORT_STREAM_CLOSE_CALLBACK_ARGS),
		int (**cb_write_confirm)(RRR_NET_TRANSPORT_STREAM_CONFIRM_CALLBACK_ARGS),
		int (**cb_ack_confirm)(RRR_NET_TRANSPORT_STREAM_CONFIRM_CALLBACK_ARGS),
		void **cb_arg,
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		int flags,
		void *stream_open_callback_arg_local
) {
	struct rrr_http_session *session = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	RRR_DBG_3("HTTP stream open %li fd %i h %i existing session %p\n",
			stream_id,
			RRR_NET_TRANSPORT_CTX_FD(handle),
			RRR_NET_TRANSPORT_CTX_HANDLE(handle),
			session
	);

	return rrr_http_application_transport_ctx_stream_open (
			stream_data,
			stream_data_destroy,
			cb_get_message,
			cb_blocked,
			cb_shutdown_read,
			cb_shutdown_write,
			cb_close,
			cb_write_confirm,
			cb_ack_confirm,
			cb_arg,
			session != NULL ? session->application : NULL, /* Application must create session if it does not exist */
			handle,
			stream_id,
			flags,
			stream_open_callback_arg_local
	);
}
