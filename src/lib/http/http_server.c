/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#include "../log.h"
#include "../allocator.h"

#include "http_common.h"
#include "http_server.h"
#include "http_session.h"
#include "http_util.h"
#include "http_application.h"
#include "http_transaction.h"

#include "../ip/ip_util.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"

void rrr_http_server_destroy (struct rrr_http_server *server) {
	if (server->transport_http != NULL) {
		rrr_net_transport_destroy(server->transport_http);
	}

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (server->transport_https != NULL) {
		rrr_net_transport_destroy(server->transport_https);
	}
#endif

#if defined(RRR_WITH_HTTP3)
	if (server->transport_quic != NULL) {
		rrr_net_transport_destroy(server->transport_quic);
	}
#endif

	rrr_free(server);
}

void rrr_http_server_destroy_void (void *server) {
	rrr_http_server_destroy(server);
}
	
static int __rrr_http_server_unique_id_generator_callback_dummy (
		RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
) {
	(void)(arg);
	*unique_id = 1;
	return 0;
}

int rrr_http_server_new (
		struct rrr_http_server **target,
		const struct rrr_http_server_callbacks *callbacks
) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_server *server = rrr_allocate(sizeof(*server));
	if (server == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_server_new\n");
		ret = 1;
		goto out;
	}

	memset(server, '\0', sizeof(*server));

	server->callbacks = *callbacks;

	// Must be set for HTTP application to run in server mode
	if (server->callbacks.unique_id_generator_callback == NULL) {
		server->callbacks.unique_id_generator_callback = __rrr_http_server_unique_id_generator_callback_dummy;

	}

	*target = server;
	server = NULL;

	goto out;
//	out_free:
//		free(server);
	out:
		return ret;
}

#define RRR_HTTP_SERVER_DEFINE_SET_FUNCTION(name)              \
    void RRR_PASTE(rrr_http_server_set_,name) (                \
            struct rrr_http_server *server,                    \
            int set                                            \
    ) {                                                        \
        server->rules.RRR_PASTE(do_,name) = (set != 0);        \
    }                                                          \

#define RRR_HTTP_SERVER_DEFINE_SET_FUNCTION_BIGLENGTH(name)    \
    void RRR_PASTE(rrr_http_server_set_,name) (                \
            struct rrr_http_server *server,                    \
            rrr_biglength set                                  \
    ) {                                                        \
        server->rules.name = set;                              \
    }                                                          \

#define RRR_HTTP_SERVER_DEFINE_SET_FUNCTION_STRING(name)       \
    void RRR_PASTE(rrr_http_server_set_,name) (                \
            struct rrr_http_server *server,                    \
            const char *set                                    \
    ) {                                                        \
        server->rules.name = set;                              \
    }                                                          \

RRR_HTTP_SERVER_DEFINE_SET_FUNCTION(no_body_parse);
RRR_HTTP_SERVER_DEFINE_SET_FUNCTION_BIGLENGTH(server_request_max_size);

static void __rrr_http_server_accept_callback (
		RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS
) {
	struct rrr_http_server *http_server = arg;

	(void)(http_server);

	char buf[256];
	rrr_ip_to_str(buf, sizeof(buf), sockaddr, socklen);
	RRR_DBG_3("HTTP accept for %s family %i using fd %i h %i\n",
			buf,
			sockaddr->sa_family,
			RRR_NET_TRANSPORT_CTX_FD(handle),
			RRR_NET_TRANSPORT_CTX_HANDLE(handle)
	);
}


static int __rrr_http_server_upgrade_verify_callback (
		RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS
);
static int __rrr_http_server_websocket_handshake_callback (
		RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
);
static int __rrr_http_server_receive_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
);
static int __rrr_http_server_failure_callback (
		RRR_HTTP_SESSION_FAILURE_CALLBACK_ARGS
);
static int __rrr_http_server_websocket_get_response_callback (
		RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS
);
static int __rrr_http_server_websocket_frame_callback (
		RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS
);
static int __rrr_http_server_unique_id_generator_callback (
		RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
);
static int __rrr_http_server_async_response_get_callback (
		RRR_HTTP_APPLICATION_ASYNC_RESPONSE_GET_CALLBACK_ARGS
);
static int __rrr_http_server_response_postprocess_callback (
		RRR_HTTP_APPLICATION_RESPONSE_POSTPROCESS_CALLBACK_ARGS
);
static int __rrr_http_server_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
);

static int __rrr_http_server_transport_ctx_application_ensure (
		struct rrr_http_server *http_server,
		struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	struct rrr_http_application *application = NULL;
	char *alpn_selected_proto = NULL;

	if (rrr_net_transport_ctx_handle_has_application_data (handle)) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_selected_proto_get(&alpn_selected_proto, handle)) != 0) {
		goto out;
	}

	const struct rrr_http_application_callbacks callbacks = {
		__rrr_http_server_unique_id_generator_callback,
		__rrr_http_server_upgrade_verify_callback,
		__rrr_http_server_websocket_handshake_callback,
		__rrr_http_server_websocket_get_response_callback,
		__rrr_http_server_websocket_frame_callback,
		__rrr_http_server_receive_callback,
		__rrr_http_server_failure_callback,
		__rrr_http_server_async_response_get_callback,
		__rrr_http_server_response_postprocess_callback,
		http_server
	};

	enum rrr_http_application_type type = RRR_HTTP_APPLICATION_HTTP1;

	if (alpn_selected_proto != NULL && strcmp(alpn_selected_proto, "h2") == 0) {
		type = RRR_HTTP_APPLICATION_HTTP2;
	}
#if defined(RRR_WITH_HTTP3)
	else if (rrr_net_transport_ctx_transport_type_get (handle) == RRR_NET_TRANSPORT_QUIC) {
		// Check only first two bytes of string (matches h3-29 etc.)
		if (alpn_selected_proto == NULL || strncmp(alpn_selected_proto, "h3", 2) != 0) {
			RRR_DBG_7("HTTP incorrect ALPN protocol '%s' for QUIC fd %i handle %i\n",
				alpn_selected_proto == NULL ? "(not given)" : alpn_selected_proto,
				RRR_NET_TRANSPORT_CTX_FD(handle),
				RRR_NET_TRANSPORT_CTX_HANDLE(handle));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		type = RRR_HTTP_APPLICATION_HTTP3;
	}
#endif

	if ((ret = rrr_http_application_new (
			&application,
			type,
			1, // Is server
			&callbacks
	)) != 0) {
		RRR_MSG_0("Could not create HTTP application in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_server_new (
			&application,
			handle
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in %s\n", __func__);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(alpn_selected_proto);
	rrr_http_application_destroy_if_not_null(&application);
	return ret;
}

static int __rrr_http_server_handshake_complete_callback (
		RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	if ((ret = __rrr_http_server_transport_ctx_application_ensure (
			http_server,
			handle
	)) != 0) {
		goto out;
	}

	RRR_DBG_3("HTTP handshake complete for fd %i h %i\n",
			RRR_NET_TRANSPORT_CTX_FD(handle),
			RRR_NET_TRANSPORT_CTX_HANDLE(handle));

	out:
	return ret;
}

#ifdef RRR_WITH_HTTP3
static int __rrr_http_server_stream_open_callback (
		RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg_global;

	(void)(arg_local);

	int ret = 0;

	if ((ret = __rrr_http_server_transport_ctx_application_ensure (
			http_server,
			handle
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_stream_open (
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
			handle,
			stream_id,
			flags,
			NULL
	)) != 0) {
		goto out;
	}

	out:
	return ret;
	
}
#endif

static int __rrr_http_server_upgrade_verify_callback (
		RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	(void)(from);
	(void)(to);
	(void)(http_server);

	*do_upgrade = 1;

	return 0;
}

static int __rrr_http_server_websocket_handshake_callback (
		RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	if (http_server->callbacks.websocket_handshake_callback == NULL) {
		RRR_DBG_1("Note: HTTP server received an HTTP1 request with upgrade to websocket, but no websocket callback is set\n");
		*do_websocket = 0;
	}
	else if ((ret = http_server->callbacks.websocket_handshake_callback (
			do_websocket,
			application_topic,
			handle,
			transaction,
			data_ptr,
			overshoot_bytes,
			next_application_type,
			http_server->callbacks.callback_arg
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_server_response_headers_push (
		struct rrr_http_part *response_part
) {
	int ret = RRR_HTTP_OK;

	ret |= rrr_http_part_header_field_push(response_part, "access-control-allow-methods", "OPTIONS, GET, POST, PUT, PATCH");

	return ret;
}

static int __rrr_http_server_response_initialize (
		struct rrr_net_transport_handle *handle,
		struct rrr_http_part *response_part
) {
	if (__rrr_http_server_response_headers_push(response_part) != 0) {
		RRR_MSG_0("HTTP server %i: Could not push default response headers in __rrr_http_server_response_initialize\n",
				RRR_NET_TRANSPORT_CTX_FD(handle));
		return RRR_HTTP_HARD_ERROR;
	}

	return RRR_HTTP_OK;
}

static int __rrr_http_server_receive_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	(void)(data_ptr);

	int ret = 0;

	if (RRR_DEBUGLEVEL_2) {
		char ip_buf[256];
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(method_buf, transaction->request_part->request_method_str_nullsafe);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(uri_buf, transaction->request_part->request_uri_nullsafe);

		rrr_net_transport_ctx_connected_address_to_str(ip_buf, sizeof(ip_buf), handle);

		RRR_MSG_2("HTTP server %i %s %s %s %s\n",
				RRR_NET_TRANSPORT_CTX_FD(handle),
				ip_buf,
				method_buf,
				uri_buf,
				(transaction->request_part->parsed_application_type == RRR_HTTP_APPLICATION_HTTP3
					? "HTTP/3"
					: (transaction->request_part->parsed_application_type == RRR_HTTP_APPLICATION_HTTP2
						? "HTTP/2"
						: (transaction->request_part->parsed_version == RRR_HTTP_VERSION_10
							? "HTTP/1.0"
							: "HTTP/1.1"
						)
					)
				)
		);

		if (overshoot_bytes > 0) {
			if (transaction->request_part->parsed_connection == RRR_HTTP_CONNECTION_CLOSE) {
				RRR_MSG_0("HTTP server %i %s has %" PRIrrrbl " bytes overshoot while protocol version is HTTP/1.0 or 'Connection: close' is set, data will be lost\n",
						RRR_NET_TRANSPORT_CTX_FD(handle), ip_buf, overshoot_bytes);
			}
			else {
				RRR_DBG_3("HTTP server %i %s has %" PRIrrrbl " bytes overshoot, expecting another request\n",
						RRR_NET_TRANSPORT_CTX_FD(handle), ip_buf, overshoot_bytes);
			}
		}
	}

	if ((ret = __rrr_http_server_response_initialize(handle, transaction->response_part)) != RRR_HTTP_OK) {
		goto out;
	}

	if (http_server->callbacks.final_callback != NULL) {
		if ((ret = http_server->callbacks.final_callback (
				NULL,
				handle,
				transaction,
				data_ptr,
				overshoot_bytes,
				next_application_type,
				http_server->callbacks.callback_arg
		)) == RRR_HTTP_NO_RESULT) {
			// Return value propagates
			goto out;
		}
	}

	if (transaction->response_part->response_code == 0) {
		switch (ret) {
			case RRR_HTTP_OK:
				transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT;
				break;
			case RRR_HTTP_SOFT_ERROR:
				transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
				break;
			default:
				transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR;
				break;
		};
	}

	out:
	return ret;
}

static int __rrr_http_server_failure_callback (
		RRR_HTTP_SESSION_FAILURE_CALLBACK_ARGS
) {
	(void)(handle);
	(void)(transaction);
	(void)(error_msg);
	(void)(arg);
	return 0;
}

static int __rrr_http_server_websocket_get_response_callback (
		RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	*data = NULL;
	*data_len = 0;
	*is_binary = 0;

	if (http_server->callbacks.websocket_get_response_callback) {
		ret = http_server->callbacks.websocket_get_response_callback (
				application_topic,
				data,
				data_len,
				is_binary,
				unique_id,
				http_server->callbacks.callback_arg
		);
	}

	return ret;
}

static int __rrr_http_server_websocket_frame_callback (
		RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	if (http_server->callbacks.websocket_frame_callback) {
		ret = http_server->callbacks.websocket_frame_callback (
				application_topic,
				handle,
				payload,
				is_binary,
				unique_id,
				http_server->callbacks.callback_arg
		);
	}

	return ret;
}

static int __rrr_http_server_unique_id_generator_callback (
		RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	if (http_server->callbacks.unique_id_generator_callback) {
		ret = http_server->callbacks.unique_id_generator_callback (
				unique_id,
				http_server->callbacks.callback_arg
		);
	}

	return ret;
}

static int __rrr_http_server_async_response_get_callback (
		RRR_HTTP_APPLICATION_ASYNC_RESPONSE_GET_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	if (http_server->callbacks.async_response_get_callback) {
		ret = http_server->callbacks.async_response_get_callback (
				transaction,
				http_server->callbacks.callback_arg
		);
	}

	return ret;
}

static int __rrr_http_server_response_postprocess_callback (
		RRR_HTTP_APPLICATION_RESPONSE_POSTPROCESS_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	if (http_server->callbacks.response_postprocess_callback) {
		ret = http_server->callbacks.response_postprocess_callback (
				transaction,
				http_server->callbacks.callback_arg
		);
	}

	return ret;
}

static void __rrr_http_server_close_connections (
		struct rrr_http_server *server
) {
	if (server->transport_http) {
		rrr_net_transport_iterate_by_mode_and_do (
				server->transport_http,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				rrr_http_session_transport_ctx_close_if_open,
				NULL
		);
	}
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (server->transport_https) {
		rrr_net_transport_iterate_by_mode_and_do (
				server->transport_https,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				rrr_http_session_transport_ctx_close_if_open,
				NULL
		);
	}
#endif
#if defined(RRR_WITH_HTTP3)
	if (server->transport_quic) {
		rrr_net_transport_iterate_by_mode_and_do (
				server->transport_quic,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				rrr_http_session_transport_ctx_close_if_open,
				NULL
		);
	}
#endif

	server->shutdown_started = 1;
}

static int __rrr_http_server_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	int again_max = 5;

	rrr_biglength received_bytes = 0;

	enum rrr_http_tick_speed tick_speed;

	if (http_server->shutdown_started) {
		__rrr_http_server_close_connections(http_server);
	}

	again:

	tick_speed = RRR_HTTP_TICK_SPEED_NO_TICK;

	if ((ret = rrr_http_session_transport_ctx_tick_server (
			&received_bytes,
			handle,
			http_server->rules.server_request_max_size,
			&http_server->rules
	)) != 0) {
		if (ret != RRR_HTTP_SOFT_ERROR && ret != RRR_READ_INCOMPLETE && ret != RRR_READ_EOF) {
			RRR_MSG_0("HTTP server %i: Hard error while working with client\n",
					RRR_NET_TRANSPORT_CTX_FD(handle));
		}
		goto out;
	}

	rrr_http_session_transport_ctx_need_tick(&tick_speed, handle);

	switch (tick_speed) {
		case RRR_HTTP_TICK_SPEED_NO_TICK:
			break;
		case RRR_HTTP_TICK_SPEED_FAST:
			if (again_max--) {
				goto again;
			}
			rrr_net_transport_ctx_notify_tick_fast(handle);
			break;
		case RRR_HTTP_TICK_SPEED_SLOW:
			rrr_net_transport_ctx_notify_tick_slow(handle);
			break;
	};

	// Clean up often to prevent huge number of HTTP2 streams waiting to be cleaned up
	rrr_http_session_transport_ctx_active_transaction_count_get_and_maintain(handle);

	ret = received_bytes == 0 ? RRR_NET_TRANSPORT_READ_INCOMPLETE : RRR_NET_TRANSPORT_READ_OK;

	out:
	return ret;
}

#define RRR_HTTP_SERVER_NET_TRANSPORT_CALLBACKS                \
    __rrr_http_server_accept_callback,                         \
    http_server,                                               \
    __rrr_http_server_handshake_complete_callback,             \
    http_server,                                               \
    __rrr_http_server_read_callback,                           \
    http_server

struct rrr_http_server_start_alpn_protos_callback_data {
	const char *name;
	struct rrr_http_server *server;
	struct rrr_net_transport **result_transport;
	const struct rrr_net_transport_config *net_transport_config;
	const int net_transport_flags;
	struct rrr_event_queue *queue;
	const uint64_t first_read_timeout_ms;
	const uint64_t hard_timeout_ms;
	const uint64_t ping_timeout_ms;
	const rrr_length send_chunk_count_limit;
	int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS);
	void *stream_open_arg;
};

static int __rrr_http_server_start_alpn_protos_callback (
		const char *alpn_protos,
		unsigned int alpn_protos_length,
		void *callback_arg
) {
	struct rrr_http_server_start_alpn_protos_callback_data *callback_data = callback_arg;
	struct rrr_http_server *http_server = callback_data->server;

	return rrr_net_transport_new (
			callback_data->result_transport,
			callback_data->net_transport_config,
			callback_data->name,
			callback_data->net_transport_flags,
			callback_data->queue,
			alpn_protos,
			alpn_protos_length,
			callback_data->first_read_timeout_ms,
			callback_data->ping_timeout_ms,
			callback_data->hard_timeout_ms,
			callback_data->send_chunk_count_limit,
			RRR_HTTP_SERVER_NET_TRANSPORT_CALLBACKS,
			callback_data->stream_open_callback,
			callback_data->stream_open_arg
	);
}

static int __rrr_http_server_start (
		struct rrr_net_transport **result_transport,
		struct rrr_http_server *http_server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit,
		const struct rrr_net_transport_config *net_transport_config,
		int net_transport_flags
) {
	int ret = 0;

	if (*result_transport != NULL) {
		RRR_BUG("BUG: Double call to %s, pointer already set\n", __func__);
	}

	const uint64_t hard_timeout_ms = (read_timeout_ms < 1000 ? 1000 : read_timeout_ms);
	const uint64_t ping_timeout_ms = hard_timeout_ms / 2;

	if (0) {
		// Placeholder due to defines
	}
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (net_transport_config->transport_type_p == RRR_NET_TRANSPORT_TLS) {
		struct rrr_http_server_start_alpn_protos_callback_data callback_data = {
				"HTTP server TLS",
				http_server,
				result_transport,
				net_transport_config,
				net_transport_flags,
				queue,
				first_read_timeout_ms,
				hard_timeout_ms,
				ping_timeout_ms,
				send_chunk_count_limit,
				NULL,
				NULL
		};

		ret = rrr_http_application_alpn_protos_with_all_tcp_do (
				__rrr_http_server_start_alpn_protos_callback,
				&callback_data
		);
	}
#endif
#ifdef RRR_WITH_HTTP3
	else if (net_transport_config->transport_type_p == RRR_NET_TRANSPORT_QUIC) {
		struct rrr_http_server_start_alpn_protos_callback_data callback_data = {
				"HTTP server QUIC",
				http_server,
				result_transport,
				net_transport_config,
				net_transport_flags,
				queue,
				first_read_timeout_ms,
				hard_timeout_ms,
				ping_timeout_ms,
				send_chunk_count_limit,
				__rrr_http_server_stream_open_callback,
				http_server
		};

		ret = rrr_http_application_alpn_protos_with_http3_do (
				__rrr_http_server_start_alpn_protos_callback,
				&callback_data
		);
	}
#endif
	else {
		ret = rrr_net_transport_new (
				result_transport,
				net_transport_config,
				"HTTP server plain",
				net_transport_flags,
				queue,
				NULL,
				0,
				first_read_timeout_ms,
				ping_timeout_ms,
				hard_timeout_ms,
				send_chunk_count_limit,
				RRR_HTTP_SERVER_NET_TRANSPORT_CALLBACKS,
				NULL,
				NULL
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not create HTTP transport in %s return was %i\n", __func__, ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			*result_transport,
			port,
			NULL,
			NULL
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_http_server_start_plain (
		struct rrr_http_server *server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_plain = {
			NULL,
			NULL,
			NULL,
			NULL,
			RRR_NET_TRANSPORT_PLAIN,
			RRR_NET_TRANSPORT_F_PLAIN,
			0
	};

	ret = __rrr_http_server_start (
			&server->transport_http,
			server,
			queue,
			port,
			first_read_timeout_ms,
			read_timeout_ms,
			send_chunk_count_limit,
			&net_transport_config_plain,
			0
	);

	return ret;
}

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
int rrr_http_server_start_tls (
		struct rrr_http_server *server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit,
		const struct rrr_net_transport_config *net_transport_config_template,
		int net_transport_flags
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_tls = *net_transport_config_template;

	net_transport_config_tls.transport_type_p = RRR_NET_TRANSPORT_TLS;

	ret = __rrr_http_server_start (
			&server->transport_https,
			server,
			queue,
			port,
			first_read_timeout_ms,
			read_timeout_ms,
			send_chunk_count_limit,
			&net_transport_config_tls,
			net_transport_flags
	);

	return ret;
}
#endif

#if defined(RRR_WITH_HTTP3)
int rrr_http_server_start_quic (
		struct rrr_http_server *server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit,
		const struct rrr_net_transport_config *net_transport_config_template,
		int net_transport_flags
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_quic = *net_transport_config_template;

	net_transport_config_quic.transport_type_p = RRR_NET_TRANSPORT_QUIC;

	ret = __rrr_http_server_start (
			&server->transport_quic,
			server,
			queue,
			port,
			first_read_timeout_ms,
			read_timeout_ms,
			send_chunk_count_limit,
			&net_transport_config_quic,
			net_transport_flags
	);

	return ret;
}
#endif

void rrr_http_server_response_available_notify (
		struct rrr_http_server *server
) {
	if (server->transport_http) {
		rrr_net_transport_event_activate_all_connected_read(server->transport_http);
	}
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (server->transport_https) {
		rrr_net_transport_event_activate_all_connected_read(server->transport_https);
	}
#endif
#if defined(RRR_WITH_HTTP3)
	if (server->transport_quic) {
		rrr_net_transport_event_activate_all_connected_read(server->transport_quic);
	}
#endif
}

void rrr_http_server_start_shutdown (
		struct rrr_http_server *server
) {
	if (server->transport_http) {
		rrr_net_transport_shutdown(server->transport_http);
	}
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (server->transport_https) {
		rrr_net_transport_shutdown(server->transport_https);
	}
#endif
#if defined(RRR_WITH_HTTP3)
	if (server->transport_quic) {
		rrr_net_transport_shutdown(server->transport_quic);
	}
#endif

	__rrr_http_server_close_connections(server);

	server->shutdown_started = 1;
}
	
int rrr_http_server_shutdown_complete (
		struct rrr_http_server *server
) {
	rrr_length total = 0;
	rrr_length tmp = 0;
	rrr_length dummy = 0;

	if (server->transport_http) {
		rrr_net_transport_stats_get (
				&dummy,
				&tmp,
				server->transport_http
		);
		total += tmp;
	}
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (server->transport_https) {
		rrr_net_transport_stats_get (
				&dummy,
				&tmp,
				server->transport_https
		);
		total += tmp;
	}
#endif
#if defined(RRR_WITH_HTTP3)
	if (server->transport_quic) {
		rrr_net_transport_stats_get (
				&dummy,
				&tmp,
				server->transport_quic
		);
		total += tmp;
	}
#endif

	RRR_DBG_1("HTTP server shutdown complete check, %" PRIrrrl " active connections left\n", total);

	return total == 0;
}
