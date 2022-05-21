/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

RRR_HTTP_SERVER_DEFINE_SET_FUNCTION(no_body_parse);
RRR_HTTP_SERVER_DEFINE_SET_FUNCTION(no_server_http2);
RRR_HTTP_SERVER_DEFINE_SET_FUNCTION_BIGLENGTH(server_request_max_size);

static void __rrr_http_server_accept_callback (
		RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS
) {
	struct rrr_http_server *http_server = arg;

	(void)(http_server);

	char buf[256];
	rrr_ip_to_str(buf, sizeof(buf), sockaddr, socklen);
	RRR_DBG_3("HTTP accept for %s family %i using fd %i\n",
			buf, sockaddr->sa_family, RRR_NET_TRANSPORT_CTX_FD(handle));
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
static int __rrr_http_server_websocket_get_response_callback (
		RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS
);
static int __rrr_http_server_websocket_frame_callback (
		RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS
);
static int __rrr_http_server_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
);

static void __rrr_http_server_handshake_complete_callback (
		RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	struct rrr_http_application *application = NULL;

	const char *alpn_selected_proto = NULL;
	rrr_net_transport_ctx_selected_proto_get(&alpn_selected_proto, handle);

	const struct rrr_http_application_callbacks callbacks = {
		http_server->callbacks.unique_id_generator_callback,
		http_server->callbacks.unique_id_generator_callback_arg,
		__rrr_http_server_upgrade_verify_callback,
		http_server,
		__rrr_http_server_websocket_handshake_callback,
		http_server,
		__rrr_http_server_websocket_get_response_callback,
		http_server,
		__rrr_http_server_websocket_frame_callback,
		http_server,
		__rrr_http_server_receive_callback,
		http_server,
		NULL,
		NULL,
		http_server->callbacks.async_response_get_callback,
		http_server->callbacks.async_response_get_callback_arg,
	};

	if (rrr_http_application_new (
			&application,
			(alpn_selected_proto != NULL && strcmp(alpn_selected_proto, "h2") == 0 ? RRR_HTTP_APPLICATION_HTTP2 : RRR_HTTP_APPLICATION_HTTP1),
			1, // Is server
			&callbacks
	) != 0) {
		RRR_MSG_0("Could not create HTTP application in __rrr_http_server_handshake_comlete_callback\n");
		goto out;
	}

	if (rrr_http_session_transport_ctx_server_new (
			&application,
			handle
	) != 0) {
		RRR_MSG_0("Could not create HTTP session in %s\n", __func__);
		goto out;
	}

	RRR_DBG_3("HTTP handshake complete for fd %i\n",
			RRR_NET_TRANSPORT_CTX_FD(handle));

	out:
	rrr_http_application_destroy_if_not_null(&application);
	return;
}

static int __rrr_http_server_upgrade_verify_callback (
		RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS
) {
	struct rrr_http_server *http_server = arg;

	(void)(from);

	if (to == RRR_HTTP_UPGRADE_MODE_HTTP2 && http_server->rules.do_no_server_http2) {
		*do_upgrade = 0;
	}
	else {
		*do_upgrade = 1;
	}

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
			http_server->callbacks.final_callback_arg
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

	ret |= rrr_http_part_header_field_push(response_part, "access-control-request-methods", "OPTIONS, GET, POST, PUT");

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
				(transaction->request_part->parsed_application_type == RRR_HTTP_APPLICATION_HTTP2
					? "HTTP/2"
					: (transaction->request_part->parsed_version == RRR_HTTP_VERSION_10
						? "HTTP/1.0"
						: "HTTP/1.1"
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
				http_server->callbacks.final_callback_arg
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
				http_server->callbacks.websocket_get_response_callback_arg
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
				http_server->callbacks.websocket_handshake_callback_arg
		);
	}

	return ret;
}

static int __rrr_http_server_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
) {
	struct rrr_http_server *http_server = arg;

	int ret = 0;

	int again_max = 5;

	rrr_biglength received_bytes_dummy = 0;

	again:
	if ((ret = rrr_http_session_transport_ctx_tick_server (
			&received_bytes_dummy,
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

	if (rrr_http_session_transport_ctx_need_tick(handle)) {
		if (again_max--) {
			goto again;
		}
		rrr_net_transport_ctx_notify_read(handle);
	}

	// Clean up often to prevent huge number of HTTP2 streams waiting to be cleaned up
	rrr_http_session_transport_ctx_active_transaction_count_get_and_maintain(handle);

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
	struct rrr_http_server *server;
	struct rrr_net_transport **result_transport;
	const struct rrr_net_transport_config *net_transport_config;
	const int net_transport_flags;
	struct rrr_event_queue *queue;
	const uint64_t first_read_timeout_ms;
	const uint64_t hard_timeout_ms;
	const uint64_t ping_timeout_ms;
	const rrr_length send_chunk_count_limit;
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
			"HTTP server",
			callback_data->net_transport_flags,
			callback_data->queue,
			alpn_protos,
			alpn_protos_length,
			callback_data->first_read_timeout_ms,
			callback_data->ping_timeout_ms,
			callback_data->hard_timeout_ms,
			callback_data->send_chunk_count_limit,
			RRR_HTTP_SERVER_NET_TRANSPORT_CALLBACKS
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
		RRR_BUG("BUG: Double call to __rrr_http_server_start, pointer already set\n");
	}

	const uint64_t hard_timeout_ms = (read_timeout_ms < 1000 ? 1000 : read_timeout_ms);
	const uint64_t ping_timeout_ms = hard_timeout_ms / 2;

	if (net_transport_config->transport_type == RRR_NET_TRANSPORT_TLS) {
		struct rrr_http_server_start_alpn_protos_callback_data callback_data = {
				http_server,
				result_transport,
				net_transport_config,
				net_transport_flags,
				queue,
				first_read_timeout_ms,
				hard_timeout_ms,
				ping_timeout_ms,
				send_chunk_count_limit
		};

		ret = rrr_http_application_alpn_protos_with_all_do (
				__rrr_http_server_start_alpn_protos_callback,
				&callback_data
		);
	}
	else {
		ret = rrr_net_transport_new (
				result_transport,
				net_transport_config,
				"HTTP server",
				net_transport_flags,
				queue,
				NULL,
				0,
				first_read_timeout_ms,
				ping_timeout_ms,
				hard_timeout_ms,
				send_chunk_count_limit,
				RRR_HTTP_SERVER_NET_TRANSPORT_CALLBACKS
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not create HTTP transport in __rrr_http_server_start return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if (queue != NULL) {
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
			NULL,
			RRR_NET_TRANSPORT_PLAIN
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

	net_transport_config_tls.transport_type = RRR_NET_TRANSPORT_TLS;

	if (server->rules.do_no_server_http2) {
		net_transport_flags |= RRR_NET_TRANSPORT_F_TLS_NO_ALPN;
	}

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
}
