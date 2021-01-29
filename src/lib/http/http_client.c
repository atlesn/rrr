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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../log.h"

#include "http_client.h"
#include "http_common.h"
#include "http_part.h"
#include "http_util.h"
#include "http_session.h"
#include "http_client_config.h"
#include "http_application.h"
#ifdef RRR_WITH_NGHTTP2
#	include "http_application_http2.h"
#endif /* RRR_WITH_NGHTTP2 */
#include "http_transaction.h"
#include "http_redirect.h"

#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"

static void __rrr_http_client_dbl_ptr_free_if_not_null (void *arg) {
	void *ptr = *((void **) arg);
	RRR_FREE_IF_NOT_NULL(ptr);
}

static void __rrr_http_client_uri_dbl_ptr_destroy_if_not_null (void *arg) {
	struct rrr_http_uri *uri = *((void **) arg);
	if (uri != NULL) {
		rrr_http_util_uri_destroy(uri);
	}
}


void rrr_http_client_request_data_init (
		struct rrr_http_client_request_data *target
) {
	memset(target, '\0', sizeof(*target));
}

static int __rrr_http_client_request_data_strings_reset (
		struct rrr_http_client_request_data *data,
		const char *server,
		const char *endpoint,
		const char *user_agent
) {
	int ret = 0;

	if (server != NULL) {
		RRR_FREE_IF_NOT_NULL(data->server);
		if ((data->server = strdup(server)) == NULL) {
			RRR_MSG_0("Could not allocate memory for server in __rrr_http_client_request_data_strings_reset\n");
			ret = 1;
			goto out;
		}
	}

	if (endpoint != NULL) {
		RRR_FREE_IF_NOT_NULL(data->endpoint);
		if ((data->endpoint = strdup(endpoint)) == NULL) {
			RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_client_request_data_strings_reset\n");
			ret = 1;
			goto out;
		}
	}

	if (user_agent != NULL) {
		RRR_FREE_IF_NOT_NULL(data->user_agent);
		if ((data->user_agent = strdup(user_agent)) == NULL) {
			RRR_MSG_0("Could not allocate memory for user_agent in __rrr_http_client_request_data_strings_reset\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_request_data (
		struct rrr_http_client_request_data *target,
		const struct rrr_http_client_request_data *source
) {
	int ret = 0;

	memcpy(target, source, sizeof(*target));

	// Make sure all string pointers are reset to avoid mayhem
	target->server = NULL;
	target->endpoint = NULL;
	target->user_agent = NULL;

	if ((ret = __rrr_http_client_request_data_strings_reset(target, source->server, source->endpoint, source->user_agent)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset (
		struct rrr_http_client_request_data *data,
		enum rrr_http_transport transport_force,
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		int do_plain_http2,
		const char *user_agent
) {
	int ret = 0;

	if ((ret = __rrr_http_client_request_data_strings_reset(data, NULL, NULL, user_agent)) != 0) {
		goto out;
	}

	data->method = method;
	data->upgrade_mode = upgrade_mode;
	data->transport_force = transport_force;
	data->do_plain_http2 = do_plain_http2;

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_config (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_client_config *config
) {
	int ret = 0;

	if ((ret = __rrr_http_client_request_data_strings_reset(data, config->server, config->endpoint, NULL)) != 0) {
		goto out;
	}

	data->http_port = config->server_port;

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_uri (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_uri *uri
) {
	int ret = 0;

	struct rrr_http_uri_flags uri_flags = {0};
	rrr_http_util_uri_flags_get(&uri_flags, uri);

	if (uri_flags.is_http || uri_flags.is_websocket) {
		data->transport_force = (uri_flags.is_tls ? RRR_HTTP_TRANSPORT_HTTPS : RRR_HTTP_TRANSPORT_HTTP);
		data->upgrade_mode = (uri_flags.is_websocket ? RRR_HTTP_UPGRADE_MODE_WEBSOCKET : RRR_HTTP_UPGRADE_MODE_HTTP2);
	}

	if ((ret = __rrr_http_client_request_data_strings_reset(data, uri->host, uri->endpoint, NULL)) != 0) {
		goto out;
	}

	if (uri->port > 0) {
		data->http_port = uri->port;
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_raw (
		struct rrr_http_client_request_data *data,
		const char *server,
		uint16_t port
) {
	int ret = 0;

	if ((ret = __rrr_http_client_request_data_strings_reset(data, server, NULL, NULL)) != 0) {
		goto out;
	}

	data->http_port = port;

	out:
	return ret;
}

void rrr_http_client_request_data_cleanup (
		struct rrr_http_client_request_data *data
) {
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->endpoint);
	RRR_FREE_IF_NOT_NULL(data->user_agent);
}

void rrr_http_client_request_data_cleanup_void (
		void *data
) {
	rrr_http_client_request_data_cleanup(data);
}

struct rrr_http_client_tick_callback_data {
	int idle_timeout_ms;
	ssize_t read_max_size;
	uint64_t bytes_total;

	struct rrr_http_redirect_collection *redirects;

	int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS);
	void *final_callback_arg;
	int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS);
	void *get_response_callback_arg;
	int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *frame_callback_arg;
};

static int __rrr_http_client_chunks_iterate_callback (
		RRR_HTTP_PART_ITERATE_CALLBACK_ARGS
) {
	struct rrr_nullsafe_str *chunks_merged = arg;

	(void)(part_data_size);
	(void)(chunk_total);
	(void)(chunk_idx);

	return rrr_nullsafe_str_append_raw(chunks_merged, data_start, chunk_data_size);
}

static int __rrr_http_client_receive_http_part_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_client_tick_callback_data *callback_data = arg;

	(void)(handle);
	(void)(overshoot_bytes);
	(void)(unique_id);
	(void)(next_protocol_version);

	int ret = RRR_HTTP_OK;

	struct rrr_http_part *response_part = transaction->response_part;
	struct rrr_nullsafe_str *chunks_merged = NULL;

	if ((ret = rrr_nullsafe_str_new_or_replace_raw(&chunks_merged, NULL, 0)) != 0) {
		goto out;
	}

	// Moved-codes. Maybe this parsing is too persmissive.
	if (response_part->response_code >= 300 && response_part->response_code <= 399) {
		const struct rrr_http_header_field *location = rrr_http_part_header_field_get(response_part, "location");
		if (location == NULL || !rrr_nullsafe_str_isset(location->value)) {
			RRR_MSG_0("Could not find Location-field in HTTP redirect response %i %s\n",
					response_part->response_code, (response_part->response_str != NULL ? response_part->response_str : "-"));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, location->value);
		if ((transaction->remaining_redirects)-- == 0) {
			RRR_MSG_0("HTTP client maximum number of redirects reached after received redirect response with location '%s'\n", value);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		else {
			RRR_DBG_3("HTTP client redirect to '%s'\n", value);
		}

		if ((ret = rrr_http_redirect_collection_push (callback_data->redirects, transaction, location->value)) != 0) {
			goto out;
		}
		rrr_http_transaction_incref(transaction);

		goto out;
	}

	if ((ret = rrr_http_part_chunks_iterate (
			response_part,
			data_ptr,
			__rrr_http_client_chunks_iterate_callback,
			chunks_merged
	) != 0)) {
		RRR_MSG_0("Error while iterating chunks in response in __rrr_http_client_receive_callback_intermediate\n");
		goto out;
	}

	ret = callback_data->final_callback (
			transaction,
			chunks_merged,
			callback_data->final_callback_arg
	);

	out:
	rrr_nullsafe_str_destroy_if_not_null(&chunks_merged);
	return ret;
}

static int __rrr_http_client_websocket_handshake_callback (
		RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;

	(void)(handle);
	(void)(transaction);
	(void)(data_ptr);
	(void)(overshoot_bytes);
	(void)(unique_id);
	(void)(next_protocol_version);
	(void)(callback_data);

	int ret = 0;

	RRR_DBG_3("HTTP WebSocket handshake response from server received\n");

	*do_websocket = 1;

	return ret;
}

static int __rrr_http_client_request_send_final_transport_ctx_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;

	int ret = 0;

	char *query_to_free = NULL;
	char *endpoint_to_free = NULL;
	char *endpoint_and_query_to_free = NULL;

	struct rrr_http_application *upgraded_app = NULL;

	enum rrr_http_upgrade_mode upgrade_mode = callback_data->data->upgrade_mode;

	// Upgrade to HTTP2 only possibly with GET requests in plain mode or with all request methods in TLS mode
	if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2 && callback_data->data->method != RRR_HTTP_METHOD_GET && !rrr_net_transport_ctx_is_tls(handle)) {
		upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
	}

	if ((ret = rrr_http_session_transport_ctx_client_new_or_clean (
			callback_data->application_type,
			handle,
			callback_data->data->user_agent
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in __rrr_http_client_request_send_callback\n");
		goto out;
	}

	int request_send_is_possible;
	if ((ret = rrr_http_session_transport_ctx_request_send_possible (
			&request_send_is_possible,
			handle
	)) != 0) {
		RRR_MSG_0("Error while checking for request send possible in HTTP session in __rrr_http_client_request_send_callback\n");
		goto out;
	}

	if (!request_send_is_possible) {
		ret = RRR_HTTP_BUSY;
		goto out;
	}

	const char *endpoint_to_use = NULL;

	if (callback_data->query_prepare_callback != NULL) {
		if	((ret = callback_data->query_prepare_callback (
				&endpoint_to_free,
				&query_to_free,
				callback_data->transaction,
				callback_data->query_prepare_callback_arg)
		) != RRR_HTTP_OK) {
			if (ret == RRR_HTTP_SOFT_ERROR) {
				RRR_MSG_3("Note: HTTP query aborted by soft error from query prepare callback in __rrr_http_client_request_send_callback\n");
				ret = 0;
				goto out;
			}
			RRR_MSG_0("Error %i from query prepare callback in __rrr_http_client_request_send_callback\n", ret);
			goto out;
		}
	}

	// Endpoint to use precedence:
	// 1. endpoint from query prepare callback
	// 2. endpoint from configuration
	// 3. default endpoint /

	if (endpoint_to_free == NULL || *(endpoint_to_free) == '\0') {
		if (callback_data->data->endpoint != NULL) {
			endpoint_to_use = callback_data->data->endpoint;
		}
		else {
			RRR_FREE_IF_NOT_NULL(endpoint_to_free);
			if ((endpoint_to_free = strdup("/")) == NULL) {
				RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_client_request_send_callback\n");
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}
			endpoint_to_use = endpoint_to_free;
		}
	}
	else {
		endpoint_to_use = endpoint_to_free;
	}

	if (query_to_free != NULL && *(query_to_free) != '\0') {
		if (strchr(endpoint_to_use, '?') != 0) {
			RRR_MSG_0("HTTP endpoint '%s' already contained a query string, cannot append query '%s' from callback. Request aborted.\n",
					endpoint_to_use, query_to_free);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		if ((ret = rrr_asprintf(&endpoint_and_query_to_free, "%s?%s", endpoint_to_use, query_to_free)) <= 0) {
			RRR_MSG_0("Could not allocate string for endpoint and query in __rrr_http_client_request_send_callback return was %i\n", ret);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}
	else {
		if ((endpoint_and_query_to_free = strdup(endpoint_to_use)) == NULL) {
			RRR_MSG_0("Could not allocate string for endpoint in __rrr_http_client_request_send_callback\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	RRR_DBG_3("HTTP using endpoint: '%s'\n", endpoint_and_query_to_free);

	if ((ret = rrr_http_transaction_endpoint_set (
			callback_data->transaction,
			endpoint_and_query_to_free
	)) != 0) {
		RRR_MSG_0("Could not set HTTP endpoint in __rrr_http_client_request_send_callback\n");
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_request_send (
			&upgraded_app,
			handle,
			callback_data->request_header_host,
			callback_data->transaction,
			upgrade_mode
	)) != 0) {
		RRR_MSG_0("Could not send request in __rrr_http_client_request_send_callback, return was %i\n", ret);
		goto out;
	}

	// Happens during TLS downgrade from HTTP2 to HTTP1 when ALPN negotiation fails
	if (upgraded_app != NULL) {
		rrr_http_session_transport_ctx_application_set(&upgraded_app, handle);
	}

	goto out;
	out:
		rrr_http_application_destroy_if_not_null(&upgraded_app);
		RRR_FREE_IF_NOT_NULL(endpoint_to_free);
		RRR_FREE_IF_NOT_NULL(endpoint_and_query_to_free);
		RRR_FREE_IF_NOT_NULL(query_to_free);
		return ret;
}

void __rrr_http_client_request_send_connect_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	(void)(sockaddr);
	(void)(socklen);

	int *result = arg;
	*result = handle->handle;
}

static int __rrr_http_client_request_send_intermediate_connect (
		struct rrr_net_transport *transport_keepalive,
		struct rrr_http_client_request_callback_data *callback_data,
		const char *server_to_use,
		const uint16_t port_to_use
) {
	int ret = 0;

	int keepalive_handle = rrr_net_transport_handle_get_by_match(transport_keepalive, server_to_use, port_to_use);

	if (keepalive_handle == 0) {
		if (rrr_net_transport_connect (
				transport_keepalive,
				port_to_use,
				server_to_use,
				__rrr_http_client_request_send_connect_callback,
				&keepalive_handle
		) != 0) {
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		if ((ret = rrr_net_transport_match_data_set(transport_keepalive, keepalive_handle, server_to_use, port_to_use)) != 0) {
			goto out;
		}
	}

	ret = rrr_net_transport_handle_with_transport_ctx_do (
			transport_keepalive,
			keepalive_handle,
			__rrr_http_client_request_send_final_transport_ctx_callback,
			callback_data
	);

	out:
		return ret;
}

static int __rrr_http_client_request_send_transport_keepalive_select (
		struct rrr_net_transport **transport_keepalive_use,
		struct rrr_net_transport *transport_keepalive_plain,
		struct rrr_net_transport *transport_keepalive_tls,
		const enum rrr_http_transport transport_force,
		const enum rrr_http_transport transport_code
) {
	int ret = 0;

	if (transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
		*transport_keepalive_use = transport_keepalive_tls;
	}
	else if (transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
		RRR_MSG_0("Warning: HTTPS force was enabled but plain HTTP was attempted (possibly following redirect), aborting request\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}
	else {
		*transport_keepalive_use = transport_keepalive_plain;
	}

	if (*transport_keepalive_use == NULL) {
		RRR_MSG_0("No transport found for HTTP transport %s, transport is not supported\n", RRR_HTTP_TRANSPORT_TO_STR(transport_code));
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_client_request_send_transport_keepalive_ensure (
		struct rrr_net_transport **transport_keepalive_plain,
		struct rrr_net_transport **transport_keepalive_tls,
		const struct rrr_net_transport_config *net_transport_config,
		const int ssl_no_cert_verify
) {
	int ret = 0;

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
	if (*transport_keepalive_tls == NULL) {
		struct rrr_net_transport_config net_transport_config_tmp = *net_transport_config;

		net_transport_config_tmp.transport_type = RRR_NET_TRANSPORT_TLS;

		int tls_flags = 0;
		if (ssl_no_cert_verify != 0) {
			tls_flags |= RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY;
		}

		const char *alpn_protos = NULL;
		unsigned alpn_protos_length = 0;

#if RRR_WITH_NGHTTP2
		rrr_http_application_http2_alpn_protos_get(&alpn_protos, &alpn_protos_length);
#endif /* RRR_WITH_NGHTTP2 */

		if (rrr_net_transport_new (
				transport_keepalive_tls,
				&net_transport_config_tmp,
				tls_flags,
				alpn_protos,
				alpn_protos_length
		) != 0) {
			RRR_MSG_0("Could not create TLS transport in __rrr_http_client_request_send_transport_keepalive_ensure\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}
#else
	(void)(transport_keepalive_tls);
	(void)(net_transport_config);
	(void)(ssl_no_cert_verify);
#endif

	if (*transport_keepalive_plain == NULL) {
		struct rrr_net_transport_config net_transport_config_tmp = {
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				RRR_NET_TRANSPORT_PLAIN
		};

		if (rrr_net_transport_new (
				transport_keepalive_plain,
				&net_transport_config_tmp,
				0,
				NULL,
				0
		) != 0) {
			RRR_MSG_0("Could not create plain transport in __rrr_http_client_request_send_transport_keepalive_ensure\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

// Note that data in the struct may change if there are any redirects
// Note that query prepare callback is not called if raw request data is set
static int __rrr_http_client_request_send (
		const struct rrr_http_client_request_data *data,
		struct rrr_net_transport **transport_keepalive_plain,
		struct rrr_net_transport **transport_keepalive_tls,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		int (*method_prepare_callback)(RRR_HTTP_CLIENT_METHOD_PREPARE_CALLBACK_ARGS),
		void *method_prepare_callback_arg,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
) {
	int ret = 0;

	struct rrr_http_transaction *transaction = NULL;
	char *server_to_free = NULL;

	struct rrr_http_client_request_callback_data callback_data = {0};

	if (transport_keepalive_plain == NULL || transport_keepalive_tls == NULL) {
		RRR_BUG("BUG: Transport keepalive return pointer was NULL in __rrr_http_client_request_send\n");
	}

	if ((ret = rrr_http_transaction_new (
			&transaction,
			data->method,
			remaining_redirects,
			application_data,
			application_data_destroy
	)) != 0) {
		RRR_MSG_0("Could not create HTTP transaction in __rrr_http_client_request_send\n");
		goto out;
	}

	callback_data.data = data;
	callback_data.query_prepare_callback = query_prepare_callback;
	callback_data.query_prepare_callback_arg = query_prepare_callback_arg;
	callback_data.application_type = RRR_HTTP_APPLICATION_HTTP1;
	callback_data.transaction = transaction;

	uint16_t port_to_use = data->http_port;
	enum rrr_http_transport transport_code = RRR_HTTP_TRANSPORT_ANY;

	if (data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}
	else if (data->transport_force == RRR_HTTP_TRANSPORT_HTTP) {
		transport_code = RRR_HTTP_TRANSPORT_HTTP;
	}

	if (port_to_use == 0) {
		if (transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
			port_to_use = 443;
		}
		else {
			port_to_use = 80;
		}
	}

	const char *server_to_use = data->server;

	if (connection_prepare_callback != NULL) {
		if ((ret = connection_prepare_callback(&server_to_free, &port_to_use, connection_prepare_callback_arg)) != 0) {
			if (ret == RRR_HTTP_SOFT_ERROR) {
				RRR_DBG_3("Note: HTTP query aborted by soft error from connection prepare callback\n");
				goto out;
			}
			RRR_MSG_0("Error %i from HTTP client connection prepare callback\n", ret);
			goto out;
		}
		if (server_to_free != NULL) {
			server_to_use = server_to_free;
		}
	}

	if (server_to_use == NULL) {
		RRR_BUG("BUG: No server set in __rrr_http_client_request_send\n");
	}

	if (port_to_use == 0) {
		RRR_BUG("BUG: Port was 0 in __rrr_http_client_request_send\n");
	}

	if (transport_code == RRR_HTTP_TRANSPORT_ANY && port_to_use == 443) {
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}

#ifdef RRR_WITH_NGHTTP2
	// If upgrade mode is HTTP2, force HTTP2 application when HTTPS is used
	if (data->upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2 && transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
		callback_data.application_type = RRR_HTTP_APPLICATION_HTTP2;
	}

	if (data->do_plain_http2 && transport_code != RRR_HTTP_TRANSPORT_HTTPS) {
		callback_data.application_type = RRR_HTTP_APPLICATION_HTTP2;
	}
#endif /* RRR_WITH_NGHTTP2 */

	callback_data.request_header_host = server_to_use;

	if (method_prepare_callback != NULL) {
		enum rrr_http_method chosen_method = data->method;
		if ((ret = method_prepare_callback(&chosen_method, transaction, method_prepare_callback_arg)) != 0) {
			if (ret != RRR_HTTP_NO_RESULT) {
				goto out;
			}
		}
		else {
			rrr_http_transaction_method_set(transaction, chosen_method);
		}
	}

	RRR_DBG_3("HTTP client request using server %s port %u transport %s method '%s' application '%s' upgrade mode '%s'\n",
			server_to_use,
			port_to_use,
			RRR_HTTP_TRANSPORT_TO_STR(transport_code),
			RRR_HTTP_METHOD_TO_STR(transaction->method),
			RRR_HTTP_APPLICATION_TO_STR(callback_data.application_type),
			RRR_HTTP_UPGRADE_MODE_TO_STR(data->upgrade_mode)
	);

	if ((ret = __rrr_http_client_request_send_transport_keepalive_ensure (
			transport_keepalive_plain,
			transport_keepalive_tls,
			net_transport_config,
			data->ssl_no_cert_verify
	)) != 0) {
		goto out;
	}

	struct rrr_net_transport *transport_keepalive_to_use = NULL;

	if ((ret = __rrr_http_client_request_send_transport_keepalive_select (
			&transport_keepalive_to_use,
			*transport_keepalive_plain,
			*transport_keepalive_tls,
			data->transport_force,
			transport_code
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_client_request_send_intermediate_connect (
			transport_keepalive_to_use,
			&callback_data,
			server_to_use,
			port_to_use
	)) != 0) {
		if (ret == RRR_HTTP_BUSY) {
			RRR_DBG_3("HTTP application temporarily busy during request to server %s port %u transport %s in http client\n",
				server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code));
		}
		else {
			RRR_DBG_2("HTTP request to server %s port %u transport %s failed in http client, return was %i\n",
				server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code), ret);
		}
		goto out;
	}

	out:
	rrr_http_transaction_decref_if_not_null(transaction);
	RRR_FREE_IF_NOT_NULL(server_to_free);
	return ret;
}

void rrr_http_client_terminate_if_open (
		struct rrr_net_transport *transport_keepalive,
		int transport_keepalive_handle
) {
	if (transport_keepalive == NULL || transport_keepalive_handle == 0) {
		return;
	}

	rrr_net_transport_handle_with_transport_ctx_do (
			transport_keepalive,
			transport_keepalive_handle,
			rrr_http_session_transport_ctx_close_if_open,
			NULL
	);
}

int rrr_http_client_request_send (
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport **transport_keepalive_plain,
		struct rrr_net_transport **transport_keepalive_tls,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		int (*method_prepare_callback)(RRR_HTTP_CLIENT_METHOD_PREPARE_CALLBACK_ARGS),
		void *method_prepare_callback_arg,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
) {
	return __rrr_http_client_request_send (
			data,
			transport_keepalive_plain,
			transport_keepalive_tls,
			net_transport_config,
			remaining_redirects,
			method_prepare_callback,
			method_prepare_callback_arg,
			connection_prepare_callback,
			connection_prepare_callback_arg,
			query_prepare_callback,
			query_prepare_callback_arg,
			application_data,
			application_data_destroy
	);
}

struct rrr_http_client_redirect_callback_data {
	int (*callback)(RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_client_redirect_callback (
		struct rrr_http_transaction *transaction,
		const struct rrr_nullsafe_str *uri_nullsafe,
		void *arg
) {
	struct rrr_http_client_redirect_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_http_uri *uri = NULL;
	char *endpoint_path_tmp = NULL;

	pthread_cleanup_push(__rrr_http_client_uri_dbl_ptr_destroy_if_not_null, &uri);
	pthread_cleanup_push(__rrr_http_client_dbl_ptr_free_if_not_null, &endpoint_path_tmp);

	if (callback_data->callback == NULL) {
		RRR_MSG_0("HTTP client got a redirect response but no redirect callback is defined\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (rrr_http_util_uri_parse(&uri, uri_nullsafe) != 0) {
		RRR_MSG_0("Could not parse Location from redirect response header\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}


	if (uri->endpoint == NULL || *(uri->endpoint) != '/') {
		if ((ret = rrr_http_transaction_endpoint_path_get (&endpoint_path_tmp, transaction)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_util_uri_endpoint_prepend(uri, endpoint_path_tmp)) != 0) {
			goto out;
		}
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(response_arg, uri_nullsafe);
	RRR_DBG_3("HTTP redirect to '%s' (%s, %s, %s, %u) original endpoint was '%s'\n",
			response_arg,
			(uri->protocol != NULL ? uri->protocol : "-"),
			(uri->host != NULL ? uri->host : "-"),
			(uri->endpoint != NULL ? uri->endpoint : "-"),
			uri->port,
			transaction->endpoint_str
	);

	ret = callback_data->callback(transaction, uri, callback_data->callback_arg);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_client_tick_handle_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_client_tick_callback_data *callback_data = arg;

	ssize_t received_bytes_dummy = 0;
	uint64_t complete_transactions_count_dummy = 0;

	int ret = rrr_http_session_transport_ctx_tick (
			&received_bytes_dummy,
			&complete_transactions_count_dummy,
			handle,
			callback_data->read_max_size,
			0, // No unique ID
			1, // Is client
			NULL,
			NULL,
			__rrr_http_client_websocket_handshake_callback,
			callback_data,
			__rrr_http_client_receive_http_part_callback,
			callback_data,
			callback_data->get_response_callback,
			callback_data->get_response_callback_arg,
			callback_data->frame_callback,
			callback_data->frame_callback_arg
	);

	rrr_net_transport_ctx_get_socket_stats(NULL, NULL, &callback_data->bytes_total, handle);

	return ret;
}

int rrr_http_client_tick (
		uint64_t *bytes_total,
		struct rrr_net_transport *transport_keepalive_plain,
		struct rrr_net_transport *transport_keepalive_tls,
		ssize_t read_max_size,
		unsigned int idle_timeout_ms,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg,
		int (*redirect_callback)(RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS),
		void *redirect_callback_arg,
		int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg
) {
	int ret = 0;

	*bytes_total = 0;

	struct rrr_http_redirect_collection redirects = {0};

	pthread_cleanup_push(rrr_http_redirect_collection_clear_void, &redirects);

	struct rrr_http_client_tick_callback_data callback_data = {
			idle_timeout_ms,
			read_max_size,
			0,
			&redirects,
			final_callback,
			final_callback_arg,
			get_response_callback,
			get_response_callback_arg,
			frame_callback,
			frame_callback_arg
	};


	if (transport_keepalive_plain != NULL) {
		if ((ret = rrr_net_transport_iterate_with_callback (
				transport_keepalive_plain,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_tick_handle_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}

	if (transport_keepalive_tls != NULL) {
		if ((ret = rrr_net_transport_iterate_with_callback (
				transport_keepalive_tls,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_tick_handle_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}

	struct rrr_http_client_redirect_callback_data redirect_callback_data = {
			redirect_callback,
			redirect_callback_arg
	};

	if ((ret = rrr_http_redirect_collection_iterate (
			&redirects,
			__rrr_http_client_redirect_callback,
			&redirect_callback_data
	)) != 0) {
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

