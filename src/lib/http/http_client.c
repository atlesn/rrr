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
#include "http_client_target_collection.h"

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
	int timeout_s;
	ssize_t read_max_size;
	uint64_t bytes_total;

	struct rrr_http_redirect_collection *redirects;

	int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS);
	void *final_callback_arg;
	int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS);
	void *get_response_callback_arg;
	int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *frame_callback_arg;
	int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS);
	void *raw_callback_arg;
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
	else if (response_part->response_code < 200 || response_part->response_code > 299) {
		RRR_MSG_0("Error while fetching HTTP: %i %s\n",
				response_part->response_code, (response_part->response_str != NULL ? response_part->response_str : "-"));
		ret = RRR_HTTP_SOFT_ERROR;
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

	struct rrr_http_transaction *transaction = NULL;
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

	if (callback_data->raw_request_data != NULL) {
		if (callback_data->raw_request_data_size == 0) {
			RRR_DBG_1("Raw request data was set in __rrr_http_client_request_send_callback_final but size was 0, nothing to send.\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		if ((ret = rrr_http_session_transport_ctx_request_raw_send (
				handle,
				callback_data->raw_request_data,
				callback_data->raw_request_data_size
		)) != 0) {
			RRR_MSG_0("Could not send raw request in __rrr_http_client_request_send_callback\n");
			goto out;
		}
	}
	else {
		const char *endpoint_to_use = NULL;

		if ((ret = rrr_http_transaction_new (
				&transaction,
				callback_data->data->method,
				callback_data->remaining_redirects,
				callback_data->application_data,
				callback_data->application_data_destroy
		)) != 0) {
			RRR_MSG_0("Could not create HTTP transaction in __rrr_http_client_request_send_callback\n");
			goto out;
		}

		if (callback_data->query_prepare_callback != NULL) {
			if	((ret = callback_data->query_prepare_callback (
					&endpoint_to_free,
					&query_to_free,
					transaction,
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
				transaction,
				endpoint_and_query_to_free
		)) != 0) {
			RRR_MSG_0("Could not set HTTP endpoint in __rrr_http_client_request_send_callback\n");
			goto out;
		}

		if ((ret = rrr_http_session_transport_ctx_request_send (
				&upgraded_app,
				handle,
				callback_data->request_header_host,
				transaction,
				upgrade_mode
		)) != 0) {
			RRR_MSG_0("Could not send request in __rrr_http_client_request_send_callback, return was %i\n", ret);
			goto out;
		}
	}

	// Happens during TLS downgrade from HTTP2 to HTTP1 when ALPN negotiation fails
	if (upgraded_app != NULL) {
		rrr_http_session_transport_ctx_application_set(&upgraded_app, handle);
	}

	goto out;
	out:
		rrr_http_application_destroy_if_not_null(&upgraded_app);
		rrr_http_transaction_decref_if_not_null(transaction);
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

static int __rrr_http_client_request_send_intermediate_target_create (
		struct rrr_net_transport *transport_keepalive,
		struct rrr_http_client_target_collection *targets,
		struct rrr_http_client_request_callback_data *callback_data,
		const char *server_to_use,
		const uint16_t port_to_use
) {
	int ret = 0;

	struct rrr_http_client_target *target = rrr_http_client_target_find_or_new(targets, server_to_use, port_to_use);
	if (target == NULL) {
		ret = 1;
		goto out;
	}

	if (target->keepalive_handle == 0) {
		if ((ret = rrr_net_transport_connect (
				transport_keepalive,
				port_to_use,
				server_to_use,
				__rrr_http_client_request_send_connect_callback,
				&target->keepalive_handle
		)) != 0) {
			ret = RRR_HTTP_SOFT_ERROR;
			goto out_remove_target;
		}
	}

	if ((ret = rrr_net_transport_handle_with_transport_ctx_do (
			transport_keepalive,
			target->keepalive_handle,
			__rrr_http_client_request_send_final_transport_ctx_callback,
			callback_data
	)) != 0) {
		goto out_remove_target;
	}

	goto out;
	out_remove_target:
		rrr_http_client_target_collection_remove(targets, target->keepalive_handle, transport_keepalive);
	out:
		return ret;
}

static int __rrr_http_client_request_send_transport_keepalive_ensure (
		struct rrr_net_transport **transport_keepalive,
		const struct rrr_net_transport_config *net_transport_config,
		const enum rrr_http_transport transport_force,
		const enum rrr_http_transport transport_code,
		const int ssl_no_cert_verify
) {
	int ret = 0;

	if (*transport_keepalive != NULL) {
		goto out;
	}

	if (transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
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

		ret = rrr_net_transport_new (
				transport_keepalive,
				&net_transport_config_tmp,
				tls_flags,
				alpn_protos,
				alpn_protos_length
		);
	}
	else if (transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
		RRR_MSG_0("Warning: HTTPS force was enabled but plain HTTP was attempted (possibly following redirect), aborting request\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}
	else {
		struct rrr_net_transport_config net_transport_config_tmp = {
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				RRR_NET_TRANSPORT_PLAIN
		};

		ret = rrr_net_transport_new (
				transport_keepalive,
				&net_transport_config_tmp,
				0,
				NULL,
				0
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not create transport in __rrr_http_client_request_send_transport_keepalive_ensure\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

// Note that data in the struct may change if there are any redirects
// Note that query prepare callback is not called if raw request data is set
static int __rrr_http_client_request_send (
		const struct rrr_http_client_request_data *data,
		struct rrr_net_transport **transport_keepalive,
		struct rrr_http_client_target_collection *targets,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		const char *raw_request_data,
		size_t raw_request_data_size,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
) {
	int ret = 0;

	char *server_to_free = NULL;
	struct rrr_http_client_request_callback_data callback_data = {0};

	if (transport_keepalive == NULL) {
		RRR_BUG("BUG: Transport keepalive return pointer was NULL in __rrr_http_client_request_send\n");
	}

	callback_data.data = data;
	callback_data.raw_request_data = raw_request_data;
	callback_data.raw_request_data_size = raw_request_data_size;
	callback_data.query_prepare_callback = query_prepare_callback;
	callback_data.query_prepare_callback_arg = query_prepare_callback_arg;
	callback_data.application_type = RRR_HTTP_APPLICATION_HTTP1;
	callback_data.application_data = application_data;
	callback_data.application_data_destroy = application_data_destroy;
	callback_data.remaining_redirects = remaining_redirects;

	uint16_t port_to_use = data->http_port;
	enum rrr_http_transport transport_code = RRR_HTTP_TRANSPORT_ANY;

	if (data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
/*		if (transport_code != RRR_HTTP_TRANSPORT_HTTPS && transport_code != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_0("Requested URI contained non-https transport while force SSL was active, cannot continue\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}*/
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}
	else if (data->transport_force == RRR_HTTP_TRANSPORT_HTTP) {
/*		if (transport_code != RRR_HTTP_TRANSPORT_HTTPS && transport_code != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_0("Requested URI contained non-http transport while force plaintext was active, cannot continue\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}*/
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

	RRR_DBG_3("Using server %s port %u transport %s method '%s' application '%s' upgrade mode '%s'\n",
			server_to_use,
			port_to_use,
			RRR_HTTP_TRANSPORT_TO_STR(transport_code),
			RRR_HTTP_METHOD_TO_STR(data->method),
			RRR_HTTP_APPLICATION_TO_STR(callback_data.application_type),
			RRR_HTTP_UPGRADE_MODE_TO_STR(data->upgrade_mode)
	);

	if ((ret = __rrr_http_client_request_send_transport_keepalive_ensure (
			transport_keepalive,
			net_transport_config,
			data->transport_force,
			transport_code,
			data->ssl_no_cert_verify
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_client_request_send_intermediate_target_create (
			*transport_keepalive,
			targets,
			&callback_data,
			server_to_use,
			port_to_use
	)) != 0) {
		RRR_MSG_0("HTTP Connection failed to server %s port %u transport %s in http client return was %i\n",
				server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code), ret);
		goto out;
	}

	out:
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
		struct rrr_net_transport **transport_keepalive,
		struct rrr_http_client_target_collection *targets,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
) {
	return __rrr_http_client_request_send (
			data,
			transport_keepalive,
			targets,
			net_transport_config,
			remaining_redirects,
			NULL,
			0,
			connection_prepare_callback,
			connection_prepare_callback_arg,
			query_prepare_callback,
			query_prepare_callback_arg,
			application_data,
			application_data_destroy
	);
}

int rrr_http_client_request_raw_send (
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport **transport_keepalive,
		struct rrr_http_client_target_collection *targets,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		const char *raw_request_data,
		size_t raw_request_data_size,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg
) {
	return __rrr_http_client_request_send (
			data,
			transport_keepalive,
			targets,
			net_transport_config,
			remaining_redirects,
			raw_request_data,
			raw_request_data_size,
			connection_prepare_callback,
			connection_prepare_callback_arg,
			NULL,
			NULL,
			NULL,
			NULL
	);
}

static int __rrr_http_client_transport_ctx_tick (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_client_tick_callback_data *callback_data = arg;

	ssize_t received_bytes_dummy = 0;

	int ret = rrr_http_session_transport_ctx_tick (
			&received_bytes_dummy,
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
			callback_data->frame_callback_arg,
			callback_data->raw_callback,
			callback_data->raw_callback_arg
	);

	rrr_net_transport_ctx_get_socket_stats(NULL, NULL, &callback_data->bytes_total, handle);

	return ret;
}

struct rrr_http_client_redirect_callback_data {
	struct rrr_http_client_target_collection *targets;
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

int rrr_http_client_tick (
		uint64_t *bytes_total,
		struct rrr_net_transport *transport_keepalive,
		struct rrr_http_client_target_collection *targets,
		ssize_t read_max_size,
		int keepalive_timeout_s,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg,
		int (*redirect_callback)(RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS),
		void *redirect_callback_arg,
		int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_arg
) {
	if (transport_keepalive == NULL) {
		RRR_BUG("BUG: NULL transport keepalive to rrr_http_client_tick\n");
	}

	// Return is only set if there is a HARD error
	int ret = 0;

	*bytes_total = 0;

	struct rrr_http_redirect_collection redirects = {0};

	pthread_cleanup_push(rrr_http_redirect_collection_clear_void, &redirects);

	struct rrr_http_client_tick_callback_data callback_data = {
			0,
			read_max_size,
			0,
			&redirects,
			final_callback,
			final_callback_arg,
			get_response_callback,
			get_response_callback_arg,
			frame_callback,
			frame_callback_arg,
			raw_callback,
			raw_callback_arg
	};

	uint64_t timeout_limit = rrr_time_get_64() - (keepalive_timeout_s * 1000 * 1000);
	RRR_LL_ITERATE_BEGIN(targets, struct rrr_http_client_target);
		if (node->keepalive_handle == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_NEXT();
		}

		callback_data.bytes_total = 0;

		int ret_tmp = rrr_net_transport_handle_with_transport_ctx_do (
				transport_keepalive,
				node->keepalive_handle,
				__rrr_http_client_transport_ctx_tick,
				&callback_data
		);

		*bytes_total += callback_data.bytes_total;

		// Run all IF's, no else if
		if (ret_tmp != 0 && ret_tmp != RRR_HTTP_OK && ret_tmp != RRR_READ_INCOMPLETE) {
			RRR_DBG_3("HTTP client connection %s:%u complete\n",
					node->server, node->port);
			RRR_LL_ITERATE_SET_DESTROY();
		}
		if (ret_tmp != 0 && ret_tmp != RRR_READ_INCOMPLETE && ret_tmp != RRR_READ_EOF) {
			RRR_MSG_0("HTTP client error during ticking with server %s:%u, return was %i\n",
					node->server,
					node->port,
					ret_tmp);
			RRR_LL_ITERATE_SET_DESTROY();
		}
		if (node->last_used < timeout_limit) {
			RRR_DBG_3("HTTP client keepalive timeout for connection %s:%u after %i seconds\n",
					node->server, node->port, keepalive_timeout_s);
			RRR_LL_ITERATE_SET_DESTROY();
		}
		if (ret_tmp == RRR_HTTP_HARD_ERROR) {
			ret = RRR_HTTP_HARD_ERROR;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY (
			targets,
			0;
			rrr_http_client_terminate_if_open(transport_keepalive, node->keepalive_handle);
			rrr_http_client_target_destroy_and_close(node, transport_keepalive);
			rrr_net_transport_maintenance (transport_keepalive);
	);

	if (ret != 0) {
		goto out;
	}

	struct rrr_http_client_redirect_callback_data redirect_callback_data = {
			targets,
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

