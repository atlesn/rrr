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

#include "../log.h"

#include "http_client.h"
#include "http_common.h"
#include "http_part.h"
#include "http_util.h"
#include "http_session.h"
#include "http_client_config.h"

#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"

int rrr_http_client_data_init (
		struct rrr_http_client_request_data *data,
		const char *user_agent
) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	if ((data->user_agent = strdup(user_agent)) == NULL) {
		RRR_MSG_0("Could not allocate memory for user agent in rrr_http_client_data_init\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_http_client_data_reset (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_client_config *config,
		enum rrr_http_transport transport_force
) {
	int ret = 0;

	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->endpoint);

	if (config->server != NULL && (data->server = strdup(config->server)) == NULL) {
		RRR_MSG_0("Could not allocate memory for server in rrr_http_client_data_reset\n");
		ret = 1;
		goto out;
	}
	if (config->endpoint != NULL && (data->endpoint = strdup(config->endpoint)) == NULL) {
		RRR_MSG_0("Could not allocate memory for endpoint in rrr_http_client_data_reset\n");
		ret = 1;
		goto out;
	}

	data->transport_force = transport_force;
	data->http_port = config->server_port;

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

static int __rrr_http_client_receive_chunk_callback (
		RRR_HTTP_PART_ITERATE_CALLBACK_ARGS
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;

	return callback_data->final_callback (
			callback_data->data,
			callback_data->response_code,
			callback_data->response_argument,
			chunk_idx,
			chunk_total,
			data_start,
			data_size,
			callback_data->final_callback_arg
	);
}

static int __rrr_http_client_receive_http_part_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;

	(void)(handle);
	(void)(sockaddr);
	(void)(socklen);
	(void)(overshoot_bytes);
	(void)(request_part);
	(void)(unique_id);
	(void)(websocket_upgrade_in_progress);

	int ret = RRR_HTTP_OK;

	callback_data->response_code = response_part->response_code;

	// Moved-codes. Maybe this parsing is too persmissive.
	if (response_part->response_code >= 300 && response_part->response_code <= 399) {
		const struct rrr_http_header_field *location = rrr_http_part_header_field_get(response_part, "location");
		if (location == NULL || !rrr_nullsafe_str_isset(location->value)) {
			RRR_MSG_0("Could not find Location-field in HTTP response %i %s\n",
					response_part->response_code, response_part->response_str);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		{
			RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, location->value);
			RRR_DBG_2("HTTP Redirect to '%s'\n", value);
		}

		if (rrr_nullsafe_str_isset(callback_data->response_argument)) {
			RRR_BUG("Response argument was not NULL in __rrr_http_client_receive_callback, possible double call with non-200 response\n");
		}
		if (rrr_nullsafe_str_dup(&callback_data->response_argument, location->value) != 0) {
			RRR_MSG_0("Could not allocate memory for location string in __rrr_http_client_receive_callback\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}

		goto out;
	}
	else if (response_part->response_code == RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS) {
		if (callback_data->method != RRR_HTTP_METHOD_GET_WEBSOCKET) {
			RRR_MSG_0("Unexpected response 101 '%s' from server\n",
					response_part->response_str);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
	}
	else if (response_part->response_code < 200 || response_part->response_code > 299) {
		RRR_MSG_0("Error while fetching HTTP: %i %s\n",
				response_part->response_code, response_part->response_str);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_http_part_chunks_iterate (
			response_part,
			data_ptr,
			__rrr_http_client_receive_chunk_callback,
			callback_data
	) != 0)) {
		RRR_MSG_0("Error while iterating chunks in response in __rrr_http_client_receive_callback_intermediate\n");
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_client_update_target_if_not_null (
		struct rrr_http_client_request_data *data,
		const char *protocol,
		const char *server,
		const char *endpoint,
		unsigned int port
) {
	if (protocol != NULL) {
		if (*protocol == '\0' || rrr_posix_strcasecmp(protocol, "any") == 0) {
			data->transport_force = RRR_HTTP_TRANSPORT_ANY;
		}
		else if (rrr_posix_strcasecmp(protocol, "http") == 0) {
			data->transport_force = RRR_HTTP_TRANSPORT_HTTP;
		}
		else if (rrr_posix_strcasecmp(protocol, "https") == 0) {
			data->transport_force = RRR_HTTP_TRANSPORT_HTTPS;
		}
		else {
			RRR_MSG_0("Unknown transport protocol '%s' in __rrr_http_client_update_target_if_not_null, expected 'any', 'http' or 'https'\n", protocol);
			return 1;
		}
	}

	if (server != NULL) {
		RRR_FREE_IF_NOT_NULL(data->server);
		if ((data->server = strdup(server)) == NULL) {
			RRR_MSG_0("Could not allocate memory for hostname in __rrr_http_client_update_target_if_not_null\n");
			return RRR_HTTP_HARD_ERROR;
		}
	}

	if (endpoint != NULL) {
		RRR_FREE_IF_NOT_NULL(data->endpoint);
		if ((data->endpoint = strdup(endpoint)) == NULL) {
			RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_client_update_target_if_not_null\n");
			return RRR_HTTP_HARD_ERROR;
		}
	}

	if (port > 0) {
		data->http_port = port;
	}

	return 0;
}

static int __rrr_http_client_send_request_websocket_handshake_callback (
		RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;

	(void)(handle);
	(void)(request_part);
	(void)(response_part);
	(void)(data_ptr);
	(void)(sockaddr);
	(void)(socklen);
	(void)(overshoot_bytes);
	(void)(unique_id);
	(void)(callback_data);

	int ret = 0;

	RRR_DBG_3("HTTP WebSocket handshake response from server received\n");

	*do_websocket = 1;

	return ret;
}

static void __rrr_http_client_send_request_callback_final (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;
	struct rrr_http_client_request_data *data = callback_data->data;

	int ret = 0;

	char *query_to_free = NULL;
	char *endpoint_to_free = NULL;
	char *endpoint_and_query_to_free = NULL;

	// Allow caller to update references
	callback_data->transport_handle = handle->handle;

	if ((ret = rrr_http_session_transport_ctx_client_new_or_clean (
			handle,
			callback_data->method,
			data->user_agent
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in __rrr_http_client_send_request_callback\n");
		goto out;
	}

	if (callback_data->raw_request_data != NULL) {
		if (callback_data->raw_request_data_size == 0) {
			RRR_DBG_1("Raw request data was set in __rrr_http_client_send_request_callback_final but size was 0, nothing to send.\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		if ((ret = rrr_http_session_transport_ctx_raw_request_send (
				handle,
				callback_data->raw_request_data,
				callback_data->raw_request_data_size
		)) != 0) {
			RRR_MSG_0("Could not send raw request in __rrr_http_client_send_request_callback\n");
			goto out;
		}
	}
	else {
		const char *endpoint_to_use = NULL;

		if (callback_data->query_prepare_callback != NULL) {
			if	((ret = callback_data->query_prepare_callback (
					&endpoint_to_free,
					&query_to_free,
					handle->application_private_ptr,
					callback_data->query_prepare_callback_arg)
			) != RRR_HTTP_OK) {
				if (ret == RRR_HTTP_SOFT_ERROR) {
					RRR_MSG_3("Note: HTTP query aborted by soft error from query prepare callback in __rrr_http_client_send_request_callback_final\n");
					ret = 0;
					goto out;
				}
				RRR_MSG_0("Error %i from query prepare callback in __rrr_http_client_send_request_callback\n", ret);
				goto out;
			}
		}

		// Endpoint to use precedence:
		// 1. endpoint from query prepare callback
		// 2. endpoint from configuration
		// 3. default endpoint /

		if (endpoint_to_free == NULL || *(endpoint_to_free) == '\0') {
			if (data->endpoint != NULL) {
				endpoint_to_use = data->endpoint;
			}
			else {
				RRR_FREE_IF_NOT_NULL(endpoint_to_free);
				if ((endpoint_to_free = strdup("/")) == NULL) {
					RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_client_send_request_callback\n");
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
				RRR_MSG_0("Could not allocate string for endpoint and query in __rrr_http_client_send_request_callback return was %i\n", ret);
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}
		}
		else {
			if ((endpoint_and_query_to_free = strdup(endpoint_to_use)) == NULL) {
				RRR_MSG_0("Could not allocate string for endpoint in __rrr_http_client_send_request_callback\n");
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}
		}

		RRR_DBG_3("HTTP using endpoint: '%s'\n", endpoint_and_query_to_free);

		if ((ret = rrr_http_session_transport_ctx_set_endpoint (
				handle,
				endpoint_and_query_to_free
		)) != 0) {
			RRR_MSG_0("Could not set HTTP endpoint in __rrr_http_client_send_request_callback\n");
			goto out;
		}

		if ((ret = rrr_http_session_transport_ctx_request_send(handle, callback_data->request_header_host)) != 0) {
			RRR_MSG_0("Could not send request in __rrr_http_client_send_request_callback\n");
			goto out;
		}
	}

	uint64_t request_start_time = rrr_time_get_64();

	if ((ret = rrr_http_session_transport_ctx_receive (
			handle,
			RRR_HTTP_CLIENT_TIMEOUT_STALL_MS * 1000,
			RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS * 1000,
			data->read_max_size,
			0,
			__rrr_http_client_send_request_websocket_handshake_callback,
			callback_data,
			__rrr_http_client_receive_http_part_callback,
			callback_data,
			callback_data->raw_callback,
			callback_data->raw_callback_arg
	)) != 0) {
		goto out;
	}

	uint64_t request_end_time = rrr_time_get_64();
	RRR_DBG_3("HTTP total request time: %" PRIu64 "ms\n", (request_end_time - request_start_time) / 1000);

	if (callback_data->response_code >= 300 && callback_data->response_code <= 399) {
		if (!rrr_nullsafe_str_isset(callback_data->response_argument)) {
			RRR_BUG("BUG: Argument was NULL with 300<=code<=399\n");
		}

		struct rrr_http_uri *uri = NULL;

		if (rrr_http_util_uri_parse(&uri, callback_data->response_argument) != 0) {
			RRR_MSG_0("Could not parse Location from redirect response header\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(response_arg, callback_data->response_argument);
		RRR_DBG_3("HTTP redirect from server '%s', from '%s' to '%s' (%s, %s, %s, %u)\n",
				data->server,
				endpoint_and_query_to_free,
				response_arg,
				(uri->protocol != NULL ? uri->protocol : "-"),
				(uri->host != NULL ? uri->host : "-"),
				(uri->endpoint != NULL ? uri->endpoint : "-"),
				uri->port
		);

		if ((ret = __rrr_http_client_update_target_if_not_null (
				data,
				uri->protocol,
				uri->host,
				uri->endpoint,
				uri->port
		)) != RRR_HTTP_OK) {
			RRR_MSG_0("Could not update target after redirect\n");
			goto out;
		}

		rrr_http_util_uri_destroy(uri);

		data->do_retry = 1;
		goto out;
	}

	data->do_retry = 0;

	goto out;
	out:
		RRR_FREE_IF_NOT_NULL(endpoint_to_free);
		RRR_FREE_IF_NOT_NULL(endpoint_and_query_to_free);
		RRR_FREE_IF_NOT_NULL(query_to_free);

		// There is not return, set return value in callback data struct for
		// caller to assess
		callback_data->http_receive_ret = ret;
}

static void __rrr_http_client_send_request_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	(void)(sockaddr);
	(void)(socklen);

	__rrr_http_client_send_request_callback_final(handle, arg);
}

static int __rrr_http_client_send_keepalive_request_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	__rrr_http_client_send_request_callback_final(handle, arg);
	return 0;
}

static void __rrr_http_client_receive_callback_data_cleanup (
		struct rrr_http_client_request_callback_data *callback_data
) {
	rrr_nullsafe_str_destroy_if_not_null(callback_data->response_argument);
	memset(callback_data, '\0', sizeof(*callback_data));
}

void __rrr_http_client_send_request_connect_callback (
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

// Note that data in the struct may change if there are any redirects
// Note that query prepare callback is not called if raw request data is set
static int __rrr_http_client_send_request (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		const char *raw_request_data,
		size_t raw_request_data_size,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_args,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	char *server_to_free = NULL;

	struct rrr_http_client_request_callback_data callback_data = {0};

	struct rrr_net_transport *transport = NULL;
	if (transport_keepalive != NULL) {
		transport = *transport_keepalive;
	}

	int transport_handle = 0;
	if (transport_keepalive_handle != NULL) {
		transport_handle = *transport_keepalive_handle;
	}

	callback_data.data = data;
	callback_data.method = method;
	callback_data.raw_request_data = raw_request_data;
	callback_data.raw_request_data_size = raw_request_data_size;
	callback_data.raw_callback = raw_callback;
	callback_data.raw_callback_arg = raw_callback_args;
	callback_data.final_callback = final_callback;
	callback_data.final_callback_arg = final_callback_arg;
	callback_data.query_prepare_callback = query_prepare_callback;
	callback_data.query_prepare_callback_arg = query_prepare_callback_arg;

	enum rrr_http_transport transport_code = RRR_HTTP_TRANSPORT_ANY;

	if (data->transport_force != 0 && data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
		RRR_DBG_3("Forcing SSL/TLS\n");
		if (transport_code != RRR_HTTP_TRANSPORT_HTTPS && transport_code != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_0("Requested URI contained non-https transport while force SSL was active, cannot continue\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}
	if (data->transport_force != 0 && data->transport_force == RRR_HTTP_TRANSPORT_HTTP) {
		RRR_DBG_3("Forcing plaintext non-SSL/TLS\n");
		if (transport_code != RRR_HTTP_TRANSPORT_HTTPS && transport_code != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_0("Requested URI contained non-http transport while force plaintext was active, cannot continue\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		transport_code = RRR_HTTP_TRANSPORT_HTTP;
	}

	uint16_t port_to_use = data->http_port;
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
				ret = 0;
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
		RRR_BUG("BUG: No server set in __rrr_http_client_send_request\n");
	}

	if (port_to_use == 0) {
		RRR_BUG("BUG: Port was 0 in __rrr_http_client_send_request\n");
	}

	callback_data.request_header_host = server_to_use;

	RRR_DBG_3("Using server %s port %u transport %s method '%s'\n",
			server_to_use,
			port_to_use,
			RRR_HTTP_TRANSPORT_TO_STR(transport_code),
			RRR_HTTP_METHOD_TO_STR(method)
	);

	if (transport == NULL) {
		if (transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
			struct rrr_net_transport_config net_transport_config_tmp = *net_transport_config;

			net_transport_config_tmp.transport_type = RRR_NET_TRANSPORT_TLS;

			int tls_flags = 0;
			if (data->ssl_no_cert_verify != 0) {
				tls_flags |= RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY;
			}

			ret = rrr_net_transport_new (
					&transport,
					&net_transport_config_tmp,
					tls_flags
			);
		}
		else if (data->transport_force != 0 && data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
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
					&transport,
					&net_transport_config_tmp,
					0
			);
		}
	}

	if (ret != 0) {
		RRR_MSG_0("Could not create transport in __rrr_http_client_send_request\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	// The callback is a void and return values from it do not propagate
	// through the net transport framework.

	if (transport_keepalive != NULL) {
		if (transport_handle == 0) {
			if ((ret = rrr_net_transport_connect (
					transport,
					port_to_use,
					server_to_use,
					__rrr_http_client_send_request_connect_callback,
					&transport_handle
			))) {
				RRR_MSG_0("Keepalive connection failed to server %s port %u transport %s in http client return was %i\n",
						server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code), ret);
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}
		}

		callback_data.transport_handle = transport_handle;
		if ((ret = rrr_net_transport_handle_with_transport_ctx_do (
				transport,
				transport_handle,
				__rrr_http_client_send_keepalive_request_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = rrr_net_transport_connect_and_close_after_callback (
				transport,
				port_to_use,
				server_to_use,
				__rrr_http_client_send_request_callback,
				&callback_data
		)) != 0) {
			RRR_MSG_0("Connection failed to server %s port %u transport %s in http client return was %i\n",
					server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code), ret);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
	}

	if ((ret = callback_data.http_receive_ret) != RRR_HTTP_OK) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(server_to_free);
	__rrr_http_client_receive_callback_data_cleanup(&callback_data);
	if (transport_keepalive != NULL) {
		*transport_keepalive = transport;
	}
	if (transport_keepalive_handle != NULL) {
		*transport_keepalive_handle = transport_handle;
	}
	else if (transport != NULL) {
		rrr_net_transport_destroy(transport);
		if (transport_keepalive != NULL) {
			*transport_keepalive = NULL;
		}
	}
	return ret;
}

int rrr_http_client_send_request (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_args,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	return __rrr_http_client_send_request (
			data,
			method,
			transport_keepalive,
			transport_keepalive_handle,
			net_transport_config,
			NULL,
			0,
			connection_prepare_callback,
			connection_prepare_callback_arg,
			raw_callback,
			raw_callback_args,
			query_prepare_callback,
			query_prepare_callback_arg,
			final_callback,
			final_callback_arg
	);
}

int rrr_http_client_send_raw_request (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		const char *raw_request_data,
		size_t raw_request_data_size,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_args,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	return __rrr_http_client_send_request (
			data,
			method,
			transport_keepalive,
			transport_keepalive_handle,
			net_transport_config,
			raw_request_data,
			raw_request_data_size,
			connection_prepare_callback,
			connection_prepare_callback_arg,
			raw_callback,
			raw_callback_args,
			NULL,
			NULL,
			final_callback,
			final_callback_arg
	);
}

int rrr_http_client_send_request_simple (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		const struct rrr_net_transport_config *net_transport_config,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	return __rrr_http_client_send_request (
			data,
			method,
			NULL,
			NULL,
			net_transport_config,
			NULL,
			0,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			final_callback,
			final_callback_arg
	);
}

int rrr_http_client_start_websocket_simple (
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	return __rrr_http_client_send_request (
			data,
			RRR_HTTP_METHOD_GET_WEBSOCKET,
			transport_keepalive,
			transport_keepalive_handle,
			net_transport_config,
			NULL,
			0,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			final_callback,
			final_callback_arg
	);
}

struct rrr_http_client_websocket_tick_callback_data {
	uint64_t bytes_total;
	int timeout_s;
	struct rrr_http_client_request_data *request_data;
	int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS);
	void *get_response_callback_arg;
	int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *frame_callback_arg;
};

static int __rrr_http_client_transport_ctx_websocket_tick (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_client_websocket_tick_callback_data *callback_data = arg;

	int ret = 0;

	rrr_net_transport_ctx_get_socket_stats(NULL, NULL, &callback_data->bytes_total, handle);

	if ((ret = rrr_http_session_transport_ctx_websocket_tick (
			handle,
			1 * 1024 * 1024 * 1024, // 1 GB
			0,
			0,
			callback_data->timeout_s,
			callback_data->get_response_callback,
			callback_data->get_response_callback_arg,
			callback_data->frame_callback,
			callback_data->frame_callback_arg
	)) != 0) {
		if (ret != RRR_READ_EOF) {
			RRR_MSG_0("HTTP client: Error %i while processing websocket data\n", ret);
		}
		goto out;
	}

	out:
	return ret;
}

int rrr_http_client_websocket_tick (
		uint64_t *bytes_total,
		int timeout_s,
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport *transport_keepalive,
		int transport_keepalive_handle,
		int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg
) {
	if (transport_keepalive == NULL) {
		RRR_BUG("BUG: NULL transport keepalive to rrr_http_client_websocket_tick\n");
	}

	struct rrr_http_client_websocket_tick_callback_data callback_data = {
			*bytes_total,
			timeout_s,
			data,
			get_response_callback,
			get_response_callback_arg,
			frame_callback,
			frame_callback_arg
	};

	int ret = rrr_net_transport_handle_with_transport_ctx_do (
			transport_keepalive,
			transport_keepalive_handle,
			__rrr_http_client_transport_ctx_websocket_tick,
			&callback_data
	);

	*bytes_total = callback_data.bytes_total;

	return ret;
}
