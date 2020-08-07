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

#include "../posix.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
#include "../gnu.h"
#include "../macro_utils.h"

int rrr_http_client_data_init (
		struct rrr_http_client_data *data,
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
		struct rrr_http_client_data *data,
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

void rrr_http_client_data_cleanup (
		struct rrr_http_client_data *data
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

	(void)(sockaddr);
	(void)(socklen);
	(void)(overshoot_bytes);
	(void)(request_part);

	int ret = RRR_HTTP_OK;

	callback_data->response_code = response_part->response_code;

	// Moved-codes. Maybe this parsing is too persmissive.
	if (response_part->response_code >= 300 && response_part->response_code <= 399) {
		const struct rrr_http_header_field *location = rrr_http_part_get_header_field(response_part, "location");
		if (location == NULL) {
			RRR_MSG_0("Could not find Location-field in HTTP response %i %s\n",
					response_part->response_code, response_part->response_str);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		RRR_DBG_2("HTTP Redirect to %s\n", location->value);

		if (callback_data->response_argument != NULL) {
			RRR_BUG("Response argument was not NULL in __rrr_http_client_receive_callback, possible double call with non-200 response\n");
		}
		if ((callback_data->response_argument = strdup(location->value)) == NULL) {
			RRR_MSG_0("Could not allocate memory for location string in __rrr_http_client_receive_callback\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}

		goto out;
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
		struct rrr_http_client_data *data,
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

static void __rrr_http_client_send_request_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;
	struct rrr_http_client_data *data = callback_data->data;

	(void)(sockaddr);
	(void)(socklen);

	int ret = 0;

	char *query_to_free = NULL;
	char *endpoint_to_free = NULL;
	char *endpoint_and_query_to_free = NULL;

	const char *endpoint = data->endpoint;

	if (endpoint == NULL || *(endpoint) == '\0') {
		if ((endpoint_to_free = strdup("/")) == NULL) {
			RRR_MSG_0("Could not allocate memory for endpoint in __rrr_http_client_send_request_callback\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
		endpoint = endpoint_to_free;
	}

	if ((ret = rrr_http_session_transport_ctx_client_new (
			handle,
			callback_data->method,
			data->user_agent
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in __rrr_http_client_send_request_callback\n");
		goto out;
	}

	if (callback_data->before_send_callback != NULL) {
		if	((ret = callback_data->before_send_callback (
				&query_to_free,
				handle->application_private_ptr,
				callback_data->before_send_callback_arg)
		) != RRR_HTTP_OK) {
			ret &= ~(RRR_HTTP_NO_RESULT);
			if (ret != 0) {
				RRR_MSG_0("Error %i while making query string in __rrr_http_client_send_request_callback\n", ret);
				goto out;
			}
		}
	}

	if (query_to_free != NULL && *(query_to_free) != '\0') {
		if (strchr(endpoint, '?') != 0) {
			RRR_MSG_0("HTTP endpoint '%s' already contained a query string, cannot append query '%s' from callback. Request aborted.\n",
					endpoint, query_to_free);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		if ((ret = rrr_asprintf(&endpoint_and_query_to_free, "%s?%s", endpoint, query_to_free)) <= 0) {
			RRR_MSG_0("Could not allocate string for endpoint and query in __rrr_http_client_send_request_callback return was %i\n", ret);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}
	else {
		if ((endpoint_and_query_to_free = strdup(endpoint)) == NULL) {
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

	if ((ret = rrr_http_session_transport_ctx_request_send(handle, data->server)) != 0) {
		RRR_MSG_0("Could not send request in __rrr_http_client_send_request_callback\n");
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_receive (
			handle,
			RRR_HTTP_CLIENT_TIMEOUT_STALL_MS * 1000,
			RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS * 1000,
			data->read_max_size,
			__rrr_http_client_receive_http_part_callback,
			callback_data
	)) != 0) {
		goto out;
	}

	if (callback_data->response_code >= 300 && callback_data->response_code <= 399) {
		if (callback_data->response_argument == NULL) {
			RRR_BUG("BUG: Argument was NULL with 300<=code<=399\n");
		}

		struct rrr_http_uri *uri = NULL;

		if (rrr_http_util_uri_parse(&uri, callback_data->response_argument) != 0) {
			RRR_MSG_0("Could not parse Location from redirect response header\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		RRR_DBG_3("HTTP redirect from server '%s', from '%s' to '%s' (%s, %s, %s, %u)\n",
				data->server,
				endpoint_and_query_to_free,
				callback_data->response_argument,
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

static void __rrr_http_client_receive_callback_data_cleanup (
		struct rrr_http_client_request_callback_data *callback_data
) {
	RRR_FREE_IF_NOT_NULL(callback_data->response_argument);
	memset(callback_data, '\0', sizeof(*callback_data));
}

// Note that data in the struct may change if there are any redirects
int rrr_http_client_send_request (
		struct rrr_http_client_data *data,
		enum rrr_http_method method,
		const struct rrr_net_transport_config *net_transport_config,
		int (*before_send_callback)(RRR_HTTP_CLIENT_BEFORE_SEND_CALLBACK_ARGS),
		void *before_send_callback_arg,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	struct rrr_net_transport *transport = NULL;
	struct rrr_http_client_request_callback_data callback_data = {0};

	callback_data.data = data;
	callback_data.method = method;
	callback_data.final_callback = final_callback;
	callback_data.final_callback_arg = final_callback_arg;
	callback_data.before_send_callback = before_send_callback;
	callback_data.before_send_callback_arg = before_send_callback_arg;

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

	RRR_DBG_3("Using server %s port %u transport %s\n",
			data->server, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code));

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

	if (ret != 0) {
		RRR_MSG_0("Could not create transport in __rrr_http_client_send_request\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	// The callback is a void and return values from it do not propagate
	// through the net transport framework.

	if ((ret = rrr_net_transport_connect_and_close_after_callback (
			transport,
			port_to_use,
			data->server,
			__rrr_http_client_send_request_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Connection failed to server %s port %u transport %s in http client return was %i\n",
				data->server, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code), ret);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = callback_data.http_receive_ret) != RRR_HTTP_OK) {
		goto out;
	}

//	rrr_http_session_add_query_field(data->session, "a", "1");
//	rrr_http_session_add_query_field(data->session, "b", "2/(&(&%\"¤&!        #Q¤#!¤&/");
//	rrr_http_session_add_query_field(data->session, "\\\\\\\\", "\\\\");

	out:
	__rrr_http_client_receive_callback_data_cleanup(&callback_data);
	if (transport != NULL) {
		rrr_net_transport_destroy(transport);
	}
	return ret;
}
