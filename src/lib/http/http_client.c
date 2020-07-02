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

#include "http_client.h"
#include "http_common.h"
#include "http_part.h"
#include "http_util.h"
#include "http_session.h"

#include "../posix.h"
#include "../log.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
#include "../gnu.h"
#include "../../global.h"

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

void rrr_http_client_data_cleanup (
		struct rrr_http_client_data *data
) {
	RRR_FREE_IF_NOT_NULL(data->protocol);
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->endpoint);
	RRR_FREE_IF_NOT_NULL(data->query);
	RRR_FREE_IF_NOT_NULL(data->user_agent);
}

static int __rrr_http_client_receive_chunk_callback (
		RRR_HTTP_PART_ITERATE_CALLBACK_ARGS
) {
	struct rrr_http_client_receive_callback_data *callback_data = arg;

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
		struct rrr_http_part *part,
		const char *data_ptr,
		void *arg
) {
	struct rrr_http_client_receive_callback_data *callback_data = arg;

	int ret = RRR_HTTP_OK;

	callback_data->response_code = part->response_code;

	// Moved-codes. Maybe this parsing is too persmissive.
	if (part->response_code >= 300 && part->response_code <= 399) {
		const struct rrr_http_header_field *location = rrr_http_part_get_header_field(part, "location");
		if (location == NULL) {
			RRR_MSG_0("Could not find Location-field in HTTP response %i %s\n",
					part->response_code, part->response_str);
			ret = RRR_HTTP_SOFT_ERROR;
		}
		RRR_DBG_1("HTTP Redirect to %s\n", location->value);

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
	else if (part->response_code < 200 || part->response_code > 299) {
		RRR_MSG_0("Error while fetching HTTP: %i %s\n",
				part->response_code, part->response_str);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_http_part_iterate_chunks (
			part,
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
		const char *hostname,
		const char *endpoint,
		unsigned int port
) {
	if (protocol != NULL) {
		RRR_FREE_IF_NOT_NULL(data->protocol);
		if ((data->protocol = strdup(protocol)) == NULL) {
			RRR_MSG_0("Could not allocate memory for protocol in __rrr_http_client_update_target_if_not_null\n");
			return RRR_HTTP_HARD_ERROR;
		}
	}

	if (hostname != NULL) {
		RRR_FREE_IF_NOT_NULL(data->server);
		if ((data->server = strdup(hostname)) == NULL) {
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
	struct rrr_http_client_receive_callback_data *callback_data = arg;
	struct rrr_http_client_data *data = callback_data->data;

	(void)(sockaddr);
	(void)(socklen);

	int ret = 0;

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

	if (data->query != NULL && *(data->query) != '\0') {
		if ((ret = rrr_asprintf(&endpoint_and_query_to_free, "%s?%s", endpoint, data->query)) <= 0) {
			RRR_MSG_0("Could not allocate string for endpoint and query in __rrr_http_client_send_request_callback\n");
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

	RRR_DBG_1("HTTP using endpoint and query: '%s'\n", endpoint_and_query_to_free);

	if ((ret = rrr_http_session_transport_ctx_client_new (
			handle,
//			RRR_HTTP_METHOD_POST_URLENCODED,
			RRR_HTTP_METHOD_GET,
			endpoint_and_query_to_free,
			data->user_agent
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in __rrr_http_client_send_request_callback\n");
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_send_request(handle, data->server)) != 0) {
		RRR_MSG_0("Could not send request in __rrr_http_client_send_request_callback\n");
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_receive(
			handle,
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

		RRR_DBG_1("Redirected to %s (%s, %s, %s, %u)\n",
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

		goto retry;
	}

	goto out;
	retry:
		data->do_retry = 1;
	out:
		RRR_FREE_IF_NOT_NULL(endpoint_to_free);
		RRR_FREE_IF_NOT_NULL(endpoint_and_query_to_free);
		callback_data->http_receive_ret = ret;
}

static void __rrr_http_client_receive_callback_data_cleanup (
		struct rrr_http_client_receive_callback_data *callback_data
) {
	RRR_FREE_IF_NOT_NULL(callback_data->response_argument);
	memset(callback_data, '\0', sizeof(*callback_data));
}
// Note that data in the struct may change if there are any redirects
int rrr_http_client_send_request (
		struct rrr_http_client_data *data,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	struct rrr_net_transport *transport = NULL;
	struct rrr_http_client_receive_callback_data callback_data = {0};

	callback_data.data = data;
	callback_data.final_callback = final_callback;
	callback_data.final_callback_arg = final_callback_arg;

	int transport_code = RRR_HTTP_TRANSPORT_ANY;

	if (data->protocol != NULL) {
		if (rrr_posix_strcasecmp(data->protocol, "http") == 0) {
			transport_code = RRR_HTTP_TRANSPORT_HTTP;
		}
		else if (rrr_posix_strcasecmp(data->protocol, "https") == 0) {
			transport_code = RRR_HTTP_TRANSPORT_HTTPS;
		}
		else {
			RRR_MSG_0("Unknown transport protocol '%s' in __rrr_http_client_send_request, expected 'http' or 'https'\n", data->protocol);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	if (data->ssl_force != 0) {
		RRR_DBG_1("Forcing SSL/TLS\n");
		if (transport_code != RRR_HTTP_TRANSPORT_HTTPS && transport_code != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_0("Requested URI contained non-https transport while force SSL was active, cannot continue\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}
	if (data->plain_force != 0) {
		RRR_DBG_1("Forcing plaintext non-SSL/TLS\n");
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

	RRR_DBG_1("Using server %s port %u transport %s\n",
			data->server, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code));

	int tls_flags = 0;
	if (data->ssl_no_cert_verify != 0) {
		tls_flags |= RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY;
	}

	struct rrr_net_transport_config net_transport_config = {
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			(transport_code == RRR_HTTP_TRANSPORT_HTTPS ? RRR_NET_TRANSPORT_TLS : RRR_NET_TRANSPORT_PLAIN)
	};

	if ((ret = rrr_net_transport_new (
			&transport,
			&net_transport_config,
			(transport_code == RRR_HTTP_TRANSPORT_HTTPS ? tls_flags : 0)
	)) != 0) {
		RRR_MSG_0("Could not create transport in __rrr_http_client_send_request\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	// The callback is a void and return values from it does not propagate
	// through the net transport framework.

	if ((ret = rrr_net_transport_connect_and_close_after_callback (
			transport,
			port_to_use,
			data->server,
			__rrr_http_client_send_request_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Connection failed to server %s port %u transport %s in http client\n",
				data->server, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code));
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = callback_data.http_receive_ret) != RRR_HTTP_OK) {
		RRR_MSG_0("HTTP error, return was %i\n", ret);
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
