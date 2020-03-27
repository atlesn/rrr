/*
#include <http_part.h>

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "../global.h"
#include "gnu.h"
#include "base64.h"
#include "linked_list.h"
#include "http_fields.h"
#include "http_session.h"
#include "http_util.h"
#include "http_part.h"
#include "net_transport.h"
//#include "ip.h"
#include "random.h"
#include "read_session.h"

void rrr_http_session_destroy (struct rrr_http_session *session) {
	RRR_FREE_IF_NOT_NULL(session->host);
	RRR_FREE_IF_NOT_NULL(session->endpoint);
	RRR_FREE_IF_NOT_NULL(session->user_agent);
//	rrr_http_fields_collection_clear(&session->fields);
	if (session->request_part != NULL) {
		rrr_http_part_destroy(session->request_part);
	}
	if (session->response_part != NULL) {
		rrr_http_part_destroy(session->response_part);
	}
	if (session->transport != NULL) {
		rrr_net_transport_destroy(session->transport);
	}
	free(session);
}

int rrr_http_session_new (
		struct rrr_http_session **target,
		enum rrr_http_transport transport,
		enum rrr_http_method method,
		const char *host,
		uint16_t port,
		const char *endpoint,
		const char *user_agent
) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_session *session = malloc(sizeof(*session));
	if (session == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_session_new\n");
		ret = 1;
		goto out;
	}

	memset(session, '\0', sizeof(*session));

	uint16_t default_port = 0;
	switch (transport) {
		case RRR_HTTP_TRANSPORT_HTTP:
			ret = rrr_net_transport_new (&session->transport, RRR_NET_TRANSPORT_PLAIN);
			default_port = 80;
			break;
		case RRR_HTTP_TRANSPORT_HTTPS:
			ret = rrr_net_transport_new (&session->transport, RRR_NET_TRANSPORT_TLS);
			default_port = 443;
			break;
		default:
			RRR_BUG("Requested transport method %i not implemented in rrr_http_session_new\n", transport);
			break;
	};

	if (ret != 0) {
		RRR_MSG_ERR("Could not create transport method in rrr_http_session_new\n");
		ret = 1;
		goto out;
	}

	session->method = method;
	session->port = (port > 0 ? port : default_port);

	session->host = strdup(host);
	if (session->host == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_session_new A\n");
		ret = 1;
		goto out;
	}

	if (endpoint != NULL && *endpoint != '\0') {
		session->endpoint = strdup(endpoint);
	}
	else {
		session->endpoint = strdup("/");
	}

	if (session->endpoint == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_http_session_new B\n");
		ret = 1;
		goto out;
	}

	if (user_agent != NULL && *user_agent != '\0') {
		session->user_agent = strdup(user_agent);
		if (session->user_agent == NULL) {
			RRR_MSG_ERR("Could not allocate memory in rrr_http_session_new D\n");
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_http_part_new(&session->request_part)) != 0) {
		RRR_MSG_ERR("Could not create request part in rrr_http_session_new\n");
		goto out;
	}

	*target = session;
	session = NULL;

	out:
	if (session != NULL) {
		rrr_http_session_destroy(session);
	}
	return ret;
}

int rrr_http_session_add_query_field (
		struct rrr_http_session *session,
		const char *name,
		const char *value
) {
	return rrr_http_fields_collection_add_field(&session->request_part->fields, name, value);
}

int rrr_http_session_add_query_field_binary (
		struct rrr_http_session *session,
		const char *name,
		void *value,
		ssize_t size
) {
	return rrr_http_fields_collection_add_field_binary(&session->request_part->fields, name, value, size);
}

static int __rrr_http_session_send_multipart_form_data_body (struct rrr_http_session *session) {
	int ret = 0;
	char *boundary_buf = NULL;
	char *name_buf = NULL;
	char *name_buf_full = NULL;
	char *body_buf = NULL;

	// RFC7578

	if ((ret = rrr_asprintf (&boundary_buf, "rrr-boundary-%i", rrr_rand())) < 0) {
		RRR_MSG_ERR("Could not create boundary_buf string in __rrr_http_session_send_post_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf (
			&body_buf,
			"Content-Type: multipart/form-data; boundary=%s\r\n", // <-- ONE CRLF
			boundary_buf
	)) < 0) {
		RRR_MSG_ERR("Could not create content type string in __rrr_http_session_send_post_body\n");
		goto out;
	}

	if ((ret = rrr_net_transport_send (session->transport, session->transport_handle, body_buf, strlen(body_buf))) != 0) {
		RRR_MSG_ERR("Could not send first part of HTTP request in __rrr_http_session_send_post_body\n");
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&session->request_part->fields, struct rrr_http_field);
		RRR_FREE_IF_NOT_NULL(name_buf);
		RRR_FREE_IF_NOT_NULL(name_buf_full);

		name_buf = NULL;
		name_buf_full = NULL;

		if (node->name != NULL) {
			if ((name_buf = rrr_http_util_quote_header_value(node->name, '"', '"')) == NULL) {
				RRR_MSG_ERR("Could not quote field name_buf in __rrr_http_session_send_multipart_form_data_body\n");
				ret = 1;
				goto out;
			}

			if ((ret = rrr_asprintf (&name_buf_full, "; name=%s", name_buf)) != 0) {
				RRR_MSG_ERR("Could not create name_buf_full in __rrr_http_session_send_multipart_form_data_body\n");
				ret = 1;
				goto out;
			}
		}

		// TODO : Support binary stuff

		RRR_FREE_IF_NOT_NULL(body_buf);
		if ((ret = rrr_asprintf (
				&body_buf,
				"\r\n--%s\r\n"  // <-- ONE CRLF
				"Content-Disposition: form-data%s\r\n\r\n%s",
				boundary_buf,
				(name_buf_full != NULL ? name_buf_full : ""),
				node->value
		)) < 0) {
			RRR_MSG_ERR("Could not create content type string and body  in __rrr_http_session_send_multipart_form_data_body\n");
			ret = 1;
			goto out;
		}

		if ((ret = rrr_net_transport_send (session->transport, session->transport_handle, body_buf, strlen(body_buf))) != 0) {
			RRR_MSG_ERR("Could not send form part of HTTP request in __rrr_http_session_send_multipart_form_data_body\n");
			goto out;
		}
	RRR_LL_ITERATE_END();

	RRR_FREE_IF_NOT_NULL(body_buf);
	if ((ret = rrr_asprintf (
			&body_buf,
			"\r\n--%s--",  // <-- ONE CRLF AFTER BODY
			boundary_buf
	)) < 0) {
		RRR_MSG_ERR("Could not create last boundary in __rrr_http_session_send_multipart_form_data_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_send (session->transport, session->transport_handle, body_buf, strlen(body_buf))) != 0) {
		RRR_MSG_ERR("Could not send last part of HTTP request in __rrr_http_session_send_multipart_form_data_body\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(name_buf);
	RRR_FREE_IF_NOT_NULL(name_buf_full);
	RRR_FREE_IF_NOT_NULL(boundary_buf);
	RRR_FREE_IF_NOT_NULL(body_buf);

	return ret;
}

static int __rrr_http_session_send_post_x_www_form_body (struct rrr_http_session *session, int no_urlencoding) {
	int ret = 0;
	char *body_buf = NULL;
	char *final_buf = NULL;

	if (no_urlencoding == 0) {
		body_buf = rrr_http_fields_to_urlencoded_form_data(&session->request_part->fields);
	}
	else {
		body_buf = rrr_http_fields_to_raw_form_data(&session->request_part->fields);
	}

	if (body_buf == NULL) {
		RRR_MSG_ERR("Could not create body in __rrr_http_session_send_post_urlencoded_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf (
			&final_buf,
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: %u\r\n\r\n%s",
			strlen(body_buf),
			body_buf
	)) < 0) {
		RRR_MSG_ERR("Could not create content type string in __rrr_http_session_send_get_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_send (session->transport, session->transport_handle, final_buf, strlen(final_buf))) != 0) {
		RRR_MSG_ERR("Could not send GET body in __rrr_http_session_send_get_body\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(final_buf);
	RRR_FREE_IF_NOT_NULL(body_buf);
	return ret;
}

int rrr_http_session_send_request (
		struct rrr_http_session *session
) {
	int ret = 0;

	char *request_buf = NULL;
	char *host_buf = NULL;
	char *user_agent_buf = NULL;

	host_buf = rrr_http_util_quote_header_value(session->host, '"', '"');
	if (host_buf == NULL) {
		RRR_MSG_ERR("Invalid host '%s' in rrr_http_session_send_request\n", session->host);
		ret = 1;
		goto out;
	}

	user_agent_buf = rrr_http_util_quote_header_value(session->user_agent, '"', '"');
	if (user_agent_buf == NULL) {
		RRR_MSG_ERR("Invalid user agent '%s' in rrr_http_session_send_request\n", session->user_agent);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf (
			&request_buf,
			"%s %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept-Charset: UTF-8\r\n",
			(session->method == RRR_HTTP_METHOD_GET ? "GET" : "POST"),
			session->endpoint,
			host_buf,
			user_agent_buf
	)) < 0) {
		RRR_MSG_ERR("Error while making request string in rrr_http_session_send_request\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_send (session->transport, session->transport_handle, request_buf, strlen(request_buf))) != 0) {
		RRR_MSG_ERR("Could not send first part of HTTP request in rrr_http_session_send_request\n");
		goto out;
	}

	if (RRR_LL_COUNT(&session->request_part->fields) > 0) {
		if (session->method == RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA) {
			if ((ret = __rrr_http_session_send_multipart_form_data_body (session)) != 0) {
				RRR_MSG_ERR("Could not send POST multipart body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else if (session->method == RRR_HTTP_METHOD_POST_URLENCODED) {
			if ((ret = __rrr_http_session_send_post_x_www_form_body (session, 0)) != 0) {
				RRR_MSG_ERR("Could not send POST urlencoded body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else if (session->method == RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING) {
			if ((ret = __rrr_http_session_send_post_x_www_form_body (session, 1)) != 0) {
				RRR_MSG_ERR("Could not send POST urlencoded body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else {
			RRR_MSG_ERR("Unknown request method for request with fields set (GET request cannot have body)\n");
			ret = 1;
			goto out;
		}
	}
	else if ((ret = rrr_net_transport_send (session->transport, session->transport_handle, "\r\n", strlen("\r\n"))) != 0) {
		RRR_MSG_ERR("Could not send last \\r\\n in rrr_http_session_send_request\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(user_agent_buf);
	RRR_FREE_IF_NOT_NULL(host_buf);
	RRR_FREE_IF_NOT_NULL(request_buf);
	return ret;
}

struct rrr_http_session_receive_data {
	struct rrr_http_session *session;
	ssize_t header_complete_pos;
	ssize_t parse_complete_pos;
	int (*callback)(struct rrr_http_session *session, const char *start, const char *end, void *arg);
	void *callback_arg;
};

static int __rrr_http_session_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;
	struct rrr_http_part *part = receive_data->session->response_part;

	int ret = 0;

	const char *start = read_session->rx_buf_ptr + receive_data->header_complete_pos;
	const char *end = read_session->rx_buf_ptr + read_session->rx_buf_wpos;

	receive_data->session->response_part->data_ptr = start;
	receive_data->session->response_part->data_length = end - start;

	if (RRR_LL_COUNT(&part->chunks) == 0) {
		ret = receive_data->callback(receive_data->session, start, end, receive_data->callback_arg);
		goto out;
	}
	else {
		const char *buf = read_session->rx_buf_ptr;
		RRR_LL_ITERATE_BEGIN(&part->chunks, struct rrr_http_chunk);
			if (node->length == 0) {
				RRR_LL_ITERATE_NEXT();
			}
			const char *data_start = buf + node->start;
			const char *data_end = data_start + node->length;
			if (data_end > end) {
				RRR_BUG("Chunk end overrun in __rrr_http_session_receive_callback\n");
			}

			ret = receive_data->callback(receive_data->session, data_start, data_end, receive_data->callback_arg);
			if (ret != 0) {
				goto out;
			}
		RRR_LL_ITERATE_END();
	}

	out:
	return ret;
}

static int __rrr_http_session_receive_get_target_size (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;

	int ret = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH;

	const char *end = read_session->rx_buf_ptr + read_session->rx_buf_wpos;

	ssize_t parsed_bytes = 0;

	ret = rrr_http_part_parse (
			receive_data->session->response_part,
			&parsed_bytes,
			read_session->rx_buf_ptr,
			receive_data->parse_complete_pos,
			end
	);

	receive_data->parse_complete_pos += parsed_bytes;

//		printf ("Header complete at %i\n", receive_data->parse_complete_pos);

	if (	receive_data->session->response_part->header_complete != 0 &&
			receive_data->header_complete_pos == 0
	) {
		receive_data->header_complete_pos = receive_data->parse_complete_pos;
	}

	if (ret == RRR_HTTP_PARSE_OK) {
		read_session->target_size = receive_data->header_complete_pos + receive_data->session->response_part->data_length;
	}
	else if (ret == RRR_HTTP_PARSE_INCOMPLETE) {
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
	}
	else if (ret == RRR_HTTP_PARSE_UNTIL_CLOSE) {
		read_session->target_size = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE;
		ret = RRR_NET_TRANSPORT_READ_OK;
	}
	else {
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
	}

	return ret;
}

int rrr_http_session_receive (
		struct rrr_http_session *session,
		int (*callback)(struct rrr_http_session *session, const char *start, const char *end, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if (session->response_part != NULL) {
		rrr_http_part_destroy(session->response_part);
	}

	if ((ret = rrr_http_part_new(&session->response_part)) != 0) {
		RRR_MSG_ERR("Could not create HTTP part in rrr_http_session_receive\n");
		goto out;
	}

	struct rrr_http_session_receive_data callback_data = {
			session,
			0,
			0,
			callback,
			callback_arg
	};

	ret = rrr_net_transport_read_message (
			session->transport,
			session->transport_handle,
			4096,
			65535,
			__rrr_http_session_receive_get_target_size,
			&callback_data,
			__rrr_http_session_receive_callback,
			&callback_data
	);

	if (ret != 0) {
		RRR_MSG_ERR("Error while reading from server in rrr_http_session_receive\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_http_session_connect (struct rrr_http_session *session) {
	int ret = 0;

	if (rrr_net_transport_connect(&session->transport_handle, session->transport, session->port, session->host) != 0) {
		RRR_MSG_ERR("Could not connect to HTTP server '%s' port '%u'\n", session->host, session->port);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

void rrr_http_session_close (struct rrr_http_session *session) {
	if (session->transport_handle > 0) {
		if (rrr_net_transport_close(session->transport, session->transport_handle) != 0) {
			RRR_MSG_ERR("Warning: Error while closing transport handle in rrr_http_session_close\n");
		}
		session->transport_handle = 0;
	}
}
