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
#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "ip.h"

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
	rrr_socket_read_session_collection_clear(&session->read_sessions);
	if (session->fd != 0) {
		rrr_socket_close(session->fd);
		session->fd = 0;
	}
	free(session);
}

int rrr_http_session_new (
		struct rrr_http_session **target,
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
		VL_MSG_ERR("Could not allocate memory in rrr_http_session_new\n");
		ret = 1;
		goto out;
	}

	memset(session, '\0', sizeof(*session));

	session->method = method;
	session->port = port;

	session->host = strdup(host);
	if (session->host == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_http_session_new A\n");
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
		VL_MSG_ERR("Could not allocate memory in rrr_http_session_new B\n");
		ret = 1;
		goto out;
	}

	if (user_agent != NULL && *user_agent != '\0') {
		session->user_agent = strdup(user_agent);
		if (session->user_agent == NULL) {
			VL_MSG_ERR("Could not allocate memory in rrr_http_session_new D\n");
			ret = 1;
			goto out;
		}
	}

	rrr_socket_read_session_collection_init(&session->read_sessions);

	if ((ret = rrr_http_part_new(&session->request_part)) != 0) {
		VL_MSG_ERR("Could not create request part in rrr_http_session_new\n");
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

	if ((ret = rrr_asprintf (&boundary_buf, "rrr-boundary-%i", rand())) < 0) {
		VL_MSG_ERR("Could not create boundary_buf string in __rrr_http_session_send_post_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf (
			&body_buf,
			"Content-Type: multipart/form-data; boundary=%s\r\n", // <-- ONE CRLF
			boundary_buf
	)) < 0) {
		VL_MSG_ERR("Could not create content type string in __rrr_http_session_send_post_body\n");
		goto out;
	}

	if ((ret = rrr_socket_sendto(session->fd, body_buf, strlen(body_buf), NULL, 0)) != 0) {
		VL_MSG_ERR("Could not send first part of HTTP request in __rrr_http_session_send_post_body\n");
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&session->request_part->fields, struct rrr_http_field);
		RRR_FREE_IF_NOT_NULL(name_buf);
		RRR_FREE_IF_NOT_NULL(name_buf_full);

		name_buf = NULL;
		name_buf_full = NULL;

		if (node->name != NULL) {
			if ((name_buf = rrr_http_util_quote_header_value(node->name, '"', '"')) == NULL) {
				VL_MSG_ERR("Could not quote field name_buf in __rrr_http_session_send_multipart_form_data_body\n");
				ret = 1;
				goto out;
			}

			if ((ret = rrr_asprintf (&name_buf_full, "; name=%s", name_buf)) != 0) {
				VL_MSG_ERR("Could not create name_buf_full in __rrr_http_session_send_multipart_form_data_body\n");
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
			VL_MSG_ERR("Could not create content type string and body  in __rrr_http_session_send_multipart_form_data_body\n");
			ret = 1;
			goto out;
		}

		if ((ret = rrr_socket_sendto(session->fd, body_buf, strlen(body_buf), NULL, 0)) != 0) {
			VL_MSG_ERR("Could not send form part of HTTP request in __rrr_http_session_send_multipart_form_data_body\n");
			goto out;
		}
	RRR_LL_ITERATE_END();

	RRR_FREE_IF_NOT_NULL(body_buf);
	if ((ret = rrr_asprintf (
			&body_buf,
			"\r\n--%s--",  // <-- ONE CRLF AFTER BODY
			boundary_buf
	)) < 0) {
		VL_MSG_ERR("Could not create last boundary in __rrr_http_session_send_multipart_form_data_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_socket_sendto(session->fd, body_buf, strlen(body_buf), NULL, 0)) != 0) {
		VL_MSG_ERR("Could not send last part of HTTP request in __rrr_http_session_send_multipart_form_data_body\n");
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
		VL_MSG_ERR("Could not create body in __rrr_http_session_send_post_urlencoded_body\n");
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
		VL_MSG_ERR("Could not create content type string in __rrr_http_session_send_get_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_socket_sendto(session->fd, final_buf, strlen(final_buf), NULL, 0)) != 0) {
		VL_MSG_ERR("Could not send GET body in __rrr_http_session_send_get_body\n");
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
		VL_MSG_ERR("Invalid host '%s' in rrr_http_session_send_request\n", session->host);
		ret = 1;
		goto out;
	}

	user_agent_buf = rrr_http_util_quote_header_value(session->user_agent, '"', '"');
	if (user_agent_buf == NULL) {
		VL_MSG_ERR("Invalid user agent '%s' in rrr_http_session_send_request\n", session->user_agent);
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
		VL_MSG_ERR("Error while making request string in rrr_http_session_send_request\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_socket_sendto(session->fd, request_buf, strlen(request_buf), NULL, 0)) != 0) {
		VL_MSG_ERR("Could not send first part of HTTP request in rrr_http_session_send_request\n");
		goto out;
	}

	if (RRR_LL_COUNT(&session->request_part->fields) > 0) {
		if (session->method == RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA) {
			if ((ret = __rrr_http_session_send_multipart_form_data_body (session)) != 0) {
				VL_MSG_ERR("Could not send POST multipart body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else if (session->method == RRR_HTTP_METHOD_POST_URLENCODED) {
			if ((ret = __rrr_http_session_send_post_x_www_form_body (session, 0)) != 0) {
				VL_MSG_ERR("Could not send POST urlencoded body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else if (session->method == RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING) {
			if ((ret = __rrr_http_session_send_post_x_www_form_body (session, 1)) != 0) {
				VL_MSG_ERR("Could not send POST urlencoded body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else {
			VL_MSG_ERR("Unknown request method for request with fields set (GET request cannot have body)\n");
			ret = 1;
			goto out;
		}
	}
	else if ((ret = rrr_socket_sendto(session->fd, "\r\n", strlen("\r\n"), NULL, 0)) != 0) {
		VL_MSG_ERR("Could not send last \r\n rrr_http_session_send_request\n");
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
	ssize_t parse_complete_pos;
	int (*callback)(struct rrr_http_session *session, void *arg);
	void *callback_arg;
};

static int __rrr_http_session_receive_callback (
		struct rrr_socket_read_session *read_session, void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;

	const char *data_start = read_session->rx_buf_ptr + receive_data->parse_complete_pos;
	const char *data_end = read_session->rx_buf_ptr + read_session->rx_buf_wpos;

	if (data_end > data_start) {
		receive_data->session->response_part->data_ptr = data_start;
		receive_data->session->response_part->data_length = data_end - data_start;
	}

	return receive_data->callback(receive_data->session, receive_data->callback_arg);
}

static int __rrr_http_session_receive_get_total_size (
		struct rrr_socket_read_session *read_session, void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;

	int ret = 0;

	const char *start = read_session->rx_buf_ptr + receive_data->parse_complete_pos;

	ssize_t parsed_bytes = 0;
	ret = rrr_http_part_parse (
			receive_data->session->response_part,
			&parsed_bytes,
			start,
			read_session->rx_buf_ptr + read_session->rx_buf_wpos
	);

	receive_data->parse_complete_pos += parsed_bytes;

	if (ret == RRR_HTTP_PARSE_OK) {
		read_session->target_size = receive_data->parse_complete_pos + receive_data->session->response_part->data_length;
	}
	else if (ret == RRR_HTTP_PARSE_INCOMPLETE) {
		ret = RRR_SOCKET_READ_INCOMPLETE;
	}
	else if (ret == RRR_HTTP_PARSE_UNTIL_CLOSE) {
		read_session->read_complete_method = RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE;
		ret = RRR_SOCKET_OK;
	}
	else {
		ret = RRR_SOCKET_SOFT_ERROR;
	}

	return ret;
}

int rrr_http_session_receive (
		struct rrr_http_session *session,
		int (*callback)(struct rrr_http_session *session, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if (session->response_part != NULL) {
		rrr_http_part_destroy(session->response_part);
	}

	if ((ret = rrr_http_part_new(&session->response_part)) != 0) {
		VL_MSG_ERR("Could not create HTTP part in rrr_http_session_receive\n");
		goto out;
	}

	struct rrr_http_session_receive_data callback_data = {
			session,
			0,
			callback,
			callback_arg
	};

	for (int i = 1000; i >= 0; i--) {
		ret = rrr_socket_read_message (
				&session->read_sessions,
				session->fd,
				4096,
				65535,
				RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_USE_TIMEOUT,
				__rrr_http_session_receive_get_total_size,
				&callback_data,
				__rrr_http_session_receive_callback,
				&callback_data
		);

		if (ret == RRR_SOCKET_OK) {
			// TODO : Check for persistent connection/more results which might be
			//		  stored in read session overshoot buffer
			goto out;
		}
		else if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			VL_MSG_ERR("Error while reading from server in rrr_http_session_receive\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_http_session_connect (struct rrr_http_session *session) {
	int ret = 0;

	struct ip_accept_data *accept_data = NULL;

	if (ip_network_connect_tcp_ipv4_or_ipv6(&accept_data, session->port, session->host) != 0) {
		VL_MSG_ERR("Could not connect to HTTP server '%s'\n", session->host);
		ret = 1;
		goto out;
	}

	session->fd = accept_data->ip_data.fd;

	out:
	RRR_FREE_IF_NOT_NULL(accept_data);
	return ret;
}

void rrr_http_session_close (struct rrr_http_session *session) {
	if (session->fd > 0) {
		rrr_socket_close(session->fd);
		session->fd = 0;
	}
}
