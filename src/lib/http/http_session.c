/*
#include <read.h>
#include <http_part.h>

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
#include <unistd.h>

#include "http_fields.h"
#include "http_session.h"
#include "http_util.h"
#include "http_part.h"

#include "../posix.h"
#include "../log.h"
#include "../gnu.h"
#include "../base64.h"
#include "../linked_list.h"
#include "../net_transport/net_transport.h"
#include "../random.h"
#include "../read.h"
#include "../vl_time.h"

static void __rrr_http_session_destroy (struct rrr_http_session *session) {
	RRR_FREE_IF_NOT_NULL(session->uri_str);
	RRR_FREE_IF_NOT_NULL(session->user_agent);
//	rrr_http_fields_collection_clear(&session->fields);
	if (session->request_part != NULL) {
		rrr_http_part_destroy(session->request_part);
	}
	if (session->response_part != NULL) {
		rrr_http_part_destroy(session->response_part);
	}
	free(session);
}

static void __rrr_http_session_destroy_void (void *ptr) {
	__rrr_http_session_destroy(ptr);
}

static int __rrr_http_session_allocate (struct rrr_http_session **target) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_session *session = malloc(sizeof(*session));
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

int rrr_http_session_transport_ctx_server_new (
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
	session->is_client = 0;

	// Transport framework responsible for cleaning up
	rrr_net_transport_ctx_handle_application_data_bind (
			handle,
			session,
			__rrr_http_session_destroy_void
	);

	session = NULL;

	out:
	if (session != NULL) {
		__rrr_http_session_destroy(session);
	}
	return ret;
}

int rrr_http_session_transport_ctx_set_endpoint (
		struct rrr_net_transport_handle *handle,
		const char *endpoint
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	RRR_FREE_IF_NOT_NULL(session->uri_str);

	if (endpoint != NULL && *endpoint != '\0') {
		session->uri_str = strdup(endpoint);
	}
	else {
		session->uri_str = strdup("/");
	}

	if (session->uri_str == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_session_transport_ctx_set_endpoint\n");
		return 1;
	}

	return 0;
}

static int __rrr_http_session_prepare_parts (struct rrr_http_session *session) {
	int ret = 0;

	if (session->response_part != NULL) {
		rrr_http_part_destroy(session->response_part);
	}
	if ((ret = rrr_http_part_new(&session->response_part)) != 0) {
		RRR_MSG_0("Could not create HTTP part in __rrr_http_session_prepare_parts\n");
		goto out;
	}

	if (session->request_part != NULL) {
		rrr_http_part_destroy(session->request_part);
	}
	if ((ret = rrr_http_part_new(&session->request_part)) != 0) {
		RRR_MSG_0("Could not create HTTP part in __rrr_http_session_prepare_parts\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_http_session_transport_ctx_client_new (
		struct rrr_net_transport_handle *handle,
		enum rrr_http_method method,
		const char *user_agent
) {
	int ret = 0;

	struct rrr_http_session *session = NULL;

	if ((__rrr_http_session_allocate(&session)) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_http_session_transport_ctx_client_new\n");
		ret = 1;
		goto out;
	}

	session->method = method;
	session->is_client = 1;
	session->uri_str = strdup("/");

	if (session->uri_str == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_session_new B\n");
		ret = 1;
		goto out;
	}

	if (user_agent != NULL && *user_agent != '\0') {
		session->user_agent = strdup(user_agent);
		if (session->user_agent == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http_session_new D\n");
			ret = 1;
			goto out;
		}
	}

	if (__rrr_http_session_prepare_parts(session) != 0) {
		RRR_MSG_0("Could not prepare parts in rrr_http_session_transport_ctx_client_new\n");
		ret = 1;
		goto out;
	}

	// Transport framework responsible for cleaning up
	rrr_net_transport_ctx_handle_application_data_bind (
			handle,
			session,
			__rrr_http_session_destroy_void
	);

	session = NULL;

	out:
	if (session != NULL) {
		__rrr_http_session_destroy(session);
	}
	return ret;
}

int rrr_http_session_transport_ctx_add_query_field (
		struct rrr_net_transport_handle *handle,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	if (pthread_mutex_trylock(&handle->lock_) == 0) {
		RRR_BUG("BUG: Handle not locked in rrr_http_session_transport_ctx_add_query_field\n");
	}

	return rrr_http_field_collection_add (
			&session->request_part->fields,
			name,
			value,
			value_size,
			content_type
	);
}

int rrr_http_session_query_field_add (
		struct rrr_http_session *session,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
) {
	return rrr_http_field_collection_add (
			&session->request_part->fields,
			name,
			value,
			value_size,
			content_type
	);
}

void rrr_http_session_query_fields_dump (
		struct rrr_http_session *session
) {
	rrr_http_field_collection_dump(&session->request_part->fields);
}

static int __rrr_http_session_multipart_form_data_body_send_wrap_chunk (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
) {
	if (size < 0) {
		RRR_BUG("Size was < 0 in __rrr_http_session_multipart_form_data_body_send_wrap_chunk\n");
	}
	if (size == 0) {
		return RRR_HTTP_OK;
	}

	int ret = 0;

	char buf[128];
	sprintf(buf, "%x\r\n", (unsigned int) size);

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, buf, strlen(buf))) != RRR_NET_TRANSPORT_SEND_OK) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, data, size)) != RRR_NET_TRANSPORT_SEND_OK) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, "\r\n", 2)) != RRR_NET_TRANSPORT_SEND_OK) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_session_multipart_field_send (
		struct rrr_net_transport_handle *handle,
		const char *boundary,
		struct rrr_http_field *node,
		int is_first
) {
	int ret = 0;

	char *name_buf = NULL;
	char *name_buf_full = NULL;
	char *content_type_buf = NULL;
	char *body_buf = NULL;

	if (node->name != NULL) {
		if ((name_buf = rrr_http_util_quote_header_value(node->name, '"', '"')) == NULL) {
			RRR_MSG_0("Could not quote field name_buf in __rrr_http_session_multipart_field_send\n");
			ret = 1;
			goto out;
		}

		if ((ret = rrr_asprintf (&name_buf_full, "; name=%s", name_buf)) <= 0) {
			RRR_MSG_0("Could not create name_buf_full in __rrr_http_session_multipart_field_send\n");
			ret = 1;
			goto out;
		}
	}

	if (node->content_type != NULL && *(node->content_type) != '\0') {
		if ((ret = rrr_asprintf (&content_type_buf, "Content-Type: %s\r\n", node->content_type)) <= 0) {
			RRR_MSG_0("Could not create content_type_buf in __rrr_http_session_multipart_field_send\n");
			ret = 1;
			goto out;
		}
	}

	RRR_FREE_IF_NOT_NULL(body_buf);
	if ((ret = rrr_asprintf (
			&body_buf,
			"%s--%s\r\n"
			"Content-Disposition: form-data%s\r\n"
			"%s\r\n",
			(is_first ? "" : "\r\n"),
			boundary,
			(name_buf_full != NULL ? name_buf_full : ""),
			(content_type_buf != NULL ? content_type_buf : "")
	)) < 0) {
		RRR_MSG_0("Could not create content type string and body  in __rrr_http_session_multipart_field_send\n");
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_http_session_multipart_form_data_body_send_wrap_chunk(handle, body_buf, strlen(body_buf))) != 0) {
		RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_session_multipart_field_send A\n");
		goto out;
	}

	if (node->value != NULL) {
		if ((ret = __rrr_http_session_multipart_form_data_body_send_wrap_chunk(handle, node->value, node->value_size)) != 0) {
			RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_session_multipart_field_send B\n");
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(name_buf);
	RRR_FREE_IF_NOT_NULL(name_buf_full);
	RRR_FREE_IF_NOT_NULL(content_type_buf);
	RRR_FREE_IF_NOT_NULL(body_buf);
	return ret;
}

static int __rrr_http_session_multipart_form_data_body_send (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	char *body_buf = NULL;
	char *boundary_buf = NULL;

	// RFC7578

	if ((ret = rrr_asprintf (&boundary_buf, "RRR%u", (unsigned int) rrr_rand())) < 0) {
		RRR_MSG_0("Could not create boundary_buf string in __rrr_http_session_multipart_form_data_body_send\n");
		ret = 1;
		goto out;
	}

	{
		RRR_FREE_IF_NOT_NULL(body_buf);
		if ((ret = rrr_asprintf (
				&body_buf,
				"Content-Type: multipart/form-data; boundary=%s\r\n"
				"Transfer-Encoding: chunked\r\n\r\n",
				boundary_buf
		)) < 0) {
			RRR_MSG_0("Could not create content type string in __rrr_http_session_multipart_form_data_body_send\n");
			goto out;
		}

		if ((ret = rrr_net_transport_ctx_send_blocking(handle, body_buf, strlen(body_buf))) != 0) {
			RRR_MSG_0("Could not send first part of HTTP request in __rrr_http_session_multipart_form_data_body_send\n");
			goto out;
		}
	}

	// All sends below this point must be wrapped inside chunk sender

	int is_first = 1;
	RRR_LL_ITERATE_BEGIN(&session->request_part->fields, struct rrr_http_field);
		if ((ret = __rrr_http_session_multipart_field_send(handle, boundary_buf, node, is_first)) != 0) {
			goto out;
		}
		is_first = 0;
	RRR_LL_ITERATE_END();

	{
		RRR_FREE_IF_NOT_NULL(body_buf);
		if ((ret = rrr_asprintf (
				&body_buf,
				"\r\n--%s--\r\n",  // <-- ONE CRLF AFTER BODY AND ONE AT THE VERY END
				boundary_buf
		)) < 0) {
			RRR_MSG_0("Could not create last boundary in __rrr_http_session_multipart_form_data_body_send\n");
			ret = 1;
			goto out;
		}

		if ((ret = __rrr_http_session_multipart_form_data_body_send_wrap_chunk(handle, body_buf, strlen(body_buf))) != 0) {
			RRR_MSG_0("Could not send last part of HTTP request in __rrr_http_session_multipart_form_data_body_send\n");
			goto out;
		}
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(handle, "0\r\n\r\n", 5)) != 0) {
		RRR_MSG_0("Could not send terminating chunk of HTTP request in __rrr_http_session_multipart_form_data_body_send\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(body_buf);
	RRR_FREE_IF_NOT_NULL(boundary_buf);

	return ret;
}

static int __rrr_http_session_post_x_www_form_body_send (
		struct rrr_net_transport_handle *handle,
		int no_urlencoding
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;
	char *body_buf = NULL;
	char *header_buf = NULL;

	ssize_t body_size = 0;

	if (no_urlencoding == 0) {
		body_buf = rrr_http_field_collection_to_urlencoded_form_data(&body_size, &session->request_part->fields);
	}
	else {
		body_buf = rrr_http_field_collection_to_raw_form_data(&body_size, &session->request_part->fields);
	}

	if (body_buf == NULL) {
		RRR_MSG_0("Could not create body in __rrr_http_session_send_post_urlencoded_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf (
			&header_buf,
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: %u\r\n\r\n",
			body_size
	)) < 0) {
		RRR_MSG_0("Could not create content type string in __rrr_http_session_send_get_body\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, header_buf, strlen(header_buf))) != 0) {
		RRR_MSG_0("Could not send GET body header in __rrr_http_session_send_get_body\n");
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, body_buf, body_size)) != 0) {
		RRR_MSG_0("Could not send GET body in __rrr_http_session_send_get_body\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(header_buf);
	RRR_FREE_IF_NOT_NULL(body_buf);
	return ret;
}

struct rrr_http_session_send_request_callback_data {
	const char *host;
};

static int __rrr_http_session_request_send (struct rrr_net_transport_handle *handle, void *arg) {
	struct rrr_http_session_send_request_callback_data *callback_data = arg;
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	char *request_buf = NULL;
	char *host_buf = NULL;
	char *user_agent_buf = NULL;

	ssize_t extra_uri_size = 0;
	char *extra_uri_tmp = NULL;
	const char *extra_uri_separator = "";

	char *uri_tmp = NULL;

	const char *uri_to_use = session->uri_str;

	host_buf = rrr_http_util_quote_header_value(callback_data->host, '"', '"');
	if (host_buf == NULL) {
		RRR_MSG_0("Invalid host '%s' in rrr_http_session_send_request\n", callback_data->host);
		ret = 1;
		goto out;
	}

	user_agent_buf = rrr_http_util_quote_header_value(session->user_agent, '"', '"');
	if (user_agent_buf == NULL) {
		RRR_MSG_0("Invalid user agent '%s' in rrr_http_session_send_request\n", session->user_agent);
		ret = 1;
		goto out;
	}

	if (session->method == RRR_HTTP_METHOD_GET && RRR_LL_COUNT(&session->request_part->fields) > 0) {
		extra_uri_tmp  = rrr_http_field_collection_to_urlencoded_form_data(&extra_uri_size, &session->request_part->fields);

		if (strchr(session->uri_str, '?') != NULL) {
			// Append to existing ?-query string in GET URI
			extra_uri_separator = "&";
		}
		else {
			extra_uri_separator = "?";
		}

		size_t uri_orig_len = strlen(uri_to_use);

		if ((uri_tmp = malloc(uri_orig_len + extra_uri_size + 1 + 1)) == NULL) { // + separator + 0
			RRR_MSG_0("Could not allocate memory for new URI in __rrr_http_session_request_send\n");
			ret = 1;
			goto out;
		}

		char *wpos = uri_tmp;

		memcpy(wpos, uri_to_use, uri_orig_len);
		wpos += uri_orig_len;

		*wpos = *extra_uri_separator;
		wpos++;

		memcpy(wpos, extra_uri_tmp, extra_uri_size);
		wpos += extra_uri_size;

		*wpos = '\0';

		uri_to_use = uri_tmp;
	}

	if ((ret = rrr_asprintf (
			&request_buf,
			"%s %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept-Charset: UTF-8\r\n",
			(session->method == RRR_HTTP_METHOD_GET ? "GET" : "POST"),
			uri_to_use,
			host_buf,
			user_agent_buf
	)) < 0) {
		RRR_MSG_0("Error while making request string in rrr_http_session_send_request\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, request_buf, strlen(request_buf))) != 0) {
		RRR_MSG_0("Could not send first part of HTTP request in rrr_http_session_send_request\n");
		goto out;
	}

	if (session->method != RRR_HTTP_METHOD_GET && RRR_LL_COUNT(&session->request_part->fields) > 0) {
		if (session->method == RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA) {
			if ((ret = __rrr_http_session_multipart_form_data_body_send (handle)) != 0) {
				RRR_MSG_0("Could not send POST multipart body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else if (session->method == RRR_HTTP_METHOD_POST_URLENCODED) {
			if ((ret = __rrr_http_session_post_x_www_form_body_send (handle, 0)) != 0) {
				RRR_MSG_0("Could not send POST urlencoded body in rrr_http_session_send_request\n");
				goto out;
			}
		}
		else if (session->method == RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING) {
			// Application may choose to quote itself (influxdb has special quoting)
			if ((ret = __rrr_http_session_post_x_www_form_body_send (handle, 1)) != 0) {
				RRR_MSG_0("Could not send POST urlencoded body in rrr_http_session_send_request\n");
				goto out;
			}
		}

		// TODO : If we use plain text or octet stream method, simply concatenate and encode all fields

		else {
			RRR_MSG_0("Unknown request method %s for request with fields set\n", RRR_HTTP_METHOD_TO_STR(session->method));
			ret = 1;
			goto out;
		}
	}
	else if ((ret = rrr_net_transport_ctx_send_blocking (handle, "\r\n", strlen("\r\n"))) != 0) {
		RRR_MSG_0("Could not send last \\r\\n in rrr_http_session_send_request\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(user_agent_buf);
	RRR_FREE_IF_NOT_NULL(host_buf);
	RRR_FREE_IF_NOT_NULL(request_buf);
	RRR_FREE_IF_NOT_NULL(extra_uri_tmp);
	RRR_FREE_IF_NOT_NULL(uri_tmp);
	return ret;
}

int rrr_http_session_transport_ctx_request_send (
		struct rrr_net_transport_handle *handle,
		const char *host
) {
	struct rrr_http_session_send_request_callback_data callback_data = {
		host
	};

	return __rrr_http_session_request_send(handle, &callback_data);
}

struct rrr_http_session_receive_data {
	struct rrr_http_session *session;
	ssize_t parse_complete_pos;
	ssize_t received_bytes;
	int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_session_response_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;
	struct rrr_http_part *part = receive_data->session->response_part;

	(void)(read_session);

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_dump_header(part);
	}

	RRR_DBG_3("HTTP reading complete, data length is %li response length is %li header length is %li\n",
			part->data_length,  part->request_or_response_length, part->header_length);

	return receive_data->callback (
			part,
			read_session->rx_buf_ptr,
			(const struct sockaddr *) &read_session->src_addr,
			read_session->src_addr_len,
			receive_data->callback_arg
	);
}

static int __rrr_http_session_request_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;
	struct rrr_http_part *part = receive_data->session->request_part;

	(void)(read_session);

	int ret = 0;

//	const struct rrr_http_header_field *content_type = rrr_http_part_get_header_field(part, "content-type");

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_dump_header(part);
	}

	RRR_DBG_3("HTTP reading complete, data length is %li response length is %li header length is %li\n",
			part->data_length,  part->request_or_response_length, part->header_length);

	if ((ret = rrr_http_part_process_multipart(part, read_session->rx_buf_ptr)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_extract_post_and_query_fields(part, read_session->rx_buf_ptr)) != 0) {
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_field_collection_dump (&part->fields);
	}

	ret = receive_data->callback (
			part,
			read_session->rx_buf_ptr,
			(const struct sockaddr *) &read_session->src_addr,
			read_session->src_addr_len,
			receive_data->callback_arg
	);

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

	ssize_t target_size;
	ssize_t parsed_bytes = 0;

	if (receive_data->session->is_client == 1) {
		ret = rrr_http_part_parse (
				receive_data->session->response_part,
				&target_size,
				&parsed_bytes,
				read_session->rx_buf_ptr,
				receive_data->parse_complete_pos,
				end,
				RRR_HTTP_PARSE_RESPONSE
		);
	}
	else {
		ret = rrr_http_part_parse (
				receive_data->session->request_part,
				&target_size,
				&parsed_bytes,
				read_session->rx_buf_ptr,
				receive_data->parse_complete_pos,
				end,
				RRR_HTTP_PARSE_REQUEST
		);
	}

	receive_data->parse_complete_pos += parsed_bytes;

	// Used only for stall timeout
	receive_data->received_bytes = read_session->rx_buf_wpos;

//	if (receive_data->session->is_client == 1 && receive_data->session->method == 0)

	if (ret == RRR_HTTP_PARSE_OK) {
		read_session->target_size = target_size;
	}
	else if (ret == RRR_HTTP_PARSE_INCOMPLETE) {
		if (receive_data->session->response_part->data_length == -1) {
			read_session->read_complete_method = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE;
			ret = RRR_NET_TRANSPORT_READ_OK;
		}
	}
	else {
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
	}

	return ret;
}

int rrr_http_session_transport_ctx_receive (
		struct rrr_net_transport_handle *handle,
		uint64_t timeout_stall_us,
		uint64_t timeout_total_us,
		ssize_t read_max_size,
		int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS),
		void *callback_arg
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	struct rrr_http_session_receive_data callback_data = {
			session,
			0,
			0,
			callback,
			callback_arg
	};

	if ((ret = __rrr_http_session_prepare_parts(callback_data.session)) != 0) {
		goto out;
	}

	uint64_t time_start;
	uint64_t time_last_change;

	time_start = time_last_change = rrr_time_get_64();

	ssize_t prev_received_bytes = 0;

	do {
		ret = rrr_net_transport_ctx_read_message (
					handle,
					100,
					4096,
					65535,
					read_max_size,
					0, // Flags
					__rrr_http_session_receive_get_target_size,
					&callback_data,
					session->is_client
						? __rrr_http_session_response_receive_callback
						: __rrr_http_session_request_receive_callback,
					&callback_data
		);

		if (ret != RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			break;
		}

		// TODO : Maybe this is not needed or we should sleep only if nothing was read
		rrr_posix_usleep(500);

		uint64_t time_now = rrr_time_get_64();

		if (prev_received_bytes != callback_data.received_bytes) {
			time_last_change = time_now;
		}

		if (time_now - time_start > timeout_total_us) {
			RRR_DBG_2("HTTP total receive timeout of %" PRIu64 " ms reached for client %i\n",
					timeout_total_us / 1000, handle->handle);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		}
		if (time_now - time_last_change > timeout_stall_us) {
			RRR_DBG_2("HTTP stall receive timeout of %" PRIu64 " ms reached for client %i\n",
					timeout_stall_us / 1000, handle->handle);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		}

		prev_received_bytes = callback_data.received_bytes;
	} while (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE);

	if (ret != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE || ret == RRR_NET_TRANSPORT_READ_SOFT_ERROR) {
			ret = RRR_HTTP_SOFT_ERROR;
		}
		else {
			ret = RRR_HTTP_HARD_ERROR;
		}
		// Don't print error here, not needed.
		goto out;
	}

	out:
	return ret;
}

int rrr_http_session_transport_ctx_check_data_received (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = handle->application_private_ptr;
	return (session->request_part->request_or_response_length > 0);
}

int rrr_http_session_transport_ctx_check_response_part_initialized (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = handle->application_private_ptr;
	return session->response_part != NULL;
}

int rrr_http_session_transport_ctx_set_response_code (
		struct rrr_net_transport_handle *handle,
		unsigned int code
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	session->response_part->response_code = code;

	return 0;
}

int rrr_http_session_transport_ctx_push_response_header (
		struct rrr_net_transport_handle *handle,
		const char *name,
		const char *value
) {
	struct rrr_http_session *session = handle->application_private_ptr;
	return rrr_http_part_header_field_push(session->response_part, name, value);
}

struct rrr_http_session_send_header_field_callback_data {
	struct rrr_net_transport_handle *handle;
};

static int __rrr_http_session_send_header_field_callback (struct rrr_http_header_field *field, void *arg) {
	struct rrr_http_session_send_header_field_callback_data *callback_data = arg;

	int ret = 0;

	char *send_data = NULL;
	size_t send_data_length = 0;

	if (field->name == NULL || field->value == NULL) {
		RRR_BUG("BUG: Name or value was NULL in __rrr_http_session_send_header_field_callback\n");
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in __rrr_http_session_send_header_field_callback, this is not supported\n");
	}

	if ((send_data_length = rrr_asprintf(&send_data, "%s: %s\r\n", field->name, field->value)) <= 0) {
		RRR_MSG_0("Could not allocate memory for header line in __rrr_http_session_send_header_field_callback\n");
		ret = 1;
		goto out;
	}

	// Hack to create Camel-Case header names (before : only)
	int next_to_upper = 1;
	for (size_t i = 0; i < send_data_length; i++) {
		if (send_data[i] == ':' || send_data[i] == '\0') {
			break;
		}

		if (next_to_upper) {
			if (send_data[i] >= 'a' && send_data[i] <= 'z') {
				send_data[i] -= ('a' - 'A');
			}
		}

		next_to_upper = (send_data[i] == '-' ? 1 : 0);
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(callback_data->handle, send_data, send_data_length)) != 0) {
		RRR_MSG_0("Error: Send failed in __rrr_http_session_send_header_field_callback\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(send_data);
	return ret;
}

int rrr_http_session_transport_ctx_send_response (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = handle->application_private_ptr;
	struct rrr_http_part *response_part = session->response_part;

	int ret = 0;

	if (response_part == NULL) {
		RRR_BUG("BUG: Response part was NULL in rrr_http_session_send_response\n");
	}
	if (response_part->response_code == 0) {
		RRR_BUG("BUG: Response code was not set in rrr_http_session_send_response\n");
	}

	const char *response_str = NULL;

	switch (response_part->response_code) {
		case RRR_HTTP_RESPONSE_CODE_OK:
			response_str = "HTTP/1.1 200 OK\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT:
			response_str = "HTTP/1.1 204 No Content\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST:
			response_str = "HTTP/1.1 400 Bad Request\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_ERROR_NOT_FOUND:
			response_str = "HTTP/1.1 404 Not Found\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR:
			response_str = "HTTP/1.1 500 Internal Server Error\r\n";
			break;
		default:
			RRR_BUG("BUG: Response code %i not implemented in rrr_http_session_send_response\n",
					response_part->response_code);
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(handle, response_str, strlen(response_str))) != 0) {
		goto out_err;
	}

	struct rrr_http_session_send_header_field_callback_data callback_data = {
			handle
	};

	if ((ret = rrr_http_part_header_fields_iterate(response_part, __rrr_http_session_send_header_field_callback, &callback_data)) != 0) {
		goto out_err;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(handle, "\r\n", 2)) != 0 ) {
		goto out_err;
	}

	goto out;
	out_err:
		RRR_MSG_0("Error while sending headers for HTTP client %i in rrr_http_session_transport_ctx_send_response\n",
				handle->handle);
	out:
		return ret;
}
