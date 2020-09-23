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
#include <strings.h>
#include <unistd.h>
#include <limits.h>

#include "../log.h"

#include "http_fields.h"
#include "http_session.h"
#include "http_util.h"
#include "http_part.h"

#include "../net_transport/net_transport.h"
#include "../random.h"
#include "../read.h"
#include "../string_builder.h"
#include "../sha1/sha1.h"
#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/base64.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../util/macro_utils.h"

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
	rrr_websocket_state_clear(&session->ws_state);
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

static int __rrr_http_session_prepare_part (struct rrr_http_part **part) {
	int ret = 0;

	if (*part != NULL) {
		rrr_http_part_destroy(*part);
		*part = NULL;
	}
	if ((ret = rrr_http_part_new(part)) != 0) {
		RRR_MSG_0("Could not create HTTP part in __rrr_http_session_prepare_part\n");
		goto out;
	}

	out:
	return ret;
}

static void __rrr_http_session_destroy_part (struct rrr_http_part **part) {
	if (*part != NULL) {
		rrr_http_part_destroy(*part);
		*part = NULL;
	}
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

int rrr_http_session_transport_ctx_client_new_or_clean (
		struct rrr_net_transport_handle *handle,
		enum rrr_http_method method,
		const char *user_agent
) {
	int ret = 0;

	struct rrr_http_session *session = NULL;

	// With keepalive connections, structures are already present in transport handle
	if (!rrr_net_transport_ctx_handle_has_application_data(handle)) {
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

		// Transport framework responsible for cleaning up
		rrr_net_transport_ctx_handle_application_data_bind (
				handle,
				session,
				__rrr_http_session_destroy_void
		);
	}
	else {
		session = handle->application_private_ptr;
	}

	if (__rrr_http_session_prepare_part(&session->request_part) != 0) {
		RRR_MSG_0("Could not prepare request part in rrr_http_session_transport_ctx_client_new\n");
		ret = 1;
		goto out;
	}

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
			(name != NULL ? strlen(name) : 0),
			value,
			value_size,
			content_type,
			(content_type != NULL ? strlen(content_type) : 0)
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
			(name != NULL ? strlen(name) : 0),
			value,
			value_size,
			content_type,
			(content_type != NULL ? strlen(content_type) : 0)
	);
}

void rrr_http_session_query_fields_dump (
		struct rrr_http_session *session
) {
	rrr_http_field_collection_dump(&session->request_part->fields);
}

int rrr_http_session_set_keepalive (
		struct rrr_http_session *session,
		int set
) {
	int ret = 0;

	if (session->request_part == NULL) {
		RRR_BUG("BUG: rrr_http_session_set_keepalive called without request part being initialized first\n");
	}

	rrr_http_part_header_field_remove(session->request_part, "Connection");

	if (set) {
		ret = rrr_http_part_header_field_push(session->request_part, "Connection", "keep-alive");
	}

	return ret;
}

static void __rrr_http_session_free_dbl_ptr (void *ptr) {
	void *to_free = *((void **) ptr);
	RRR_FREE_IF_NOT_NULL(to_free);
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

	if (rrr_nullsafe_str_isset(node->name)) {
		if ((name_buf = rrr_http_util_quote_header_value_nullsafe(node->name, '"', '"')) == NULL) {
			RRR_MSG_0("Could not quote field name_buf in __rrr_http_session_multipart_field_send\n");
			ret = 1;
			goto out;
		}

		if ((ret = rrr_asprintf (&name_buf_full, "; name=%s", name_buf)) <= 0) {
			RRR_MSG_0("Could not create name_buf_full in __rrr_http_session_multipart_field_send return was %i\n", ret);
			ret = 1;
			goto out;
		}
	}

	if (rrr_nullsafe_str_isset(node->content_type)) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,node->content_type);
		if ((ret = rrr_asprintf (&content_type_buf, "Content-Type: %s\r\n", value)) <= 0) {
			RRR_MSG_0("Could not create content_type_buf in __rrr_http_session_multipart_field_send return was %i\n", ret);
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
		RRR_MSG_0("Could not create content type string and body  in __rrr_http_session_multipart_field_send return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_http_session_multipart_form_data_body_send_wrap_chunk(handle, body_buf, strlen(body_buf))) != 0) {
		RRR_MSG_0("Could not send form part of HTTP request in __rrr_http_session_multipart_field_send A\n");
		goto out;
	}

	if (rrr_nullsafe_str_isset(node->value)) {
		if ((ret = __rrr_http_session_multipart_form_data_body_send_wrap_chunk(
				handle,
				node->value->str,
				node->value->len
		)) != 0) {
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

	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &body_buf);
	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &boundary_buf);

	// RFC7578

	if ((ret = rrr_asprintf (&boundary_buf, "RRR%u", (unsigned int) rrr_rand())) < 0) {
		RRR_MSG_0("Could not create boundary_buf string in __rrr_http_session_multipart_form_data_body_send return was %i\n", ret);
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
			RRR_MSG_0("Could not create content type string in __rrr_http_session_multipart_form_data_body_send return was %i\n", ret);
			ret = 1;
			goto out;
		}

		if ((ret = rrr_net_transport_ctx_send_blocking(handle, body_buf, strlen(body_buf))) != 0) {
			RRR_DBG_1("Could not send first part of HTTP request in __rrr_http_session_multipart_form_data_body_send\n");
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
			RRR_MSG_0("Could not create last boundary in __rrr_http_session_multipart_form_data_body_send return was %i\n", ret);
			ret = 1;
			goto out;
		}

		if ((ret = __rrr_http_session_multipart_form_data_body_send_wrap_chunk(handle, body_buf, strlen(body_buf))) != 0) {
			RRR_MSG_0("Could not send last part of HTTP request in __rrr_http_session_multipart_form_data_body_send\n");
			goto out;
		}
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(handle, "0\r\n\r\n", 5)) != 0) {
		RRR_DBG_1("Could not send terminating chunk of HTTP request in __rrr_http_session_multipart_form_data_body_send\n");
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

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

	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &body_buf);
	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &header_buf);

	rrr_length body_size = 0;
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
			"Content-Length: %" PRIrrrl "\r\n\r\n",
			body_size
	)) < 0) {
		RRR_MSG_0("Could not create content type string in __rrr_http_session_send_get_body return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, header_buf, strlen(header_buf))) != 0) {
		RRR_DBG_1("Could not send GET body header in __rrr_http_session_send_get_body\n");
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, body_buf, body_size)) != 0) {
		RRR_DBG_1("Could not send GET body in __rrr_http_session_send_get_body\n");
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

struct rrr_http_session_send_request_callback_data {
	const char *host;
};

static int __rrr_http_session_request_send_make_headers_callback (
		struct rrr_http_header_field *field,
		void *arg
) {
	struct rrr_string_builder *builder = arg;

	// Note : Only plain values supported
	if (!rrr_nullsafe_str_isset(field->value)) {
		return 0;
	}

	int ret = 0;

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,field->value);

	ret |= rrr_string_builder_append(builder, name);
	ret |= rrr_string_builder_append(builder, ": ");
	ret |= rrr_string_builder_append(builder, value);
	ret |= rrr_string_builder_append(builder, "\r\n");

	return ret;
}

static int __rrr_http_session_request_send (struct rrr_net_transport_handle *handle, void *arg) {
	struct rrr_http_session_send_request_callback_data *callback_data = arg;
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	char *request_buf = NULL;
	char *host_buf = NULL;
	char *user_agent_buf = NULL;
	char *uri_tmp = NULL;
	char *extra_uri_tmp = NULL;

	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &request_buf);
	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &host_buf);
	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &user_agent_buf);
	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &uri_tmp);
	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &extra_uri_tmp);

	rrr_length extra_uri_size = 0;
	const char *extra_uri_separator = "";

	const char *uri_to_use = session->uri_str;

	struct rrr_string_builder *header_builder = NULL;

	if (rrr_string_builder_new(&header_builder) != 0) {
		RRR_MSG_0("Failed to create string builder in __rrr_http_session_request_send\n");
		ret = 1;
		goto out_final;
	}

	pthread_cleanup_push(rrr_string_builder_destroy_void, header_builder);

	host_buf = rrr_http_util_quote_header_value(callback_data->host, strlen(callback_data->host), '"', '"');
	if (host_buf == NULL) {
		RRR_MSG_0("Invalid host '%s' in rrr_http_session_send_request\n", callback_data->host);
		ret = 1;
		goto out;
	}

	user_agent_buf = rrr_http_util_quote_header_value(session->user_agent, strlen(session->user_agent), '"', '"');
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

		rrr_biglength uri_orig_len = strlen(uri_to_use);
		RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(uri_orig_len,"rrr_http_session_send_request");

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
		RRR_MSG_0("Error while making request string in rrr_http_session_send_request return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, request_buf, strlen(request_buf))) != 0) {
		RRR_DBG_1("Could not send first part of HTTP request header in rrr_http_session_send_request\n");
		goto out;
	}

	rrr_string_builder_clear(header_builder);

	if (rrr_http_part_header_fields_iterate (
			session->request_part,
			__rrr_http_session_request_send_make_headers_callback,
			header_builder
	) != 0) {
		RRR_MSG_0("Failed to make header fields in rrr_http_session_send_request\n");
		ret = 1;
		goto out;
	}

	ssize_t header_builder_length = rrr_string_builder_length(header_builder);
	if (header_builder_length > 0) {
		RRR_FREE_IF_NOT_NULL(request_buf);
		request_buf = rrr_string_builder_buffer_takeover(header_builder);
		if ((ret = rrr_net_transport_ctx_send_blocking (handle, request_buf, header_builder_length)) != 0) {
			RRR_MSG_0("Could not send second part of HTTP request header in rrr_http_session_send_request\n");
			goto out;
		}
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
		pthread_cleanup_pop(1);
	out_final:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
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

int rrr_http_session_transport_ctx_raw_request_send (
		struct rrr_net_transport_handle *handle,
		const char *raw_request_data,
		size_t raw_request_size
) {
	if (raw_request_size == 0) {
		RRR_BUG("BUG: Received 0 size in rrr_http_session_transport_ctx_raw_request_send\n");
	}
	return rrr_net_transport_ctx_send_blocking (handle, raw_request_data, raw_request_size);
}

struct rrr_http_session_receive_data {
	struct rrr_net_transport_handle *handle;
	ssize_t parse_complete_pos;
	ssize_t received_bytes; // Used only for stall timeout and sleeping
	rrr_http_unique_id unique_id;
	int (*websocket_callback)(RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS);
	void *websocket_callback_arg;
	int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
	int (*raw_callback)(RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS);
	void *raw_callback_arg;
};

static int __rrr_http_session_response_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;
	struct rrr_http_session *session = receive_data->handle->application_private_ptr;

	int ret = 0;

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_dump_header(session->response_part);
	}

	RRR_DBG_3("HTTP reading complete, data length is %li response length is %li header length is %li\n",
			session->response_part->data_length,
			session->response_part->headroom_length,
			session->response_part->header_length
	);

	if (receive_data->raw_callback != NULL) {
		if ((ret = receive_data->raw_callback (
				read_session->rx_buf_ptr,
				read_session->rx_buf_wpos,
				0,
				receive_data->raw_callback_arg
		)) != 0) {
			RRR_MSG_0("Error %i from raw callback in __rrr_http_session_response_receive_callback\n", ret);
			goto out;
		}
	}

	if ((ret = receive_data->callback (
			receive_data->handle,
			session->request_part,
			session->response_part,
			read_session->rx_buf_ptr,
			(const struct sockaddr *) &read_session->src_addr,
			read_session->src_addr_len,
			read_session->rx_overshoot_size,
			0,
			receive_data->callback_arg
	)) != 0) {
		goto out;
	}

	// ALWAYS destroy parts
	out:
	__rrr_http_session_destroy_part(&session->response_part);
	__rrr_http_session_destroy_part(&session->request_part);

	return ret;
}

struct rrr_http_session_send_header_field_callback_data {
	struct rrr_net_transport_handle *handle;
};

static int __rrr_http_session_send_header_field_callback (struct rrr_http_header_field *field, void *arg) {
	struct rrr_http_session_send_header_field_callback_data *callback_data = arg;

	int ret = 0;

	char *send_data = NULL;
	size_t send_data_length = 0;

	if (!rrr_nullsafe_str_isset(field->name) || !rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: Name or value was NULL in __rrr_http_session_send_header_field_callback\n");
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in __rrr_http_session_send_header_field_callback, this is not supported\n");
	}

	pthread_cleanup_push(__rrr_http_session_free_dbl_ptr, &send_data);

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, field->value);

	if ((send_data_length = rrr_asprintf(&send_data, "%s: %s\r\n", name, value)) <= 0) {
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
		RRR_DBG_1("Error: Send failed in __rrr_http_session_send_header_field_callback\n");
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_session_transport_ctx_send_response (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http_session *session = handle->application_private_ptr;
	struct rrr_http_part *response_part = session->response_part;

	int ret = 0;

	if (response_part == NULL) {
		RRR_BUG("BUG: Response part was NULL in rrr_http_session_send_response\n");
	}

	if (response_part->response_raw_data_nullsafe != NULL) {
		if ((ret = rrr_net_transport_ctx_send_blocking (
				handle,
				response_part->response_raw_data_nullsafe->str,
				response_part->response_raw_data_nullsafe->len
		)) != 0 ) {
			goto out_err;
		}
		goto out;
	}

	if (response_part->response_code == 0) {
		RRR_BUG("BUG: Response code was not set in rrr_http_session_send_response\n");
	}

	const char *response_str = NULL;

	switch (response_part->response_code) {
		case RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS:
			response_str = "HTTP/1.1 101 Switching Protocols\r\n";
			break;
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
		case RRR_HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT:
			response_str = "HTTP/1.1 504 Gateway Timeout\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_VERSION_NOT_SUPPORTED:
			response_str = "HTTP/1.1 504 Version Not Supported\r\n";
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

static int __rrr_http_session_request_receive_check_websocket_version (
		struct rrr_http_session *session
) {
	const struct rrr_http_header_field *sec_websocket_version = rrr_http_part_header_field_get(session->request_part, "sec-websocket-version");
	if (sec_websocket_version == NULL) {
		RRR_DBG_1("Field Sec-WebSocket-Version missing in HTTP request with Connection: Upgrade and Upgrade: websocket headers set\n");
		return 1;
	}

	if (rrr_nullsafe_str_cmpto(sec_websocket_version->value, "13") != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,sec_websocket_version->value);
		RRR_DBG_1("Received HTTP request with WebSocket upgrade and version '%s' set, but only version '13' is supported\n",
				value);
		return 1;
	}
	return 0;
}

static int __rrr_http_session_request_receive_try_websocket (
		int *do_websocket,
		struct rrr_http_session_receive_data *receive_data,
		struct rrr_http_session *session,
		struct rrr_read_session *read_session,
		const char *data_to_use
) {
	*do_websocket = 0;

	int ret = 0;

	char *accept_str_tmp = NULL;
	char *accept_base64_tmp = NULL;

	const struct rrr_http_header_field *connection = rrr_http_part_header_field_get_with_value(session->request_part, "connection", "upgrade");
	const struct rrr_http_header_field *upgrade = rrr_http_part_header_field_get_with_value(session->request_part, "upgrade", "websocket");

	if (connection == NULL || upgrade == NULL) {
		goto out;
	}

	*do_websocket = 1;

	if (read_session->rx_overshoot_size) {
		RRR_DBG_1("Extra data received from client after websocket HTTP request\n");
		goto out_bad_request;
	}

	if (__rrr_http_session_request_receive_check_websocket_version(session) != 0) {
		goto out_bad_request;
	}

	const struct rrr_http_header_field *sec_websocket_key = rrr_http_part_header_field_get(session->request_part, "sec-websocket-key");
	if (sec_websocket_key == NULL) {
		RRR_DBG_1("HTTP request with WebSocket upgrade missing field Sec-WebSocket-Key\n");
		goto out_bad_request;
	}

	if (!rrr_nullsafe_str_isset(sec_websocket_key->binary_value_nullsafe)) {
		RRR_BUG("BUG: Binary value was not set for sec-websocket-key header field in __rrr_http_session_request_receive_try_websocket\n");
	}

	if (rrr_nullsafe_str_len(sec_websocket_key->binary_value_nullsafe) != 16) {
		RRR_DBG_1("Incorrect length for Sec-WebSocket-Key header field in HTTP request with WebSocket upgrade. 16 bytes are required but got %" PRIrrrl "\n",
				rrr_nullsafe_str_len(sec_websocket_key->binary_value_nullsafe));
		goto out_bad_request;
	}

	if ((ret = receive_data->websocket_callback (
			do_websocket,
			receive_data->handle,
			session->request_part,
			session->response_part,
			data_to_use,
			(const struct sockaddr *) &read_session->src_addr,
			read_session->src_addr_len,
			read_session->rx_overshoot_size,
			receive_data->unique_id,
			receive_data->websocket_callback_arg
	)) != RRR_HTTP_OK || session->response_part->response_code != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(session->response_part, "connection", "upgrade")) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(session->response_part, "upgrade", "websocket")) != 0) {
		goto out;
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(sec_websocket_key_str, sec_websocket_key->value);
	if (rrr_asprintf(&accept_str_tmp, "%s%s", sec_websocket_key_str, RRR_HTTP_WEBSOCKET_GUID) <= 0) {
		RRR_MSG_0("Failed to concatenate accept-string in __rrr_http_session_request_receive_try_websocket\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	rrr_SHA1Context sha1_ctx = {0};
	rrr_SHA1Reset(&sha1_ctx);
	rrr_SHA1Input(&sha1_ctx, (const unsigned char *) accept_str_tmp, strlen(accept_str_tmp));

	if (!rrr_SHA1Result(&sha1_ctx) || sha1_ctx.Corrupted != 0 || sha1_ctx.Computed != 1) {
		RRR_MSG_0("Computation of SHA1 failed in __rrr_http_session_request_receive_try_websocket (Corrupt: %i - Computed: %i)\n",
				sha1_ctx.Corrupted, sha1_ctx.Computed);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	rrr_SHA1toBE(&sha1_ctx);

	size_t accept_base64_length = 0;
	if ((accept_base64_tmp = (char *) rrr_base64_encode (
			(const unsigned char *) sha1_ctx.Message_Digest,
			sizeof(sha1_ctx.Message_Digest),
			&accept_base64_length
	)) == NULL) {
		RRR_MSG_0("Base64 encoding failed in __rrr_http_session_request_receive_try_websocket\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(session->response_part, "sec-websocket-accept", accept_base64_tmp)) != 0) {
		goto out;
	}

	session->response_part->response_code = RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS;

	goto out;
	out_bad_request:
		session->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
	out:
		RRR_FREE_IF_NOT_NULL(accept_str_tmp);
		RRR_FREE_IF_NOT_NULL(accept_base64_tmp);
		return ret;
}

static int __rrr_http_session_request_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;
	struct rrr_http_session *session = receive_data->handle->application_private_ptr;

	int ret = 0;

	char *merged_chunks = NULL;

//	const struct rrr_http_header_field *content_type = rrr_http_part_get_header_field(part, "content-type");

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_dump_header(session->request_part);
	}

	RRR_DBG_3("HTTP reading complete, data length is %li response length is %li header length is %li\n",
			session->request_part->data_length,
			session->request_part->headroom_length,
			session->request_part->header_length
	);

	if (receive_data->raw_callback != NULL) {
		if ((ret = receive_data->raw_callback (
				read_session->rx_buf_ptr,
				read_session->rx_buf_wpos,
				receive_data->unique_id,
				receive_data->raw_callback_arg
		)) != 0) {
			RRR_MSG_0("Error %i from raw callback in __rrr_http_session_request_receive_callback\n", ret);
			goto out;
		}
	}

	if ((ret = rrr_http_part_merge_chunks(&merged_chunks, session->request_part, read_session->rx_buf_ptr)) != 0) {
		goto out;
	}

	const char *data_to_use = (merged_chunks != NULL ? merged_chunks : read_session->rx_buf_ptr);

	if ((ret = rrr_http_part_process_multipart(session->request_part, data_to_use)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_extract_post_and_query_fields(session->request_part, data_to_use)) != 0) {
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_field_collection_dump (&session->request_part->fields);
	}

	if ((ret = __rrr_http_session_prepare_part(&session->response_part)) != 0) {
		RRR_MSG_0("Failed to prepare response part in __rrr_http_session_request_receive_callback\n");
		goto out;
	}

	int do_websocket = 0;
	if (receive_data->websocket_callback != NULL && (ret = __rrr_http_session_request_receive_try_websocket (
			&do_websocket,
			receive_data,
			session,
			read_session,
			data_to_use
	)) != 0) {
		goto out;
	}

	if (do_websocket != 0) {
		if (session->response_part->response_code == RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS) {
			RRR_DBG_3("Upgrading HTTP connection to WebSocket\n");
		}
		else {
			RRR_DBG_1("Upgrade HTTP connection to WebSocket failed\n");
		}
	}

	if (do_websocket == 0 && (ret = receive_data->callback (
			receive_data->handle,
			session->request_part,
			session->response_part,
			data_to_use,
			(const struct sockaddr *) &read_session->src_addr,
			read_session->src_addr_len,
			read_session->rx_overshoot_size,
			receive_data->unique_id,
			receive_data->callback_arg
	)) != RRR_HTTP_OK) {
		goto out;
	}

	if ((ret = __rrr_http_session_transport_ctx_send_response(receive_data->handle)) != RRR_HTTP_OK) {
		goto out;
	}

	out:
	// ALWAYS destroy parts
	__rrr_http_session_destroy_part(&session->request_part);
	__rrr_http_session_destroy_part(&session->response_part);
	RRR_FREE_IF_NOT_NULL(merged_chunks);
	return ret;
}

static int __rrr_http_session_receive_get_target_size (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_session_receive_data *receive_data = arg;
	struct rrr_http_session *session = receive_data->handle->application_private_ptr;

	int ret = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH;

	const char *end = read_session->rx_buf_ptr + read_session->rx_buf_wpos;

	// ASCII validation
	int rnrn_counter = 4;
	for (const unsigned char *pos = (const unsigned char *) read_session->rx_buf_ptr; pos < (const unsigned char *) end; pos++) {
//		printf("pos: %02x\n", *pos);
		if (*pos == '\r' && (rnrn_counter == 4 || rnrn_counter == 2)) {
			--rnrn_counter;
		}
		else if (*pos == '\n' && (rnrn_counter == 3 || rnrn_counter == 1)) {
			if (--rnrn_counter == 0) {
				break; // Header complete
			}
		}
		else {
			rnrn_counter = 4;

			if (*pos > 0x7f) {
				RRR_MSG_0("Received non-ASCII character %02x in HTTP request\n", *pos);
				ret = RRR_READ_SOFT_ERROR;
				goto out;
			}
		}
	}

	if (rnrn_counter != 0) {
		ret = RRR_READ_INCOMPLETE;
		goto out;
	}

	if (receive_data->parse_complete_pos > read_session->rx_buf_wpos) {
		RRR_MSG_0("Warning: Client sent some extra data after completed HTTP parse\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	size_t target_size;
	size_t parsed_bytes = 0;

	struct rrr_http_part **part_to_use = NULL;
	enum rrr_http_parse_type parse_type = 0;

	if (session->is_client == 1) {
		part_to_use = &session->response_part;
		parse_type = RRR_HTTP_PARSE_RESPONSE;
	}
	else {
		part_to_use = &session->request_part;
		parse_type = RRR_HTTP_PARSE_REQUEST;
	}

	if (*part_to_use == NULL) {
		if (rrr_http_part_new(part_to_use) != 0) {
			RRR_MSG_0("Could not create new part in __rrr_http_session_receive_get_target_size\n");
			ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
			goto out;
		}
	}

	// There might be more than one chunk in each read cycle, we have to
	// go through all of them in a loop here. The parser will always return
	// after a chunk is found.
	do {
		ret = rrr_http_part_parse (
				*part_to_use,
				&target_size,
				&parsed_bytes,
				read_session->rx_buf_ptr,
				receive_data->parse_complete_pos,
				end,
				parse_type
		);

		receive_data->parse_complete_pos += parsed_bytes;
	} while (parsed_bytes != 0 && ret == RRR_HTTP_PARSE_INCOMPLETE);

	if (target_size > SSIZE_MAX) {
		RRR_MSG_0("Target size %lu exceeds maximum value of %li while parsing HTTP part\n",
				target_size, SSIZE_MAX);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	// Used only for stall timeout
	receive_data->received_bytes = read_session->rx_buf_wpos;

	if (ret == RRR_HTTP_PARSE_OK) {
		read_session->target_size = target_size;
	}
	else if (ret == RRR_HTTP_PARSE_INCOMPLETE) {
		if ((*part_to_use)->data_length_unknown) {
			read_session->read_complete_method = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE;
			ret = RRR_NET_TRANSPORT_READ_OK;
		}
	}
	else {
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
	}

	out:
	return ret;
}

int rrr_http_session_transport_ctx_receive (
		struct rrr_net_transport_handle *handle,
		uint64_t timeout_stall_us,
		uint64_t timeout_total_us,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int (*websocket_callback)(RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS),
		void *websocket_callback_arg,
		int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS),
		void *callback_arg,
		int (*raw_callback)(RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_arg
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	struct rrr_http_session_receive_data callback_data = {
			handle,
			0,
			0,
			unique_id,
			websocket_callback,
			websocket_callback_arg,
			callback,
			callback_arg,
			raw_callback,
			raw_callback_arg
	};

	// Parts are prepared when a new client is created and /after/
	// final receive callback. The latter is to prepare for any new
	// parts on the same connection.
	//	if ((ret = __rrr_http_session_prepare_parts(callback_data.session)) != 0) {
	//		goto out;
	//	}

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

		uint64_t time_now = rrr_time_get_64();

		if (prev_received_bytes != callback_data.received_bytes) {
			time_last_change = time_now;
		}
		else {
			rrr_posix_usleep(500);
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

struct rrr_http_session_websocket_frame_callback_data {
	struct rrr_http_session *session;
	rrr_http_unique_id unique_id;
	int (*callback)(RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_session_websocket_frame_callback (
		RRR_WEBSOCKET_FRAME_CALLBACK_ARGS
) {
	struct rrr_http_session_websocket_frame_callback_data *callback_data = arg;
	return callback_data->callback (
			opcode,
			payload,
			payload_size,
			callback_data->unique_id,
			callback_data->callback_arg
	);
}

int rrr_http_session_transport_ctx_websocket_tick (
		struct rrr_net_transport_handle *handle,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int (*callback)(RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *callback_arg
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	struct rrr_http_session_websocket_frame_callback_data callback_data = {
			session,
			unique_id,
			callback,
			callback_arg
	};

	ret = rrr_websocket_transport_ctx_read_frames (
			handle,
			&session->ws_state,
			100,
			4096,
			65535,
			read_max_size,
			__rrr_http_session_websocket_frame_callback,
			&callback_data
	);

	return ret & ~(RRR_NET_TRANSPORT_READ_INCOMPLETE);
}
