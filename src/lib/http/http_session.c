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
#include "http_part_parse.h"
#include "http_part_multipart.h"
#include "http_application.h"

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
#ifdef RRR_WITH_NGHTTP2
#include "../http2/http2.h"
#endif

#ifdef RRR_WITH_NGHTTP2
const char rrr_http_session_alpn_protos_http2_priority[] = {
	     6, 'h', 't', 't', 'p', '/', '2',
	     8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};
#endif /* RRR_WITH_NGHTTP2 */

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
	rrr_http_application_destroy_if_not_null(&session->application);
	rrr_websocket_state_clear_all(&session->ws_state);
#ifdef RRR_WITH_NGHTTP2
	rrr_http2_session_destroy_if_not_null(&session->http2_session);
#endif
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

static void __rrr_http_session_destroy_part_if_not_null (struct rrr_http_part **part) {
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
		struct rrr_http_application **application,
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

		rrr_websocket_state_set_client_mode(&session->ws_state);

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

	if (rrr_http_part_prepare(&session->request_part) != 0) {
		RRR_MSG_0("Could not prepare request part in rrr_http_session_transport_ctx_client_new\n");
		ret = 1;
		goto out;
	}

	if (application != NULL && *application != NULL) {
		rrr_http_application_destroy_if_not_null(&session->application);
		session->application = *application;
		*application = NULL;
	}

	if (session->application == NULL) {
		RRR_BUG("BUG: Application pointer was NULL at end of rrr_http_session_transport_ctx_client_new_or_clean, maybe caller forgot to create it for us\n");
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

int rrr_http_session_transport_ctx_request_send (
		struct rrr_net_transport_handle *handle,
		const char *host
) {
	struct rrr_http_session *session = handle->application_private_ptr;
	return rrr_http_application_transport_ctx_request_send (
			session->application,
			handle,
			session->user_agent,
			host,
			session->uri_str,
			session->method,
			session->upgrade_mode,
			&session->ws_state,
			session->request_part
	);
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

int rrr_http_session_transport_ctx_tick (
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

	// Parts are prepared when a new client is created and /after/
	// final receive callback. The latter is to prepare for any new
	// parts on the same connection.
	//	if ((ret = __rrr_http_session_prepare_parts(callback_data.session)) != 0) {
	//		goto out;
	//	}

	uint64_t time_start;
	uint64_t time_last_change;

	time_start = time_last_change = rrr_time_get_64();

	ssize_t parse_complete_pos = 0;
	ssize_t received_bytes = 0;
	ssize_t prev_received_bytes = 0;

	// TODO : Don't prepare response part here

	if ((ret = rrr_http_part_prepare(&session->response_part)) != 0) {
		RRR_MSG_0("Failed to prepare response part in rrr_http_session_transport_ctx_tick\n");
		goto out;
	}


	// TODO : Don't block, return READ_INCOMPLETE to callers. Callers must be adapted.
	do {
		ret = rrr_http_application_transport_ctx_tick (
				&parse_complete_pos,
				&received_bytes,
				session->application,
				handle,
				&session->ws_state,
				session->request_part,
				session->response_part,
				read_max_size,
				unique_id,
				session->is_client,
				websocket_callback,
				websocket_callback_arg,
				callback,
				callback_arg,
				raw_callback,
				raw_callback_arg
		);

		if (ret != RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			break;
		}

		uint64_t time_now = rrr_time_get_64();

		if (prev_received_bytes != received_bytes) {
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

		prev_received_bytes = received_bytes;
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
	// ALWAYS destroy parts
	__rrr_http_session_destroy_part_if_not_null(&session->response_part);
	__rrr_http_session_destroy_part_if_not_null(&session->request_part);
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

static int __rrr_http_session_websocket_get_responses (
		struct rrr_websocket_state *ws_state,
		int (*get_response_callback)(RRR_HTTP_SESSION_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg
) {
	int ret = 0;

	void *response_data = NULL;
	ssize_t response_data_len = 0;
	int response_is_binary = 0;

	do {
		RRR_FREE_IF_NOT_NULL(response_data);
		if ((ret = get_response_callback (
				&response_data,
				&response_data_len,
				&response_is_binary,
				get_response_callback_arg
		)) != 0) {
			goto out;
		}
		if (response_data) {
			if ((ret = rrr_websocket_frame_enqueue (
					ws_state,
					(response_is_binary ? RRR_WEBSOCKET_OPCODE_BINARY : RRR_WEBSOCKET_OPCODE_TEXT),
					(char**) &response_data,
					response_data_len
			)) != 0) {
				goto out;
			}
		}
	} while (response_data != NULL);

	out:
	RRR_FREE_IF_NOT_NULL(response_data);
	return ret;
}

int rrr_http_session_transport_ctx_websocket_tick (
		struct rrr_net_transport_handle *handle,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int ping_interval_s,
		int timeout_s,
		int (*get_response_callback)(RRR_HTTP_SESSION_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	int ret = 0;

	struct rrr_http_session_websocket_frame_callback_data callback_data = {
			session,
			unique_id,
			frame_callback,
			frame_callback_arg
	};

	if (rrr_websocket_check_timeout(&session->ws_state, timeout_s) != 0) {
		RRR_DBG_2("HTTP websocket session timed out after %i seconds of inactivity\n", timeout_s);
		ret = RRR_READ_EOF;
		goto out;
	}

	if ((ret = rrr_websocket_enqueue_ping_if_needed(&session->ws_state, ping_interval_s)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_session_websocket_get_responses (
			&session->ws_state,
			get_response_callback,
			get_response_callback_arg
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_websocket_transport_ctx_send_frames (
			handle,
			&session->ws_state
	)) != 0) {
		goto out;
	}

	if ((ret = (rrr_websocket_transport_ctx_read_frames (
			handle,
			&session->ws_state,
			100,
			4096,
			65535,
			read_max_size,
			__rrr_http_session_websocket_frame_callback,
			&callback_data
	)) & ~(RRR_NET_TRANSPORT_READ_INCOMPLETE)) != 0) {
		goto out;
	}

	out:
	return ret;
}

#ifdef RRR_WITH_NGHTTP2
struct rrr_http_session_http2_get_response_callback_data {
	struct rrr_net_transport_handle *handle;
	int (*get_raw_response_callback)(RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS);
	void *get_raw_response_callback_arg;
	int (*get_response_callback)(RRR_HTTP_SESSION_HTTP2_RECEIVE_CALLBACK_ARGS);
	void *get_response_callback_arg;
};

static int __rrr_http_session_http2_get_response (RRR_HTTP2_GET_RESPONSE_CALLBACK_ARGS) {
	struct rrr_http_session_http2_get_response_callback_data *callback_data = callback_arg;

	(void)(session);
	(void)(stream_id);

	int ret = 0;

	struct rrr_http_part *response_part = NULL;

	if (callback_data->get_raw_response_callback != NULL) {
		if ((ret = callback_data->get_raw_response_callback (
				data,
				data_size,
				stream_application_id,
				callback_data->get_raw_response_callback_arg
		)) != 0) {
			goto out;
		}
	}

	if (callback_data->get_response_callback != NULL) {
		if ((ret = rrr_http_part_new(&response_part)) != 0) {
			goto out;
		}

		if ((ret = callback_data->get_response_callback (
				callback_data->handle,
				stream_application_data,
				response_part,
				data,
				data_size,
				callback_data->get_response_callback_arg,
				stream_application_id
		)) != 0) {
			goto out;
		}
	}

	out:
	if (response_part != NULL) {
		rrr_http_part_destroy(response_part);
	}
	return ret;
}

int rrr_http_session_transport_ctx_http2_tick (
		struct rrr_net_transport_handle *handle,
		int (*get_raw_response_callback)(RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS),
		void *get_raw_response_callback_arg,
		int (*get_response_callback)(RRR_HTTP_SESSION_HTTP2_RECEIVE_CALLBACK_ARGS),
		void *get_response_callback_arg
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	if (session->http2_session == NULL) {
		return RRR_HTTP_SOFT_ERROR;
	}

	struct rrr_http_session_http2_get_response_callback_data callback_data = {
			handle,
			get_raw_response_callback,
			get_raw_response_callback_arg,
			get_response_callback,
			get_response_callback_arg
	};

	return rrr_http2_transport_ctx_tick (
			session->http2_session,
			handle,
			__rrr_http_session_http2_get_response,
			&callback_data
	);
}

void rrr_http_session_get_http2_alpn_protos (
		const char **target,
		unsigned int *length
) {
	*target = rrr_http_session_alpn_protos_http2_priority;
	*length = sizeof(rrr_http_session_alpn_protos_http2_priority);
}
#endif /* RRR_WITH_NGHTTP2 */

int rrr_http_session_transport_ctx_close_if_open (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_session *session = handle->application_private_ptr;

	(void)(arg);

#ifdef RRR_WITH_NGHTTP2
	if (session != NULL && session->http2_session != NULL) {
		rrr_http2_transport_ctx_terminate(session->http2_session, handle);
	}
#else
	(void)(session);
#endif /* RRR_WITH_NGHTTP2 */
	return 0; // Always return 0
}
