
/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <nghttp2/nghttp2.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "http2.h"
#include "../log.h"
#include "../rrr_inttypes.h"
#include "../net_transport/net_transport.h"
#include "../util/macro_utils.h"
#include "../util/base64.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../http/http_common.h"
#include "../http/http_header_fields.h"

#define RRR_HTTP2_PING_INTERVAL_S 1

struct rrr_http2_stream {
	RRR_LL_NODE(struct rrr_http2_stream);
	int please_delete_me;
	struct rrr_http_header_field_collection headers;
	int32_t stream_id;
	void *data;
	size_t data_size;
	size_t data_wpos;
	void *application_data;
	void (*application_data_destroy_function)(void *);
};

struct rrr_http2_stream_collection {
	RRR_LL_HEAD(struct rrr_http2_stream);
};

struct rrr_http2_session;

struct rrr_http2_callback_data {
	struct rrr_net_transport_handle *handle;
	// Callback may be NULL
	int (*callback)(RRR_HTTP2_GET_RESPONSE_CALLBACK_ARGS);
	void *callback_arg;
};

struct rrr_http2_session {
	nghttp2_session *session;
	void *initial_receive_data;
	size_t initial_receive_data_len;
	struct rrr_http2_stream_collection streams;
	// Must be updated on every tick
	struct rrr_http2_callback_data callback_data;
	uint64_t last_ping_time;
};

void __rrr_http2_stream_destroy (
		struct rrr_http2_stream *stream
) {
	rrr_http_header_field_collection_clear(&stream->headers);
	if (stream->application_data != NULL) {
		stream->application_data_destroy_function(stream->application_data);
	}
	RRR_FREE_IF_NOT_NULL(stream->data);
	free(stream);
}

void __rrr_http2_stream_collection_destroy (
		struct rrr_http2_stream_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_http2_stream, __rrr_http2_stream_destroy(node));
}

struct rrr_http2_stream *__rrr_http2_stream_collection_maintain_and_find_or_create (
		struct rrr_http2_stream_collection *collection,
		int32_t stream_id
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_http2_stream);
		if (node->please_delete_me) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->stream_id == stream_id) {
			return node;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; __rrr_http2_stream_destroy(node));

	struct rrr_http2_stream *new_stream = malloc(sizeof(*new_stream));
	if (new_stream == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http2_stream_collection_maintain_and_find_or_create\n");
		return NULL;
	}
	memset(new_stream, '\0', sizeof(*new_stream));
	new_stream->stream_id = stream_id;

	RRR_LL_PUSH(collection, new_stream);

	return new_stream;
}

int __rrr_http2_stream_collection_data_push (
		struct rrr_http2_stream_collection *collection,
		int32_t stream_id,
		const char *data,
		size_t data_size
) {
	int ret = 0;

	struct rrr_http2_stream *target = __rrr_http2_stream_collection_maintain_and_find_or_create(collection, stream_id);
	if (target == NULL) {
		ret = RRR_HTTP2_HARD_ERROR;
		goto out;
	}

	if (data_size == 0) {
		goto out;
	}

	if (target->data_wpos + data_size > target->data_size) {
		size_t new_size = target->data_size + data_size + 65536;
		void *data_new = realloc(target->data, new_size);
		if (data_new == NULL) {
			RRR_MSG_0("Could not allocate memory for data in __rrr_http2_stream_collection_data_push\n");
			ret = RRR_HTTP2_HARD_ERROR;
			goto out;
		}
		target->data_size = new_size;
		target->data = data_new;
	}

	memcpy(target->data + target->data_wpos, data, data_size);
	target->data_wpos += data_size;

	out:
	return ret;
}

static ssize_t __rrr_http2_send_callback (
		nghttp2_session *nghttp2_session,
		const uint8_t *data,
		size_t length,
		int flags,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	if (length > SSIZE_MAX) {
		// Truncate
		length = SSIZE_MAX;
	}

	printf("send %u\n", length);

	uint64_t bytes_written = 0;
	int ret = 0;
	if ((ret = rrr_net_transport_ctx_send_nonblock(&bytes_written, session->callback_data.handle, data, length)) != 0) {
		ret &= ~(RRR_NET_TRANSPORT_SEND_INCOMPLETE);
		if (ret & RRR_NET_TRANSPORT_READ_READ_EOF) {
			RRR_DBG_3("http2 EOF while sending\n");
			return NGHTTP2_ERR_EOF;
		}
		else if (ret != 0) {
			RRR_DBG_3("http2 send failed with error %i\n", ret);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}

	if (bytes_written > SSIZE_MAX) {
		RRR_BUG("BUG: Bytes written exceeds SSIZE_MAX in __rrr_http2_send_callback, this should not be possible\n");
	}

	return (bytes_written > 0 ? bytes_written : NGHTTP2_ERR_WOULDBLOCK);
}

static ssize_t __rrr_http2_recv_callback (
		nghttp2_session *nghttp2_session,
		uint8_t *buf,
		size_t length,
		int flags,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

//	This does not handle situations where the server stops replying and we have nothing to send
//	if (rrr_net_transport_ctx_check_alive(session->callback_data.handle) != RRR_NET_TRANSPORT_READ_OK) {
//		return NGHTTP2_ERR_EOF;
//	}

	if (length > SSIZE_MAX) {
		// Truncate to fit in function return value
		length = SSIZE_MAX;
	}

	uint64_t bytes_read = 0;
	int ret = 0;
	if ((ret = rrr_net_transport_ctx_read(&bytes_read, session->callback_data.handle, (char *) buf, length)) != 0) {
		ret &= ~(RRR_NET_TRANSPORT_SEND_INCOMPLETE);
		if (ret & RRR_NET_TRANSPORT_READ_READ_EOF) {
			RRR_DBG_3("http2 EOF while sending\n");
			return NGHTTP2_ERR_EOF;
		}
		else if (ret != 0) {
			RRR_DBG_3("http2 recv failed with error %i\n", ret);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}

	if (bytes_read > SSIZE_MAX) {
		RRR_BUG("BUG: Bytes written exceeds SSIZE_MAX in __rrr_http2_recv_callback, this should not be possible\n");
	}

	printf("recv %u\n", bytes_read);

	return (bytes_read > 0 ? bytes_read : NGHTTP2_ERR_WOULDBLOCK);
}

static int __rrr_http2_on_data_chunk_recv_callback (
		nghttp2_session *nghttp2_session,
		uint8_t flags,
		int32_t stream_id,
		const uint8_t *data,
		size_t len,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;
	(void)(flags);

	RRR_DBG_7 ("http2 recv chunk stream %" PRIi32 " size %llu\n", stream_id, (unsigned long long) len);

	if (__rrr_http2_stream_collection_data_push(&session->streams, stream_id, (const char *) data, len) != 0) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
/*
	struct Request *req;
	if ((req = nghttp2_session_get_stream_user_data(nghttp2_session, stream_id))) {
		RRR_DBG_7("[INFO] C <---------------------------- S (DATA chunk)\n%lu bytes\n",
				(unsigned long int) len);
		fwrite(data, 1, len, stdout);
		RRR_DBG_7("\n");
	}
*/
	return 0;
}

static int __rrr_http2_on_stream_close_callback (
		nghttp2_session *nghttp2_session,
		int32_t stream_id,
		uint32_t error_code,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	RRR_DBG_7 ("http2 close stream %" PRIi32 ": %s\n", stream_id, nghttp2_http2_strerror(error_code));

	struct rrr_http2_stream *stream = __rrr_http2_stream_collection_maintain_and_find_or_create(&session->streams, stream_id);
	if (stream->data != NULL) {
		if (error_code == 0) {
			if (session->callback_data.callback != NULL) {
				if (session->callback_data.callback (
						session,
						&stream->headers,
						stream_id,
						stream->data,
						stream->data_wpos,
						stream->application_data,
						session->callback_data.callback_arg
				) != 0) {
					return NGHTTP2_ERR_CALLBACK_FAILURE;
				}
			}
		}
		stream->please_delete_me = 1;
	}

	return 0;
}

static int __rrr_http2_on_frame_recv_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	RRR_DBG_7 ("http2 read frame type %" PRIu8 " stream %" PRIi32 " length %lu\n", frame->hd.type, frame->hd.stream_id, frame->hd.length);

	(void)(session);

	return 0;
}

static int __rrr_http2_on_invalid_frame_recv_callback (
		nghttp2_session *session,
		const nghttp2_frame *frame,
		int lib_error_code,
		void *user_data
) {
	RRR_DBG_7 ("http2 read invalid frame type %" PRIu8 " stream %" PRIi32 " length %lu lib error %s\n",
			frame->hd.type, frame->hd.stream_id, frame->hd.length, nghttp2_strerror(lib_error_code));

	return 0;
}

static int __rrr_http2_on_header_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		const uint8_t *name,
		size_t namelen,
		const uint8_t *value,
		size_t valuelen,
		uint8_t flags,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(namelen);

	struct rrr_http2_stream *stream = __rrr_http2_stream_collection_maintain_and_find_or_create(&session->streams, frame->hd.stream_id);
	if (stream == NULL) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	RRR_DBG_3("Received HTTP2 header %s=%s\n", name, value);

	ssize_t parsed_bytes = 0;
	if (rrr_http_header_field_parse_value(&stream->headers, &parsed_bytes, name, value) != 0) {
		RRR_MSG_0("HTTP2 header field parsing of field '%s' failed, parsed %lli of %llu bytes\n",
				name, (long long int) parsed_bytes, (unsigned long long int) valuelen);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int __rrr_http2_on_begin_headers_callback(
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(session);

	printf("header begin: %i\n", frame->hd.type);

	return 0;
}

static int __rrr_http2_error_callback(
		nghttp2_session *session,
		const char *msg,
        size_t len,
		void *user_data
) {
	(void)(session);
	(void)(len);
	(void)(user_data);

	printf("nghttp2 error: %s\n", msg);

	return 0;
}

int rrr_http2_session_client_new_or_reset (
		struct rrr_http2_session **target,
		void **initial_receive_data,
		size_t initial_receive_data_len
) {
	int ret = 0;

	struct rrr_http2_session *result = NULL;
	nghttp2_session_callbacks *callbacks = NULL;

	result = *target;
	*target = NULL;

	if (nghttp2_session_callbacks_new(&callbacks) != 0) {
		RRR_MSG_0("Could not create callbacks object in rrr_http2_session_new_or_reset\n");
		ret = 1;
		goto out;
	}

	nghttp2_session_callbacks_set_send_callback					(callbacks, __rrr_http2_send_callback);
	nghttp2_session_callbacks_set_recv_callback					(callbacks, __rrr_http2_recv_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback	(callbacks, __rrr_http2_on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback		(callbacks, __rrr_http2_on_stream_close_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback		(callbacks, __rrr_http2_on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks, __rrr_http2_on_invalid_frame_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback			(callbacks, __rrr_http2_on_header_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback		(callbacks, __rrr_http2_on_begin_headers_callback);
	nghttp2_session_callbacks_set_error_callback 				(callbacks, __rrr_http2_error_callback);

	if (result == NULL) {
		if ((result = malloc(sizeof(*result))) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http2_session_new_or_reset\n");
			goto out;
		}
		memset(result, '\0', sizeof(*result));
	}

	if (result->session != NULL) {
		nghttp2_session_del(result->session);
		result->session = NULL;
	}

	if (nghttp2_session_client_new(&result->session, callbacks, result) != 0) {
		RRR_MSG_0("Could not allocate nghttp2 session in rrr_http2_session_new_or_reset\n");
		ret = 1;
		goto out_free;
	}

	if (initial_receive_data != NULL && *initial_receive_data != NULL) {
		result->initial_receive_data = *initial_receive_data;
		result->initial_receive_data_len = initial_receive_data_len;
		*initial_receive_data = NULL;
	}

	result->last_ping_time = rrr_time_get_64();

	*target = result;

	goto out;
	out_destroy_session:
		nghttp2_session_del(result->session);
	out_free:
		free(result);
	out:
		if (callbacks != NULL) {
			nghttp2_session_callbacks_del(callbacks);
		}
		return ret;
}

void rrr_http2_session_destroy_if_not_null (
		struct rrr_http2_session **target
) {
	if (*target == NULL) {
		return;
	}
	if ((*target)->session != NULL) {
		nghttp2_session_del((*target)->session);
	}
	__rrr_http2_stream_collection_destroy(&(*target)->streams);
	RRR_FREE_IF_NOT_NULL((*target)->initial_receive_data);
	free(*target);
	*target = NULL;
}

int rrr_http2_session_stream_application_data_set (
		struct rrr_http2_session *session,
		int32_t stream_id,
		void *application_data,
		void (*application_data_destroy_function)(void *)
) {
	struct rrr_http2_stream *stream = __rrr_http2_stream_collection_maintain_and_find_or_create(&session->streams, stream_id);
	if (stream == NULL) {
		return RRR_HTTP2_HARD_ERROR;
	}

	if (stream->application_data != NULL) {
		stream->application_data_destroy_function(stream->application_data);
	}

	stream->application_data = application_data;
	stream->application_data_destroy_function = application_data_destroy_function;

	return RRR_HTTP2_OK;
}

void *rrr_http2_session_stream_application_data_get (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	struct rrr_http2_stream *stream = __rrr_http2_stream_collection_maintain_and_find_or_create(&session->streams, stream_id);
	if (stream == NULL) {
		return NULL;
	}

	return stream->application_data;
}

int rrr_http2_session_client_upgrade_postprocess (
		struct rrr_http2_session *session,
		const void *upgrade_settings,
		size_t upgrade_settings_len
) {
	int ret = 0;

	if ((ret = nghttp2_session_upgrade2 (
			session->session,
			upgrade_settings,
			upgrade_settings_len,
			0,   // Not head request
			NULL // No stream user data
	)) != 0) {
		RRR_MSG_0("Could not perform http2 upgrade postprocessing inrrr_http2_client_upgrade_postprocess ");
		ret = RRR_HTTP2_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_http2_session_client_native_start (
		struct rrr_http2_session *session
) {
	int ret = 0;

	nghttp2_settings_entry vector[] = {
			{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
	};

	/* client 24 bytes magic string will be sent by nghttp2 library */
	if ((ret = nghttp2_submit_settings (
			session->session,
			NGHTTP2_FLAG_NONE,
			vector,
			sizeof(vector) / sizeof(*vector)
	)) != 0) {
		RRR_MSG_0("Failed to submit HTTP2 settings when starting native client: %s", nghttp2_strerror(ret));
		ret = RRR_HTTP2_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

#define MAKE_NV(name, value)			\
{										\
    (uint8_t *) name,					\
	(uint8_t *) value,					\
	sizeof(name) - 1,					\
	strlen(value),						\
    NGHTTP2_NV_FLAG_NONE                \
}

int rrr_http2_request_submit (
		struct rrr_http2_session *session,
		int is_https,
		enum rrr_http_method method,
		const char *host,
		const char *endpoint
) {
	int ret = 0;

	const char *scheme = (is_https ? "https" : "http");

	nghttp2_nv headers[] = {
		MAKE_NV(":method", RRR_HTTP_METHOD_TO_STR_CONFORMING(method)),
		MAKE_NV(":scheme", scheme),
		MAKE_NV(":authority", host),
		MAKE_NV(":path", endpoint)
	};

	uint32_t stream_id = nghttp2_submit_request (
			session->session,
			NULL,
			headers,
			sizeof(headers) / sizeof(*headers),
			NULL,
			NULL
	);

	if (stream_id < 0) {
		RRR_MSG_0 ("HTTP2 request submission failed: %s", nghttp2_strerror(stream_id));
		ret = RRR_HTTP2_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_http2_transport_ctx_tick (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle,
		int (*callback)(RRR_HTTP2_GET_RESPONSE_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = RRR_HTTP2_DONE;

	// Always update callback data. Persistent user_data pointer was set in the
	// new() function
	struct rrr_http2_callback_data callback_data = {
			handle,
			callback,
			callback_arg
	};
	session->callback_data = callback_data;

	// Parse any overshoot data from HTTP/1.1 parsing
	if (session->initial_receive_data != NULL) {
		size_t send_bytes = session->initial_receive_data_len;
		const void *send_pos = session->initial_receive_data;
		while (send_bytes) {
			ssize_t bytes = nghttp2_session_mem_recv(session->session, send_pos, send_bytes);
			if (bytes < 0) {
				RRR_MSG_0("Error from nghttp2_session_mem_recv in rrr_http2_tick: %s\n", nghttp2_strerror(bytes));
				ret = RRR_HTTP2_HARD_ERROR;
				goto out;
			}
			if (bytes > send_bytes) {
				RRR_MSG_0("Value returned from nghttp2_session_mem_recv was too high in rrr_http2_tick, possible bug\n");
				ret = RRR_HTTP2_HARD_ERROR;
				goto out;
			}
			send_bytes -= bytes;
			send_pos += bytes;
		}
		RRR_FREE_IF_NOT_NULL(session->initial_receive_data);
		session->initial_receive_data_len = 0;
	}

	// Send PINGs to get feedbacks should the socket break down
	// while we have nothing else to send
	if (rrr_time_get_64() - session->last_ping_time > RRR_HTTP2_PING_INTERVAL_S * 1000 * 1000) {
		session->last_ping_time = rrr_time_get_64();
		if ((ret = nghttp2_submit_ping(session->session, NGHTTP2_FLAG_NONE, NULL)) != 0) {
			RRR_MSG_0("Error from nghttp2_submit_ping in rrr_http2_tick: %s\n", nghttp2_strerror(ret));
			ret = RRR_HTTP2_SOFT_ERROR;
			goto out;
		}
	}

	printf ("WR: %i, WW %i\n", nghttp2_session_want_read(session->session), nghttp2_session_want_write(session->session));

	if (nghttp2_session_want_read(session->session) == 0 && nghttp2_session_want_write(session->session) == 0) {
		RRR_DBG_7("http2 done\n");
		ret = RRR_HTTP2_DONE;
		goto out;
	}

	if ((ret = nghttp2_session_send(session->session)) != 0) {
		RRR_DBG_3("Error from nghttp2 send: %s\n", nghttp2_strerror(ret));
		ret = (ret == NGHTTP2_ERR_EOF ? RRR_HTTP2_DONE : RRR_HTTP2_SOFT_ERROR);
		goto out;
	}

	if ((ret = nghttp2_session_recv(session->session)) != 0) {
		RRR_DBG_3("Error from nghttp2 recv: %s\n", nghttp2_strerror(ret));
		ret = (ret == NGHTTP2_ERR_EOF ? RRR_HTTP2_DONE : RRR_HTTP2_SOFT_ERROR);
		goto out;
	}

	out:
	return ret;
}

void rrr_http2_transport_ctx_terminate (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle
) {
	struct rrr_http2_callback_data callback_data = {
			handle,
			NULL,
			NULL
	};
	session->callback_data = callback_data;

	nghttp2_session_terminate_session(session->session, 0);
}

int rrr_http2_pack_upgrade_request_settings (
		char **target
) {
	*target = NULL;

	uint8_t payload[128];
	ssize_t payload_size = 0;

	nghttp2_settings_entry iv[2];

	iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
	iv[0].value = NGHTTP2_DEFAULT_HEADER_TABLE_SIZE;

	iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
	iv[1].value = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;

	if ((payload_size = nghttp2_pack_settings_payload (payload, sizeof(payload), iv, sizeof(iv) / sizeof(*iv))) <= 0) {
		RRR_MSG_0("Could not pack SETTINGS packet in rrr_http2_pack_upgrade_request_settings, return was %li\n", payload_size);
		return 1;
	}

	size_t result_length = 0;
	unsigned char *result = rrr_base64url_encode((unsigned char *) payload, payload_size, &result_length);

	if (result == NULL) {
		RRR_MSG_0("Base64url encoding failed in rrr_http2_pack_upgrade_request_settings\n");
		return 1;
	}

	*target = result;

	return 0;
}

int rrr_http2_select_next_protocol (
		const unsigned char **out,
		unsigned char *outlen,
		const unsigned char *in,
		unsigned int inlen
) {
	int ret = nghttp2_select_next_protocol((unsigned char **) out, outlen, in, inlen);
	if (ret == 0) {
		RRR_DBG_3("Note: HTTP2 not available, HTTP/1.1 selected\n");
	}
	else if (ret < 0) {
		RRR_DBG_3("Note: Neither HTTP/1.1 nor HTTP/2 advertised in TLS protocol list from remote\n");
		return RRR_HTTP2_SOFT_ERROR;
	}
	RRR_DBG_3("HTTP/2 selected by NPN/ALPN\n");
	return RRR_HTTP2_OK;
}
