
/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#include "../log.h"
#include "../allocator.h"
#include "http2.h"
#include "../rrr_inttypes.h"
#include "../net_transport/net_transport.h"
#include "../util/macro_utils.h"
#include "../util/base64.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../http/http_common.h"
#include "../http/http_header_fields.h"
#include "../map.h"

// The actual ping and maintenance interval will depend on how often the tick function is called
#define RRR_HTTP2_PING_MAINTENANCE_INTERVAL_S 1

struct rrr_http2_stream {
	RRR_LL_NODE(struct rrr_http2_stream);
	struct rrr_http_header_field_collection headers;
	void *data;
	size_t data_size;
	size_t data_wpos;
	void *application_data;

	// Submit data frame on next before_frame_send_callback
	int data_submission_requested;

	void (*application_data_destroy_function)(void *);
	struct rrr_map headers_to_send;

	uint64_t creation_time;
};

struct rrr_http2_stream_collection {
	struct rrr_http2_stream streams[RRR_HTTP2_STREAM_BLOCKS * 64];
	int32_t stream_ids[RRR_HTTP2_STREAM_BLOCKS * 64];
	uint64_t active_flags[RRR_HTTP2_STREAM_BLOCKS];
	uint64_t delete_me_flags[RRR_HTTP2_STREAM_BLOCKS];
	uint32_t stream_count;
};

struct rrr_http2_session;

struct rrr_http2_callback_data {
	struct rrr_net_transport_handle *handle;
	// Callback may be NULL
	int (*callback)(RRR_HTTP2_DATA_RECEIVE_CALLBACK_ARGS);
	int (*data_source_callback)(RRR_HTTP2_DATA_SOURCE_CALLBACK_ARGS);
	void *callback_arg;
};

struct rrr_http2_session {
	nghttp2_session *session;
	void *initial_receive_data;
	ssize_t initial_receive_data_len;
	struct rrr_http2_stream_collection streams;
	// Must be updated on every tick
	struct rrr_http2_callback_data callback_data;
	uint64_t last_ping_send_time;
	uint64_t last_ping_receive_time;
	uint64_t closed_stream_count;
};

#define RRR_HTTP2_STREAM_GROUP(idx) \
	((idx & 0xffffffffffffffc0) >> 6)

#define RRR_HTTP2_STREAM_MASK(idx) \
	((uint64_t) 1 << idx)

#define RRR_HTTP2_STREAMS_ITERATE_BEGIN()                                         \
	do { for (uint64_t i = 0; i < RRR_HTTP2_STREAM_BLOCKS * 64; i++) {        \
		uint64_t group = RRR_HTTP2_STREAM_GROUP(i);                       \
		uint64_t mask = RRR_HTTP2_STREAM_MASK(i);                         \
		struct rrr_http2_stream *node = &collection->streams[i];          \
		(void)(group); (void)(mask); (void)(node)

#define RRR_HTTP2_STREAMS_ITERATE_DELETE_ME_BEGIN()                               \
	RRR_HTTP2_STREAMS_ITERATE_BEGIN();                                        \
		if ((collection->delete_me_flags[group] & mask) != 0) {           \

#define RRR_HTTP2_STREAMS_ITERATE_ACTIVE_BEGIN()                                  \
	RRR_HTTP2_STREAMS_ITERATE_BEGIN();                                        \
		if ((collection->active_flags[group] & mask) != 0) {              \

#define RRR_HTTP2_STREAMS_ITERATE_INACTIVE_BEGIN()                                \
	RRR_HTTP2_STREAMS_ITERATE_BEGIN();                                        \
		if ((collection->active_flags[group] & mask) == 0) {              \

#define RRR_HTTP2_STREAMS_ITERATE_END() \
	}}} while(0)

int __rrr_http2_stream_reset (
		struct rrr_http2_stream_collection *collection,
		uint64_t index
) {
	struct rrr_http2_stream *stream = &collection->streams[index];
	rrr_http_header_field_collection_clear(&stream->headers);
	if (stream->application_data != NULL) {
		stream->application_data_destroy_function(stream->application_data);
	}
	RRR_FREE_IF_NOT_NULL(stream->data);
	rrr_map_clear(&stream->headers_to_send);
	memset(stream, '\0', sizeof(*stream));

	collection->active_flags[RRR_HTTP2_STREAM_GROUP(index)] &= ~RRR_HTTP2_STREAM_MASK(index);
	collection->delete_me_flags[RRR_HTTP2_STREAM_GROUP(index)] &= ~RRR_HTTP2_STREAM_MASK(index);
	collection->stream_ids[index] = 0;
	collection->stream_count--;

	return 0;
}

void __rrr_http2_stream_collection_destroy (
		struct rrr_http2_stream_collection *collection
) {
	if (RRR_DEBUGLEVEL_3) {
		// This is useful to detect usage of invalid stream IDs. There
		// is no checks when for instance header fields are pushed if a
		// stream ID is correct and will actually be sent.
		RRR_HTTP2_STREAMS_ITERATE_ACTIVE_BEGIN();
			uint64_t age_ms = (rrr_time_get_64() - node->creation_time) / 1000;
			RRR_DBG_3("http2 stream id %i late destroy (upon collection destruction), age is %" PRIu64 "ms\n",
					collection->stream_ids[i], age_ms);
		RRR_HTTP2_STREAMS_ITERATE_END();
	}
	RRR_HTTP2_STREAMS_ITERATE_ACTIVE_BEGIN();
		__rrr_http2_stream_reset(collection, i);
	RRR_HTTP2_STREAMS_ITERATE_END();
}

void __rrr_http2_streams_maintain (
		struct rrr_http2_session *session
) {
	struct rrr_http2_stream_collection *collection = &session->streams;

	RRR_HTTP2_STREAMS_ITERATE_DELETE_ME_BEGIN();
		session->closed_stream_count++;
		__rrr_http2_stream_reset(collection, i);
	RRR_HTTP2_STREAMS_ITERATE_END();
}

void __rrr_http2_stream_delete_me_set (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	struct rrr_http2_stream_collection *collection = &session->streams;

	RRR_HTTP2_STREAMS_ITERATE_ACTIVE_BEGIN();
		if (session->streams.stream_ids[i] == stream_id) {
			session->streams.delete_me_flags[RRR_HTTP2_STREAM_GROUP(i)] |= RRR_HTTP2_STREAM_MASK(i);
			break;
		}
	RRR_HTTP2_STREAMS_ITERATE_END();
}

struct rrr_http2_stream *__rrr_http2_stream_find (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	struct rrr_http2_stream_collection *collection = &session->streams;

	RRR_HTTP2_STREAMS_ITERATE_ACTIVE_BEGIN();
		if (session->streams.stream_ids[i] == stream_id) {
			return &session->streams.streams[i];
		}
	RRR_HTTP2_STREAMS_ITERATE_END();

	return NULL;
}

struct rrr_http2_stream *__rrr_http2_stream_find_or_create (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	struct rrr_http2_stream_collection *collection = &session->streams;
	struct rrr_http2_stream *old_stream = __rrr_http2_stream_find (session, stream_id);
	if (old_stream != NULL) {
		return old_stream;
	}

	int all_set = 1;
	for (uint64_t i = 0; i < RRR_HTTP2_STREAM_BLOCKS; i++) {
		if (session->streams.active_flags[i] != UINT64_MAX) {
			all_set = 0;
			break;
		}
	}

	if (all_set) {
		return NULL;
	}

	RRR_HTTP2_STREAMS_ITERATE_INACTIVE_BEGIN();
		node->creation_time = rrr_time_get_64();

		collection->active_flags[group] |= mask;
		collection->stream_ids[i] = stream_id;
		collection->stream_count++;

		return node;
	RRR_HTTP2_STREAMS_ITERATE_END();

	RRR_BUG("BUG: Flag error in __rrr_http2_stream_find_or_create\n");

	return NULL;;
}

int __rrr_http2_stream_data_push (
		struct rrr_http2_stream *target,
		const char *data,
		size_t data_size
) {
	int ret = 0;

	if (data_size == 0) {
		goto out;
	}

	if (target->data_wpos + data_size > target->data_size) {
		size_t new_size = target->data_size + data_size + 65536;
		void *data_new = rrr_reallocate(target->data, target->data_size, new_size);
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

	(void)(nghttp2_session);
	(void)(flags);

	if (length > SSIZE_MAX) {
		// Truncate
		length = SSIZE_MAX;
	}

	// TODO : Maybe event framework can send from nghttp2 directly instead of copying data to net transport first

	int ret = 0;
	if ((ret = rrr_net_transport_ctx_send_push_const (session->callback_data.handle, data, length)) != 0) {
		RRR_DBG_3("http2 send push failed with error %i\n", ret);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return length;
}

static ssize_t __rrr_http2_recv_callback (
		nghttp2_session *nghttp2_session,
		uint8_t *buf,
		size_t length,
		int flags,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(nghttp2_session);
	(void)(flags);

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

	return (bytes_read > 0 ? (ssize_t) bytes_read : NGHTTP2_ERR_WOULDBLOCK);
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

	(void)(nghttp2_session);
	(void)(flags);

	RRR_DBG_7 ("http2 recv chunk stream %" PRIi32 " size %llu\n", stream_id, (unsigned long long) len);

	struct rrr_http2_stream *stream = __rrr_http2_stream_find(session, stream_id);
	if (stream == NULL) {
		RRR_DBG_7("http2 unknown stream %u in data frame\n", stream_id);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (__rrr_http2_stream_data_push(stream, (const char *) data, len) != 0) {
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

	int ret = 0;

	(void)(nghttp2_session);

	RRR_DBG_7 ("http2 close stream %" PRIi32 ": %s\n", stream_id, nghttp2_http2_strerror(error_code));

	struct rrr_http2_stream *stream = __rrr_http2_stream_find(session, stream_id);
	__rrr_http2_stream_delete_me_set(session, stream_id);

	if (session->callback_data.callback != NULL) {
		if (session->callback_data.callback (
				session,
				&stream->headers,
				stream_id,
				0,
				0,
				1, // Is stream close
				stream->data,
				stream->data_wpos,
				stream->application_data,
				session->callback_data.callback_arg
		) != 0) {
			ret = NGHTTP2_ERR_CALLBACK_FAILURE;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_http2_on_frame_send_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(session);
	(void)(nghttp2_session);

	RRR_DBG_7 ("http2 send frame type %" PRIu8 " stream %" PRIi32 " length %lu\n", frame->hd.type, frame->hd.stream_id, frame->hd.length);

	return 0;
}

static int __rrr_http2_on_frame_recv_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(session);
	(void)(nghttp2_session);

	RRR_DBG_7 ("http2 read frame type %" PRIu8 " stream %" PRIi32 " length %lu\n", frame->hd.type, frame->hd.stream_id, frame->hd.length);

	if (frame->hd.type == NGHTTP2_PING) {
		session->last_ping_receive_time = rrr_time_get_64();
		return 0;
	}
	else if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) {
		return 0;
	}

	struct rrr_http2_stream *stream = __rrr_http2_stream_find(session, frame->hd.stream_id);
	if (stream == NULL) {
		RRR_DBG_7("http2 unknown stream %u in frame\n", frame->hd.stream_id);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if ((frame->hd.flags & (NGHTTP2_FLAG_END_HEADERS|NGHTTP2_FLAG_END_STREAM)) && session->callback_data.callback != NULL) {
		if (session->callback_data.callback (
				session,
				&stream->headers,
				frame->hd.stream_id,
				(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) != 0,
				(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0,
				0, // Is not stream close
				stream->data,
				stream->data_wpos,
				stream->application_data,
				session->callback_data.callback_arg
		) != 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int __rrr_http2_on_invalid_frame_recv_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		int lib_error_code,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(session);
	(void)(nghttp2_session);

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

	(void)(nghttp2_session);
	(void)(namelen);
	(void)(flags);

	struct rrr_http2_stream *stream;

	int retries = 1;
	do {
		stream = __rrr_http2_stream_find_or_create(session, frame->hd.stream_id);
		if (stream != NULL) {
			break;
		}
		__rrr_http2_streams_maintain(session);
	} while (retries--);

	if (stream == NULL) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	RRR_DBG_3("Received HTTP2 header %s=%s\n", name, value);

	ssize_t parsed_bytes = 0;
	if (rrr_http_header_field_parse_value(&stream->headers, &parsed_bytes, (const char *) name, (const char *) value) != 0) {
		RRR_MSG_0("HTTP2 header field parsing of field '%s' failed, parsed %lli of %llu bytes\n",
				name, (long long int) parsed_bytes, (unsigned long long int) valuelen);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int __rrr_http2_on_begin_headers_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(nghttp2_session);
	(void)(frame);
	(void)(session);

	RRR_DBG_7("nghttp2 begin headers\n");

	return 0;
}

static int __rrr_http2_error_callback (
		nghttp2_session *session,
		const char *msg,
        size_t len,
		void *user_data
) {
	(void)(session);
	(void)(len);
	(void)(user_data);
	(void)(msg);

	RRR_DBG_7("nghttp2 error: %s\n", msg);

	return 0;
}

// Library documents that length is no more than 16KiB
static ssize_t __rrr_http2_data_source_read_callback (
		nghttp2_session *nghttp2_session,
		int32_t stream_id,
		uint8_t *buf,
		size_t length,
		uint32_t *data_flags,
		nghttp2_data_source *source,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(nghttp2_session);
	(void)(source);

	rrr_length bytes_written = 0;
	*data_flags = 0;

	int done = 0;
	if (session->callback_data.data_source_callback (
			&done,
			&bytes_written,
			buf,
			length,
			stream_id,
			session->callback_data.callback_arg
	) != 0) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (done) {
		*data_flags = NGHTTP2_DATA_FLAG_EOF;
	}

	return bytes_written;
}

static int __rrr_http2_data_submit_if_needed (
		struct rrr_http2_session *session,
		struct rrr_http2_stream *stream,
		uint32_t stream_id
) {
	int ret = 0;

	if (!stream->data_submission_requested) {
		goto out;
	}
	stream->data_submission_requested = 0;

	nghttp2_data_provider data_provider = {
			{ 0 },
			__rrr_http2_data_source_read_callback
	};

	// Note that the final source read callback is set in the tick() function

	if ((ret = nghttp2_submit_data(session->session, NGHTTP2_FLAG_END_STREAM, stream_id, &data_provider)) != 0) {
		RRR_MSG_0 ("HTTP2 data submission failed: %s\n", nghttp2_strerror(ret));
		ret = RRR_HTTP2_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http2_before_frame_send_callback (
		nghttp2_session *nghttp2_session,
		const nghttp2_frame *frame,
		void *user_data
) {
	struct rrr_http2_session *session = user_data;

	(void)(nghttp2_session);

	int ret = 0;

	if (frame->hd.type != NGHTTP2_HEADERS) {
		goto out;
	}

	struct rrr_http2_stream *stream = __rrr_http2_stream_find(session, frame->hd.stream_id);
	if (stream == NULL) {
		RRR_DBG_7("http2 unknown stream %u in before_frame_send_callback\n", frame->hd.stream_id);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if ((ret = __rrr_http2_data_submit_if_needed(session, stream, frame->hd.stream_id)) != 0) {
		ret = NGHTTP2_ERR_CALLBACK_FAILURE;
		goto out;
	}

	out:
	return ret;
}

int rrr_http2_session_new_or_reset (
		struct rrr_http2_session **target,
		void **initial_receive_data,
		size_t initial_receive_data_len,
		int is_server
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
	nghttp2_session_callbacks_set_on_header_callback			(callbacks, __rrr_http2_on_header_callback);
	nghttp2_session_callbacks_set_before_frame_send_callback	(callbacks, __rrr_http2_before_frame_send_callback);

	if (RRR_DEBUGLEVEL_7) {
		nghttp2_session_callbacks_set_on_frame_send_callback		(callbacks, __rrr_http2_on_frame_send_callback);
		nghttp2_session_callbacks_set_on_begin_headers_callback		(callbacks, __rrr_http2_on_begin_headers_callback);
		nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks, __rrr_http2_on_invalid_frame_recv_callback);
		nghttp2_session_callbacks_set_error_callback 				(callbacks, __rrr_http2_error_callback);
	}

	if (result == NULL) {
		if ((result = rrr_allocate(sizeof(*result))) == NULL) {
			RRR_MSG_0("Could not allocate memory in rrr_http2_session_new_or_reset\n");
			goto out;
		}
		memset(result, '\0', sizeof(*result));
	}

	if (result->session != NULL) {
		nghttp2_session_del(result->session);
		result->session = NULL;
	}

	if (is_server) {
		if (nghttp2_session_server_new(&result->session, callbacks, result) != 0) {
			RRR_MSG_0("Could not allocate nghttp2 server session in rrr_http2_session_new_or_reset\n");
			ret = 1;
			goto out_free;
		}
	}
	else {
		if (nghttp2_session_client_new(&result->session, callbacks, result) != 0) {
			RRR_MSG_0("Could not allocate nghttp2 client session in rrr_http2_session_new_or_reset\n");
			ret = 1;
			goto out_free;
		}
	}

	if (initial_receive_data != NULL && *initial_receive_data != NULL) {
		if (initial_receive_data_len > SSIZE_MAX) {
			RRR_MSG_0("Initial receive data exceeds maximum in rrr_http2_session_new_or_reset\n");
			ret = 1;
			goto out_free;
		}

		result->initial_receive_data = *initial_receive_data;
		result->initial_receive_data_len = initial_receive_data_len;
		*initial_receive_data = NULL;
	}

	result->last_ping_send_time = result->last_ping_receive_time = rrr_time_get_64();

	*target = result;

	goto out;
//	out_destroy_session:
//		nghttp2_session_del(result->session);
	out_free:
		rrr_free(result);
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
	rrr_free(*target);
	*target = NULL;
}

int rrr_http2_session_stream_application_data_set (
		struct rrr_http2_session *session,
		int32_t stream_id,
		void *application_data,
		void (*application_data_destroy_function)(void *)
) {
	struct rrr_http2_stream *stream = __rrr_http2_stream_find_or_create(session, stream_id);
	if (stream == NULL) {
		return RRR_HTTP2_SOFT_ERROR;
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
	struct rrr_http2_stream *stream = __rrr_http2_stream_find_or_create(session, stream_id);
	if (stream == NULL) {
		return NULL;
	}

	return stream->application_data;
}

static int __rrr_http2_session_stream_header_push (
		struct rrr_http2_session *session,
		int32_t stream_id,
		const char *name,
		const char *value
) {
	struct rrr_http2_stream *stream = __rrr_http2_stream_find(session, stream_id);

	if (stream == NULL) {
		int ret_tmp = 0;
		int retries = 1;
		do {
			if (session->streams.stream_count < nghttp2_session_get_remote_settings(session->session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)) {
				ret_tmp = 0;
				break;
			}
			// Max number of streams (by remote) reached
			ret_tmp = RRR_HTTP2_BUSY;
			__rrr_http2_streams_maintain(session);
		} while (retries--);

		if (ret_tmp != 0) {
			return ret_tmp;
		}

		if ((stream = __rrr_http2_stream_find_or_create(session, stream_id)) == NULL) {
			// Max number of streams (local) reached
			return RRR_HTTP2_BUSY;
		}
	}

	return rrr_map_item_add_new(&stream->headers_to_send, name, value);
}

#define MAKE_NV(name, value)                                   \
{                                                              \
    (uint8_t *) name,                                          \
    (uint8_t *) value,                                         \
    strlen(name),                                              \
    strlen(value),                                             \
    NGHTTP2_NV_FLAG_NONE                                       \
}

static int __rrr_http2_session_stream_headers_submit (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	struct rrr_http2_stream *stream = __rrr_http2_stream_find_or_create(session, stream_id);
	if (stream == NULL) {
		RRR_BUG("BUG: Could not find stream id %u in __rrr_http2_session_stream_headers_submit\n", stream_id);
	}

	// Must hold stream ID
	int32_t ret = 0;

	nghttp2_nv *headers = NULL;

	const int header_count = RRR_MAP_COUNT(&stream->headers_to_send);

	if (header_count == 0) {
		goto out;
	}

	if ((headers = rrr_allocate(header_count * sizeof(*headers))) == NULL) {
		RRR_MSG_0("Could not allocate memory for headers in __rrr_http2_session_stream_headers_submit\n");
		ret = 1;
		goto out;
	}

	memset(headers, '\0', header_count * sizeof(*headers));

	int i = 0;
	RRR_MAP_ITERATE_BEGIN(&stream->headers_to_send);
		nghttp2_nv header = MAKE_NV(node_tag, node_value);
		headers[i] = header;
		i++;
	RRR_MAP_ITERATE_END();

	if ((ret = nghttp2_submit_headers (
			session->session,
			0,
			(stream_id == (int32_t) nghttp2_session_get_next_stream_id(session->session) ? -1 : stream_id), // Not allocated yet if equal to next stream ID
			NULL,
			headers,
			header_count,
			NULL
	)) != 0 && ret != stream_id) {
		RRR_MSG_0 ("HTTP2 header field submission failed: %s", nghttp2_strerror(ret));
		ret = RRR_HTTP2_SOFT_ERROR;
		goto out;
	}

	// Set to 0 in case it contains stream ID
	ret = 0;

	out:
	RRR_FREE_IF_NOT_NULL(headers);
	return ret;
}

int rrr_http2_session_upgrade_postprocess (
		struct rrr_http2_session *session,
		const void *upgrade_settings,
		size_t upgrade_settings_len,
		enum rrr_http_method method
) {
	int ret = 0;

	if ((ret = nghttp2_session_upgrade2 (
			session->session,
			upgrade_settings,
			upgrade_settings_len,
			method == RRR_HTTP_METHOD_HEAD ? 1 : 0,
			NULL // No stream user data
	)) != 0) {
		RRR_MSG_0("Could not perform http2 upgrade postprocessing in rrr_http2_session_upgrade_postprocess\n");
		ret = RRR_HTTP2_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_http2_session_settings_submit (
		struct rrr_http2_session *session
) {
	int ret = 0;

	nghttp2_settings_entry vector[] = {
			{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, RRR_HTTP2_STREAM_BLOCKS * 64}
	};

	/* client 24 bytes magic string will be sent by nghttp2 library if we are a client */

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

int rrr_http2_request_start (
		int32_t *stream_id,
		struct rrr_http2_session *session
) {
	int ret = 0;

	*stream_id = 0;

	// Note that stream ID will not be incremented in the library until we send headers
	uint32_t stream_id_tmp = nghttp2_session_get_next_stream_id(session->session);
	if (stream_id_tmp >= (uint32_t) 1 << 31) {
		RRR_MSG_0 ("HTTP2 request submission failed, IDs exhausted: %s", nghttp2_strerror(stream_id_tmp));
		ret = RRR_HTTP2_SOFT_ERROR;
		goto out;
	}

	*stream_id = stream_id_tmp;

	out:
	return ret;
}

int rrr_http2_header_submit (
		struct rrr_http2_session *session,
		int32_t stream_id,
		const char *name,
		const char *value
) {
	int ret = 0;

	const char *disallowed_names[] = {
			"connection",
			"keep-alive",
			"transfer-encoding"
	};

	for (size_t i = 0; i < sizeof(disallowed_names) / sizeof(*disallowed_names); i++) {
		if (strcmp(disallowed_names[i], name) == 0) {
			RRR_DBG_3("Submit HTTP2 header: '%s'='%s' is prohibited in HTTP2, ignoring\n", name, value);
			goto out;
		}
	}

	RRR_DBG_3("Submit HTTP2 header: '%s'='%s'\n", name, value);

	if ((ret = __rrr_http2_session_stream_header_push(session, stream_id, name, value)) != 0) {
		goto out;
	}
	out:
	return ret;
}

int rrr_http2_header_status_submit (
		struct rrr_http2_session *session,
		int32_t stream_id,
		unsigned int response_code
) {
	int ret = 0;

	if (response_code > 999) {
		RRR_BUG("BUG: Invalid response code %u to rrr_http2_response_status_submit\n", response_code);
	}

	char tmp[8];
	sprintf(tmp, "%u", response_code);

	if ((rrr_http2_header_submit (session, stream_id, ":status", tmp)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http2_headers_end (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	return __rrr_http2_session_stream_headers_submit(session, stream_id);
}

int rrr_http2_response_submit (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	int ret = 0;

	nghttp2_data_provider data_provider = {
			{ 0 },
			__rrr_http2_data_source_read_callback
	};

	// Note that the final source read callback is set in the tick() function

	if ((ret = nghttp2_submit_response(session->session, stream_id, NULL, 0, &data_provider)) != 0) {
		RRR_MSG_0 ("HTTP2 response submission failed: %s", nghttp2_strerror(ret));
		ret = RRR_HTTP2_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_http2_data_submission_request_set (
		struct rrr_http2_session *session,
		int32_t stream_id
) {
	int ret = 0;

	struct rrr_http2_stream *stream = __rrr_http2_stream_find_or_create(session, stream_id);
	if (stream == NULL) {
		return RRR_HTTP2_SOFT_ERROR;
	}

	stream->data_submission_requested = 1;

	return ret;
}

int rrr_http2_transport_ctx_streams_iterate (
		struct rrr_http2_session *session,
		int (*callback)(uint32_t stream_id, void *application_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_http2_stream_collection *collection = &session->streams;

	RRR_HTTP2_STREAMS_ITERATE_ACTIVE_BEGIN();
		if ((ret = callback(collection->stream_ids[i], node->application_data, callback_arg)) != 0) {
			goto out;
		}
	RRR_HTTP2_STREAMS_ITERATE_END();

	out:
	return ret;
}

int rrr_http2_streams_count_and_maintain (
		struct rrr_http2_session *session
) {
	 __rrr_http2_streams_maintain (session);

	return session->streams.stream_count;
}

int rrr_http2_need_tick (
		struct rrr_http2_session *session
) {
	/* When a request is created and ready to be sent, we need to tick more */
	return nghttp2_session_want_write(session->session) || session->initial_receive_data_len > 0;
}

int rrr_http2_transport_ctx_tick (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle,
		int (*data_receive_callback)(RRR_HTTP2_DATA_RECEIVE_CALLBACK_ARGS),
		int (*data_source_callback)(RRR_HTTP2_DATA_SOURCE_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = RRR_HTTP2_DONE;

	// Just to clean up any streams needing deletion
	__rrr_http2_stream_find(session, 0);

	// Always update callback data. Persistent user_data pointer was set in the
	// new() function
	struct rrr_http2_callback_data callback_data = {
			handle,
			data_receive_callback,
			data_source_callback,
			callback_arg
	};
	session->callback_data = callback_data;

	// Parse any overshoot data from HTTP/1.1 parsing
	if (session->initial_receive_data != NULL) {
		ssize_t send_bytes = session->initial_receive_data_len;
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
	if (rrr_time_get_64() - session->last_ping_send_time > RRR_HTTP2_PING_MAINTENANCE_INTERVAL_S * 1000 * 1000) {
		session->last_ping_send_time = rrr_time_get_64();

		 __rrr_http2_streams_maintain (session);

		if ((ret = nghttp2_submit_ping(session->session, NGHTTP2_FLAG_NONE, NULL)) != 0) {
			RRR_MSG_0("Error from nghttp2_submit_ping in rrr_http2_tick: %s\n", nghttp2_strerror(ret));
			ret = RRR_HTTP2_SOFT_ERROR;
			goto out;
		}
	}

	if (nghttp2_session_want_read(session->session) == 0 && nghttp2_session_want_write(session->session) == 0) {
		RRR_DBG_7("http2 done\n");
		ret = RRR_HTTP2_DONE;
		goto out;
	}

	if ((ret = nghttp2_session_send(session->session)) != 0) {
		if (ret == NGHTTP2_ERR_EOF) {
			RRR_DBG_7("http2 done during send\n");
			ret = RRR_HTTP2_DONE;
			goto out;
		}
		RRR_DBG_3("Error from nghttp2 send: %s\n", nghttp2_strerror(ret));
		ret = (ret == NGHTTP2_ERR_EOF ? RRR_HTTP2_DONE : RRR_HTTP2_SOFT_ERROR);
		goto out;
	}

	if ((ret = nghttp2_session_recv(session->session)) != 0) {
		if (ret == NGHTTP2_ERR_EOF) {
			RRR_DBG_7("http2 done during recv\n");
			ret = RRR_HTTP2_DONE;
			goto out;
		}
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
			NULL,
			NULL
	};
	session->callback_data = callback_data;

	nghttp2_session_terminate_session(session->session, 0);
}

int rrr_http2_upgrade_request_settings_pack (
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

	*target = (char *) result;

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
