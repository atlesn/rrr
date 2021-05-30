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

#ifndef RRR_HTTP2_H

#include <nghttp2/nghttp2.h>

#include "../http/http_common.h"
#include "../read_constants.h"
#include "../rrr_types.h"

// Blocks of 64, maximum number of concurrent streams
#define RRR_HTTP2_STREAM_BLOCKS 3
#define RRR_HTTP2_STREAM_MAX (RRR_HTTP2_STREAM_BLOCKS * 64)

#define RRR_HTTP2_OK            RRR_READ_OK
#define RRR_HTTP2_SOFT_ERROR    RRR_READ_SOFT_ERROR
#define RRR_HTTP2_HARD_ERROR    RRR_READ_HARD_ERROR
#define RRR_HTTP2_DONE          RRR_READ_EOF
#define RRR_HTTP2_BUSY          RRR_READ_INCOMPLETE

#define RRR_HTTP2_DATA_RECEIVE_CALLBACK_ARGS                   \
    struct rrr_http2_session *session,                         \
    struct rrr_http_header_field_collection *headers,          \
    int32_t stream_id,                                         \
    short is_header_end,                                       \
    short is_data_end,                                         \
    short is_stream_close,                                     \
    short is_stream_error,                                     \
    const char *stream_error_msg,                              \
    void *data,                                                \
    size_t data_size,                                          \
    void *stream_application_data,                             \
    void *callback_arg

#define RRR_HTTP2_DATA_SOURCE_CALLBACK_ARGS                    \
    int *done,                                                 \
    rrr_length *written_bytes,                                 \
    uint8_t *buf,                                              \
    size_t buf_size,                                           \
    int32_t stream_id,                                         \
    void *callback_arg

enum rrr_http_method;
struct rrr_http_header_field_collection;
struct rrr_net_transport_handle;
struct rrr_http2_session;

int rrr_http2_session_new_or_reset (
		struct rrr_http2_session **target,
		void **initial_receive_data,
		size_t initial_receive_data_len,
		int is_server
);
void rrr_http2_session_destroy_if_not_null (
		struct rrr_http2_session **target
);
int rrr_http2_session_stream_application_data_set (
		struct rrr_http2_session *session,
		int32_t stream_id,
		void *application_data,
		void (*application_data_destroy_function)(void *)
);
void *rrr_http2_session_stream_application_data_get (
		struct rrr_http2_session *session,
		int32_t stream_id
);
int rrr_http2_session_upgrade_postprocess (
		struct rrr_http2_session *session,
		const void *http1_upgrade_settings,
		size_t http1_upgrade_settings_len,
		enum rrr_http_method method
);
int rrr_http2_session_settings_submit (
		struct rrr_http2_session *session
);
int rrr_http2_request_start (
		int32_t *stream_id,
		struct rrr_http2_session *session
);
int rrr_http2_header_submit (
		struct rrr_http2_session *session,
		int32_t stream_id,
		const char *name,
		const char *value
);
int rrr_http2_header_status_submit (
		struct rrr_http2_session *session,
		int32_t stream_id,
		unsigned int response_code
);
int rrr_http2_headers_end (
		struct rrr_http2_session *session,
		int32_t stream_id
);
int rrr_http2_response_submit (
		struct rrr_http2_session *session,
		int32_t stream_id
);
int rrr_http2_data_submission_request_set (
		struct rrr_http2_session *session,
		int32_t stream_id
);
int rrr_http2_transport_ctx_streams_iterate (
		struct rrr_http2_session *session,
		int (*callback)(uint32_t stream_id, void *application_data, void *arg),
		void *callback_arg
);
int rrr_http2_streams_count_and_maintain (
		struct rrr_http2_session *session
);
int rrr_http2_need_tick (
		struct rrr_http2_session *session
);
int rrr_http2_transport_ctx_tick (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle,
		int (*data_receive_callback)(RRR_HTTP2_DATA_RECEIVE_CALLBACK_ARGS),
		int (*data_source_callback)(RRR_HTTP2_DATA_SOURCE_CALLBACK_ARGS),
		void *callback_arg
);
void rrr_http2_transport_ctx_terminate (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle
);
int rrr_http2_upgrade_request_settings_pack (
		char **target
);
int rrr_http2_select_next_protocol (
		const unsigned char **out,
		unsigned char *outlen,
		const unsigned char *in,
		unsigned int inlen
);

#endif /* RRR_HTTP2_H */
