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

#ifndef RRR_HTTP2_H

#include <nghttp2/nghttp2.h>

#include "../read_constants.h"

#define RRR_HTTP2_OK			RRR_READ_OK
#define RRR_HTTP2_SOFT_ERROR	RRR_READ_SOFT_ERROR
#define RRR_HTTP2_HARD_ERROR	RRR_READ_HARD_ERROR
#define RRR_HTTP2_DONE			RRR_READ_EOF

#define RRR_HTTP2_GET_RESPONSE_CALLBACK_ARGS	\
	struct rrr_http2_session *session,			\
	int32_t stream_id,							\
	void *data,									\
	size_t data_size,							\
	void *stream_application_data,				\
	uint64_t stream_application_id,				\
	void *callback_arg

struct rrr_net_transport_handle;
struct rrr_http2_session;

int rrr_http2_session_client_new_or_reset (
		struct rrr_http2_session **target,
		void **initial_receive_data,
		size_t initial_receive_data_len
);
void rrr_http2_session_destroy_if_not_null (
		struct rrr_http2_session **target
);
int rrr_http2_session_stream_application_data_set (
		struct rrr_http2_session *session,
		int32_t stream_id,
		void **application_data,
		void (*application_data_destroy_function)(void *)
);
void *rrr_http2_session_stream_application_data_get (
		struct rrr_http2_session *session,
		int32_t stream_id
);
int rrr_http2_session_stream_application_id_set (
		struct rrr_http2_session *session,
		int32_t stream_id,
		uint64_t id
);
int rrr_http2_session_stream_application_id_get (
		uint64_t *result,
		struct rrr_http2_session *session,
		int32_t stream_id
);
int rrr_http2_session_client_upgrade_postprocess (
		struct rrr_http2_session *session,
		const void *http1_upgrade_settings,
		size_t http1_upgrade_settings_len
);
int rrr_http2_transport_ctx_tick (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle,
		int (*get_response_callback)(RRR_HTTP2_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg
);
void rrr_http2_transport_ctx_terminate (
		struct rrr_http2_session *session,
		struct rrr_net_transport_handle *handle
);
int rrr_http2_pack_upgrade_request_settings (
		char **target
);

#endif /* RRR_HTTP2_H */
