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

#ifndef RRR_HTTP_SESSION_H
#define RRR_HTTP_SESSION_H

#include <stdint.h>
#include <sys/socket.h>

#include "http_common.h"
#include "http_fields.h"
#include "http_part.h"

#define RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS	\
	const struct rrr_http_part *request_part,	\
	struct rrr_http_part *response_part,		\
	const char *data_ptr,						\
	const struct sockaddr *sockaddr,			\
	socklen_t socklen,							\
	ssize_t overshoot_bytes,					\
	rrr_http_unique_id unique_id,				\
	void *arg

#define RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS	\
	rrr_http_unique_id *result,								\
	void *arg

#define RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS	\
	RRR_HTTP_COMMON_RAW_RECEIVE_CALLBACK_ARGS

struct rrr_http_session {
	int is_client;
	enum rrr_http_method method;
	char *uri_str;
	char *user_agent;
	struct rrr_http_part *request_part;
	struct rrr_http_part *response_part;
};

struct rrr_net_transport;
struct rrr_net_transport_handle;

int rrr_http_session_transport_ctx_server_new (
		struct rrr_net_transport_handle *handle
);
int rrr_http_session_transport_ctx_set_endpoint (
		struct rrr_net_transport_handle *handle,
		const char *endpoint
);
int rrr_http_session_transport_ctx_client_new_or_clean (
		struct rrr_net_transport_handle *handle,
		enum rrr_http_method method,
		const char *user_agent
);
int rrr_http_session_transport_ctx_add_query_field (
		struct rrr_net_transport_handle *handle,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
);
int rrr_http_session_query_field_add (
		struct rrr_http_session *session,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
);
void rrr_http_session_query_fields_dump (
		struct rrr_http_session *session
);
int rrr_http_session_set_keepalive (
		struct rrr_http_session *session,
		int set
);
int rrr_http_session_transport_ctx_request_send (
		struct rrr_net_transport_handle *handle,
		const char *host
);
int rrr_http_session_transport_ctx_raw_request_send (
		struct rrr_net_transport_handle *handle,
		const char *raw_request_data,
		size_t raw_request_size
);
int rrr_http_session_transport_ctx_receive (
		struct rrr_net_transport_handle *handle,
		uint64_t timeout_stall_us,
		uint64_t timeout_total_us,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int (*callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS),
		void *callback_arg,
		int (*raw_callback)(RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_arg
);

#endif /* RRR_HTTP_SESSION_H */
