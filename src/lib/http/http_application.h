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

#ifndef RRR_HTTP_APPLICATION_H
#define RRR_HTTP_APPLICATION_H

#include "http_common.h"

#include <unistd.h>
#include <sys/socket.h>

#define RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_COMMON_ARGS	\
	struct rrr_net_transport_handle *handle,				\
	const struct rrr_http_part *request_part,				\
	struct rrr_http_part *response_part,					\
	const char *data_ptr,									\
	const struct sockaddr *sockaddr,						\
	socklen_t socklen,										\
	ssize_t overshoot_bytes,								\
	rrr_http_unique_id unique_id

#define RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS	\
	int *do_websocket,											\
	RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_COMMON_ARGS,			\
	void *arg

#define RRR_HTTP_APPLICATION_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS \
	void **data, ssize_t *data_len, int *is_binary, void *arg

#define RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS \
	const char *payload, uint64_t payload_size, int is_binary, rrr_http_unique_id unique_id, void *arg

#define RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS		\
	RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_COMMON_ARGS,	\
	enum rrr_http_upgrade_mode upgrade_mode,			\
	void *arg

#define RRR_HTTP_APPLICATION_RAW_RECEIVE_CALLBACK_ARGS			\
	RRR_HTTP_COMMON_RAW_RECEIVE_CALLBACK_ARGS

struct rrr_http_application;
struct rrr_net_transport_handle;
struct rrr_http_part;

void rrr_http_application_destroy_if_not_null (
		struct rrr_http_application **app
);
int rrr_http_application_new (
		struct rrr_http_application **target,
		enum rrr_http_application_type type
);
int rrr_http_application_transport_ctx_request_send (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		const char *user_agent,
		const char *host,
		const char *uri_str,
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		struct rrr_http_part *request_part
);
int rrr_http_application_transport_ctx_response_send (
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_part *response_part
);
int rrr_http_application_transport_ctx_tick (
		ssize_t *parse_complete_pos,
		ssize_t *received_bytes,
		struct rrr_http_application *app,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_part *request_part,
		struct rrr_http_part *response_part,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int is_client,
		int (*websocket_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS),
		void *websocket_callback_arg,
		int (*get_response_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg,
		int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS),
		void *callback_arg,
		int (*raw_callback)(RRR_HTTP_APPLICATION_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_arg
);

#endif /* RRR_HTTP_APPLICATION_H */
