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

#ifndef RRR_HTTP_CLIENT_H
#define RRR_HTTP_CLIENT_H

#include <inttypes.h>
#include <sys/types.h>

#include "http_common.h"
#include "http_session.h"

#define RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS	\
	RRR_HTTP_COMMON_RAW_RECEIVE_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS			\
	struct rrr_http_client_request_data *data, 		\
	int response_code,								\
	const struct rrr_nullsafe_str *response_arg,	\
	int chunk_idx,									\
	int chunk_total,								\
	const char *chunk_data_start,					\
	size_t chunk_data_size,							\
	size_t part_data_size,							\
	void *arg

#define RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS	\
	char **endpoint_override,						\
	char **query_string,							\
	struct rrr_http_session *session,				\
	void *arg

#define RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS	\
	char **server_override,									\
	uint16_t *port_override,								\
	void *arg

#define RRR_HTTP_CLIENT_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS \
	RRR_HTTP_SESSION_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS \
	RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_HTTP2_RECEIVE_CALLBACK_ARGS \
	RRR_HTTP_SESSION_HTTP2_RECEIVE_CALLBACK_ARGS

struct rrr_nullsafe_str;
struct rrr_net_transport_config;
struct rrr_http_client_config;
struct rrr_http_session;
struct rrr_net_transport;

struct rrr_http_client_request_data {
	enum rrr_http_transport transport_force;

	char *server;
	uint16_t http_port;
	char *endpoint;
	char *user_agent;

	int ssl_no_cert_verify;

	ssize_t read_max_size;

	int do_retry;
};

struct rrr_http_client_request_callback_data {
	enum rrr_http_method method;
	enum rrr_http_upgrade_mode upgrade_mode;

	int response_code;
	struct rrr_nullsafe_str *response_argument;

	// Errors do not propagate through net transport framework. Return
	// value of http callbacks is saved here.
	int http_receive_ret;

	struct rrr_http_client_request_data *data;

	struct rr_net_transport *transport;
	int transport_handle;

	const char *raw_request_data;
	size_t raw_request_data_size;

	const char *request_header_host;

	int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS);
	void *query_prepare_callback_arg;
	int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS);
	void *raw_callback_arg;
	int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS);
	void *final_callback_arg;
};

int rrr_http_client_data_init (
		struct rrr_http_client_request_data *data,
		const char *user_agent
);
int rrr_http_client_data_reset (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_client_config *config,
		enum rrr_http_transport transport_force
);
void rrr_http_client_request_data_cleanup (
		struct rrr_http_client_request_data *data
);
void rrr_http_client_terminate_if_open (
		struct rrr_net_transport *transport_keepalive,
		int transport_keepalive_handle
);
// Note that data in the struct may change if there are any redirects
int rrr_http_client_send_request (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_args,
		int (*query_perpare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);
int rrr_http_client_send_raw_request (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		const char *raw_request_data,
		size_t raw_request_data_size,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_args,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);
int rrr_http_client_send_request_simple (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		const struct rrr_net_transport_config *net_transport_config,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);
int rrr_http_client_send_request_keepalive_simple (
		struct rrr_http_client_request_data *data,
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);
int rrr_http_client_start_websocket_simple (
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport **transport_keepalive,
		int *transport_keepalive_handle,
		const struct rrr_net_transport_config *net_transport_config,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);
int rrr_http_client_websocket_tick (
		uint64_t *bytes_total,
		int timeout_s,
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport *transport_keepalive,
		int transport_keepalive_handle,
		int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg
);

#ifdef RRR_WITH_NGHTTP2
int rrr_http_client_http2_tick (
		struct rrr_http_client_request_data *data,
		struct rrr_net_transport *transport_keepalive,
		int transport_keepalive_handle,
		int (*raw_callback)(RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS),
		void *raw_callback_arg,
		int (*get_response_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *get_response_callback_arg
);
#endif /* RRR_WITH_NGHTTP2 */

#endif /* RRR_HTTP_CLIENT_H */
