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

#define RRR_HTTP_CLIENT_RAW_RECEIVE_CALLBACK_ARGS              \
    RRR_HTTP_COMMON_RECEIVE_RAW_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_UNIQUE_ID_GENERATOR_CALLBACK_ARGS      \
    RRR_HTTP_COMMON_UNIQUE_ID_GENERATOR_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS                    \
    const struct rrr_http_transaction *transaction,            \
    const struct rrr_nullsafe_str *response_data,              \
    void *arg

#define RRR_HTTP_CLIENT_FAILURE_CALLBACK_ARGS                  \
    const struct rrr_http_transaction *transaction,            \
    const char *error_msg,                                     \
    void *arg

#define RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS                 \
    const struct rrr_http_transaction *transaction,            \
    const struct rrr_http_uri *uri,                            \
    void *arg

#define RRR_HTTP_CLIENT_METHOD_PREPARE_CALLBACK_ARGS           \
    enum rrr_http_method *chosen_method,                       \
    struct rrr_http_transaction *transaction,                  \
    void *arg

#define RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS            \
    char **endpoint_override,                                  \
    char **query_string,                                       \
    struct rrr_http_transaction *transaction,                  \
    void *arg

#define RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS       \
    char **server_override,                                    \
    uint16_t *port_override,                                   \
    void *arg

#define RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS \
	RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS \
	RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS

#define RRR_HTTP_CLIENT_HTTP2_RECEIVE_CALLBACK_ARGS \
	RRR_HTTP_SESSION_HTTP2_RECEIVE_CALLBACK_ARGS

struct rrr_http_client;
struct rrr_event_queue;
struct rrr_http_uri;
struct rrr_nullsafe_str;
struct rrr_net_transport_config;
struct rrr_http_client_config;
struct rrr_http_session;
struct rrr_net_transport;

struct rrr_http_client_callbacks {
	int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS);
	void *final_callback_arg;

	int (*failure_callback)(RRR_HTTP_CLIENT_FAILURE_CALLBACK_ARGS);
	void *failure_callback_arg;

	int (*redirect_callback)(RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS);
	void *redirect_callback_arg;

	int (*get_response_callback)(RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS);
	void *get_response_callback_arg;

	int (*frame_callback)(RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *frame_callback_arg;

	int (*unique_id_generator_callback)(RRR_HTTP_CLIENT_UNIQUE_ID_GENERATOR_CALLBACK_ARGS);
	void *unique_id_generator_callback_arg;
};

struct rrr_http_client_request_data {
	enum rrr_http_transport transport_force;

	char *server;
	uint16_t http_port;
	char *endpoint;
	char *user_agent;

	enum rrr_http_method method;
	enum rrr_http_body_format body_format;
	enum rrr_http_upgrade_mode upgrade_mode;
	enum rrr_http_version protocol_version;
	int do_plain_http2;

	int ssl_no_cert_verify;
	uint16_t concurrent_connections;

	ssize_t read_max_size;
};

struct rrr_http_client_request_callback_data {
	const struct rrr_http_client_request_data *data;

	const char *request_header_host;

	int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS);
	void *query_prepare_callback_arg;

	enum rrr_http_application_type application_type;

	struct rrr_http_transaction *transaction;
};

int rrr_http_client_new (
		struct rrr_http_client **target,
		struct rrr_event_queue *events,
		uint64_t idle_timeout_ms,
		int send_chunk_count_limit,
		const struct rrr_http_client_callbacks *callbacks
);
void rrr_http_client_destroy (
		struct rrr_http_client *client
);
uint64_t rrr_http_client_active_transaction_count_get (
		const struct rrr_http_client *http_client
);
void rrr_http_client_websocket_response_available_notify (
		struct rrr_http_client *http_client
);
int rrr_http_client_request_data_reset_from_request_data (
		struct rrr_http_client_request_data *target,
		const struct rrr_http_client_request_data *source
);
int rrr_http_client_request_data_reset (
		struct rrr_http_client_request_data *data,
		enum rrr_http_transport transport_force,
		enum rrr_http_method method,
		enum rrr_http_body_format body_format,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		int do_plain_http2,
		const char *user_agent
);
int rrr_http_client_request_data_reset_from_config (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_client_config *config
);
int rrr_http_client_request_data_reset_from_uri (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_uri *uri
);
int rrr_http_client_request_data_reset_from_raw (
		struct rrr_http_client_request_data *data,
		const char *server,
		uint16_t port
);
void rrr_http_client_request_data_cleanup (
		struct rrr_http_client_request_data *data
);
void rrr_http_client_request_data_cleanup_void (
		void *data
);
void rrr_http_client_terminate_if_open (
		struct rrr_net_transport *transport_keepalive,
		int transport_keepalive_handle
);
int rrr_http_client_request_send (
		const struct rrr_http_client_request_data *data,
		struct rrr_http_client *http_client,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		int (*method_prepare_callback)(RRR_HTTP_CLIENT_METHOD_PREPARE_CALLBACK_ARGS),
		void *method_prepare_callback_arg,
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		void *connection_prepare_callback_arg,
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *query_prepare_callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
);

#endif /* RRR_HTTP_CLIENT_H */
