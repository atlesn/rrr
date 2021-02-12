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

#ifndef RRR_HTTP_APPLICATION_INTERNALS_H
#define RRR_HTTP_APPLICATION_INTERNALS_H

struct rrr_http_application;
struct rrr_net_transport_handle;
struct rrr_http_transaction;
enum rrr_http_method;
	
#define RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS        \
    int *is_possible,                                          \
    struct rrr_http_application *application

#define RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS                 \
    struct rrr_http_application **upgraded_app,                \
    struct rrr_http_application *application,                  \
    struct rrr_net_transport_handle *handle,                   \
    const char *user_agent,                                    \
    const char *host,                                          \
    enum rrr_http_upgrade_mode upgrade_mode,                   \
    struct rrr_http_transaction *transaction

#define RRR_HTTP_APPLICATION_TICK_ARGS                                                           \
    ssize_t *received_bytes,                                                                     \
    uint64_t *active_transaction_count,                                                          \
    struct rrr_http_application **upgraded_app,                                                  \
    struct rrr_http_application *app,                                                            \
    struct rrr_net_transport_handle *handle,                                                     \
    ssize_t read_max_size,                                                                       \
    int (*unique_id_generator_callback)(RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS), \
    void *unique_id_generator_callback_arg,                                                      \
    int (*upgrade_verify_callback)(RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS),           \
    void *upgrade_verify_callback_arg,                                                           \
    int (*websocket_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS),           \
    void *websocket_callback_arg,                                                                \
    int (*get_response_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),     \
    void *get_response_callback_arg,                                                             \
    int (*frame_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS),                   \
    void *frame_callback_arg,                                                                    \
    int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS),                                 \
    void *callback_arg

#define RRR_HTTP_APPLICATION_ALPN_PROTOS_GET_ARGS              \
    const char **target,                                       \
    unsigned int *length

#define RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS                 \
    struct rrr_http_application *app,                          \
    struct rrr_net_transport_handle *handle


struct rrr_http_application_constants {
	enum rrr_http_application_type type;
	void (*destroy)(struct rrr_http_application *);
	int (*request_send_possible)(RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS);
	int (*request_send)(RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS);
	int (*tick)(RRR_HTTP_APPLICATION_TICK_ARGS);
	void (*polite_close)(RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS);
};

#define RRR_HTTP_APPLICATION_HEAD                              \
    const struct rrr_http_application_constants *constants;    \
    uint64_t complete_transaction_count

struct rrr_http_application {
	RRR_HTTP_APPLICATION_HEAD;
};

#endif /* RRR_HTTP_APPLICATION_INTERNALS_H */
