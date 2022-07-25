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

#ifndef RRR_HTTP_APPLICATION_INTERNALS_H
#define RRR_HTTP_APPLICATION_INTERNALS_H

#include "http_common.h"
#include "http_application.h"
#include "../net_transport/net_transport.h"

#include "../rrr_types.h"

struct rrr_http_application;
struct rrr_http_transaction;
struct rrr_http_rules;

#define RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS        \
    int *is_possible,                                          \
    struct rrr_http_application *application

#define RRR_HTTP_APPLICATION_TRANSACTION_COUNT_ARGS            \
    struct rrr_http_application *application,                  \
    struct rrr_net_transport_handle *handle                    \

#define RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS                 \
    struct rrr_http_application **upgraded_app,                \
    struct rrr_http_application *application,                  \
    struct rrr_net_transport_handle *handle,                   \
    const char *user_agent,                                    \
    const char *host,                                          \
    enum rrr_http_upgrade_mode upgrade_mode,                   \
    enum rrr_http_version protocol_version,                    \
    struct rrr_http_transaction *transaction

#define RRR_HTTP_APPLICATION_NEED_TICK_ARGS                    \
    struct rrr_http_application *app

#define RRR_HTTP_APPLICATION_TICK_ARGS                         \
    rrr_biglength *received_bytes,                             \
    struct rrr_http_application **upgraded_app,                \
    struct rrr_http_application *app,                          \
    struct rrr_net_transport_handle *handle,                   \
    rrr_biglength read_max_size,                               \
    const struct rrr_http_rules *rules

#define RRR_HTTP_APPLICATION_ALPN_PROTOS_GET_ARGS              \
    const char **target,                                       \
    unsigned int *length

#define RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS                 \
    struct rrr_http_application *app,                          \
    struct rrr_net_transport_handle *handle

#define RRR_HTTP_APPLICATION_STREAM_OPEN_ARGS                                   \
    void (**stream_data),                                                       \
    void (**stream_data_destroy)(void *stream_data),                            \
    int (**cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS), \
    int (**cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS),         \
    int (**cb_ack)(RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS),                 \
    void **cb_arg,                                                              \
    struct rrr_http_application *app,                                           \
    struct rrr_net_transport_handle *handle,                                    \
    int64_t stream_id,                                                          \
    int flags,                                                                  \
    void *stream_open_callback_arg_local

struct rrr_http_application_constants {
	enum rrr_http_application_type type;
	void (*destroy)(struct rrr_http_application *);
	uint64_t (*active_transaction_count_get_and_maintain)(RRR_HTTP_APPLICATION_TRANSACTION_COUNT_ARGS);
	int (*request_send_possible)(RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS);
	int (*request_send)(RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS);
	int (*tick)(RRR_HTTP_APPLICATION_TICK_ARGS);
	int (*need_tick)(RRR_HTTP_APPLICATION_NEED_TICK_ARGS);
	void (*polite_close)(RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS);

	// Only for applications using QUIC
	int (*stream_open)(RRR_HTTP_APPLICATION_STREAM_OPEN_ARGS);
};

#define RRR_HTTP_APPLICATION_HEAD                              \
    const struct rrr_http_application_constants *constants;    \
    struct rrr_http_application_callbacks callbacks

struct rrr_http_application {
	RRR_HTTP_APPLICATION_HEAD;
};

#endif /* RRR_HTTP_APPLICATION_INTERNALS_H */
