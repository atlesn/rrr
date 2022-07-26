/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_COMMON_H
#define RRR_HTTP_COMMON_H

#include <inttypes.h>

#include "../read_constants.h"
#include "../rrr_types.h"

// Limits for HTTP1 only
#define RRR_HTTP_PARSE_HEADROOM_LIMIT_KB 1024
#define RRR_HTTP_PARSE_HEADER_LIMIT_KB 64

#define RRR_HTTP_CLIENT_USER_AGENT "RRR/" PACKAGE_VERSION
#define RRR_HTTP_SERVER_USER_AGENT "RRR/" PACKAGE_VERSION

#define RRR_HTTP_CLIENT_TIMEOUT_STALL_MS    500
#define RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS    2000

#define RRR_HTTP_SERVER_WORKER_THREAD_WATCHDOG_TIMER_MS   5000
#define RRR_HTTP_SERVER_WORKER_FIRST_DATA_TIMEOUT_MS      2000
#define RRR_HTTP_SERVER_WORKER_IDLE_TIMEOUT_MS            30000
#define RRR_HTTP_SERVER_WORKER_TRANSACTION_TIMEOUT_MS     RRR_HTTP_SERVER_WORKER_IDLE_TIMEOUT_MS
#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_PING_INTERVAL_S  5
#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_TIMEOUT_S        (RRR_HTTP_SERVER_WORKER_WEBSOCKET_PING_INTERVAL_S*2)

#define RRR_HTTP_OK                      RRR_READ_OK
#define RRR_HTTP_HARD_ERROR              RRR_READ_HARD_ERROR
#define RRR_HTTP_SOFT_ERROR              RRR_READ_SOFT_ERROR
#define RRR_HTTP_BUSY                    RRR_READ_INCOMPLETE
#define RRR_HTTP_NO_RESULT               RRR_READ_INCOMPLETE
#define RRR_HTTP_DONE                    RRR_READ_EOF

#define RRR_HTTP_PARSE_OK                RRR_READ_OK
#define RRR_HTTP_PARSE_HARD_ERR          RRR_READ_HARD_ERROR
#define RRR_HTTP_PARSE_SOFT_ERR          RRR_READ_SOFT_ERROR
#define RRR_HTTP_PARSE_INCOMPLETE        RRR_READ_INCOMPLETE
#define RRR_HTTP_PARSE_EOF               RRR_READ_EOF

#define RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS        101
#define RRR_HTTP_RESPONSE_CODE_OK                         200
#define RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT              204
#define RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST          400
#define RRR_HTTP_RESPONSE_CODE_ERROR_NOT_FOUND            404
#define RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR      500
#define RRR_HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT            504
#define RRR_HTTP_RESPONSE_CODE_VERSION_NOT_SUPPORTED      505

#define RRR_HTTP_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

enum rrr_http_transport {
	RRR_HTTP_TRANSPORT_ANY,
	RRR_HTTP_TRANSPORT_HTTP,
	RRR_HTTP_TRANSPORT_HTTPS,
	RRR_HTTP_TRANSPORT_QUIC
};

enum rrr_http_method {
	RRR_HTTP_METHOD_UNKNOWN,
	RRR_HTTP_METHOD_GET,
	RRR_HTTP_METHOD_OPTIONS,
	RRR_HTTP_METHOD_HEAD,
	RRR_HTTP_METHOD_DELETE,
	RRR_HTTP_METHOD_PUT,
	RRR_HTTP_METHOD_PATCH,
	RRR_HTTP_METHOD_POST /* Remove the other POSTS and replace functionallity with format */
};

enum rrr_http_body_format {
	RRR_HTTP_BODY_FORMAT_MULTIPART_FORM_DATA,
	RRR_HTTP_BODY_FORMAT_URLENCODED,
	RRR_HTTP_BODY_FORMAT_URLENCODED_NO_QUOTING,
	RRR_HTTP_BODY_FORMAT_JSON,
	RRR_HTTP_BODY_FORMAT_RAW
};

enum rrr_http_upgrade_mode {
	RRR_HTTP_UPGRADE_MODE_NONE,
	RRR_HTTP_UPGRADE_MODE_WEBSOCKET,
	RRR_HTTP_UPGRADE_MODE_HTTP2
};

enum rrr_http_application_type {
	RRR_HTTP_APPLICATION_UNSPECIFIED,
	RRR_HTTP_APPLICATION_HTTP1,
	RRR_HTTP_APPLICATION_HTTP2,
	RRR_HTTP_APPLICATION_HTTP3
};

enum rrr_http_version {
	RRR_HTTP_VERSION_UNSPECIFIED,
	RRR_HTTP_VERSION_10,
	RRR_HTTP_VERSION_11
};

enum rrr_http_connection {
	RRR_HTTP_CONNECTION_UNSPECIFIED,
	RRR_HTTP_CONNECTION_CLOSE,
	RRR_HTTP_CONNECTION_KEEPALIVE
};

enum rrr_http_parse_type {
	RRR_HTTP_PARSE_REQUEST,
	RRR_HTTP_PARSE_RESPONSE,
	RRR_HTTP_PARSE_MULTIPART
};

struct rrr_http_rules {
	short do_no_server_http2;
	short do_no_body_parse;
	union {
		rrr_biglength server_request_max_size;
		rrr_biglength client_response_max_size;
	};
	const char *server_alt_svc_header;
};

extern const char *rrr_http_transport_str_any;
extern const char *rrr_http_transport_str_http;
extern const char *rrr_http_transport_str_https;
extern const char *rrr_http_transport_str_quic;

#define RRR_HTTP_TRANSPORT_TO_STR(transport)                                             \
    (transport == RRR_HTTP_TRANSPORT_ANY ? rrr_http_transport_str_any :                  \
    (transport == RRR_HTTP_TRANSPORT_HTTP ? rrr_http_transport_str_http :                \
    (transport == RRR_HTTP_TRANSPORT_HTTPS ? rrr_http_transport_str_https :              \
    (transport == RRR_HTTP_TRANSPORT_QUIC ? rrr_http_transport_str_quic : ("unknown")    \
    ))))

extern const char *rrr_http_method_str_get;
extern const char *rrr_http_method_str_head;
extern const char *rrr_http_method_str_put;
extern const char *rrr_http_method_str_patch;
extern const char *rrr_http_method_str_delete;
extern const char *rrr_http_method_str_post;

#define RRR_HTTP_METHOD_TO_STR(method)                                                                                         \
    (method == RRR_HTTP_METHOD_GET ? rrr_http_method_str_get :                                                                 \
    (method == RRR_HTTP_METHOD_HEAD ? rrr_http_method_str_head :                                                               \
    (method == RRR_HTTP_METHOD_PUT ? rrr_http_method_str_put :                                                                 \
    (method == RRR_HTTP_METHOD_PATCH ? rrr_http_method_str_patch :                                                             \
    (method == RRR_HTTP_METHOD_DELETE ? rrr_http_method_str_delete :                                                           \
    (method == RRR_HTTP_METHOD_POST ? rrr_http_method_str_post :                                                               \
    ("unknown") ))))))

#define RRR_HTTP_METHOD_TO_STR_CONFORMING(method)                                                                              \
    (method == RRR_HTTP_METHOD_GET ? rrr_http_method_str_get :                                                                 \
    (method == RRR_HTTP_METHOD_HEAD ? rrr_http_method_str_head :                                                               \
    (method == RRR_HTTP_METHOD_PUT ? rrr_http_method_str_put :                                                                 \
    (method == RRR_HTTP_METHOD_PATCH ? rrr_http_method_str_patch :                                                             \
    (method == RRR_HTTP_METHOD_DELETE ? rrr_http_method_str_delete :                                                           \
    rrr_http_method_str_post                                                                                                   \
    )))))

extern const char *rrr_http_body_format_str_multipart_form_data;
extern const char *rrr_http_body_format_str_urlencoded;
extern const char *rrr_http_body_format_str_urlencoded_no_quoting;
extern const char *rrr_http_body_format_str_json;
extern const char *rrr_http_body_format_str_raw;

#define RRR_HTTP_BODY_FORMAT_TO_STR(format)                                                                                    \
    (format == RRR_HTTP_BODY_FORMAT_MULTIPART_FORM_DATA ? rrr_http_body_format_str_multipart_form_data :                       \
    (format == RRR_HTTP_BODY_FORMAT_URLENCODED ? rrr_http_body_format_str_urlencoded :                                         \
    (format == RRR_HTTP_BODY_FORMAT_URLENCODED_NO_QUOTING ? rrr_http_body_format_str_urlencoded_no_quoting :                   \
    (format == RRR_HTTP_BODY_FORMAT_JSON ? rrr_http_body_format_str_json :                                                     \
    (format == RRR_HTTP_BODY_FORMAT_RAW ? rrr_http_body_format_str_raw :                                                       \
    "(unknown)"                                                                                                                \
    )))))

extern const char *rrr_http_upgrade_mode_str_none;
extern const char *rrr_http_upgrade_mode_str_websocket;
extern const char *rrr_http_upgrade_mode_str_http2;

#define RRR_HTTP_UPGRADE_MODE_TO_STR(upgrade_mode)                                                                             \
    (upgrade_mode == RRR_HTTP_UPGRADE_MODE_NONE ? rrr_http_upgrade_mode_str_none :                                             \
    (upgrade_mode == RRR_HTTP_UPGRADE_MODE_WEBSOCKET ? rrr_http_upgrade_mode_str_websocket :                                   \
    (upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2 ? rrr_http_upgrade_mode_str_http2 : ("unknown")                               \
    )))

extern const char *rrr_http_application_str_http1;
extern const char *rrr_http_application_str_http2;
extern const char *rrr_http_application_str_http3;

#define RRR_HTTP_APPLICATION_TO_STR(application)                                                                               \
    (application == RRR_HTTP_APPLICATION_HTTP1 ? rrr_http_application_str_http1 :                                              \
    (application == RRR_HTTP_APPLICATION_HTTP2 ? rrr_http_application_str_http2 :                                              \
    (application == RRR_HTTP_APPLICATION_HTTP3 ? rrr_http_application_str_http3 : ("unknown")                                  \
    )))

extern const char *rrr_http_version_str_10;
extern const char *rrr_http_version_str_11;

#define RRR_HTTP_VERSION_TO_STR(version)                                                                                       \
    (version == RRR_HTTP_VERSION_10 ? rrr_http_version_str_10 :                                                                \
    (version == RRR_HTTP_VERSION_11 ? rrr_http_version_str_11 : ("unspecified")                                                \
    ))

typedef uint64_t rrr_http_unique_id;
struct rrr_nullsafe_str;

#define RRR_HTTP_COMMON_RECEIVE_RAW_CALLBACK_ARGS              \
    const struct rrr_nullsafe_str *data,                       \
    struct rrr_http_transaction *transaction,                  \
    rrr_http_unique_id unique_id,                              \
    enum rrr_http_application_type next_protocol_version,      \
    void *arg

#define RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS                \
    const struct rrr_nullsafe_str *str, void *arg

#define RRR_HTTP_COMMON_UNIQUE_ID_GENERATOR_CALLBACK_ARGS \
    rrr_http_unique_id *unique_id, void *arg

#endif /* RRR_HTTP_COMMON_H */
