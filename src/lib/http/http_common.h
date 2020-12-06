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

#ifndef RRR_HTTP_COMMON_H
#define RRR_HTTP_COMMON_H

#include <inttypes.h>

#include "../read_constants.h"

#define RRR_HTTP_CLIENT_USER_AGENT "RRR/" PACKAGE_VERSION

#define RRR_HTTP_CLIENT_TIMEOUT_STALL_MS	500
#define RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS	2000

#define RRR_HTTP_SERVER_USER_AGENT						"RRR/" PACKAGE_VERSION
#define RRR_HTTP_SERVER_WORKER_THREAD_WATCHDOG_TIMER_MS	5000

#define RRR_HTTP_OK						RRR_READ_OK
#define RRR_HTTP_HARD_ERROR				RRR_READ_HARD_ERROR
#define RRR_HTTP_SOFT_ERROR				RRR_READ_SOFT_ERROR

#define RRR_HTTP_PARSE_OK				RRR_READ_OK
#define RRR_HTTP_PARSE_HARD_ERR 		RRR_READ_HARD_ERROR
#define RRR_HTTP_PARSE_SOFT_ERR			RRR_READ_SOFT_ERROR
#define RRR_HTTP_PARSE_INCOMPLETE		RRR_READ_INCOMPLETE

#define RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS		101
#define RRR_HTTP_RESPONSE_CODE_OK						200
#define RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT			204
#define RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST		400
#define RRR_HTTP_RESPONSE_CODE_ERROR_NOT_FOUND			404
#define RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR	500
#define RRR_HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT			504
#define RRR_HTTP_RESPONSE_CODE_VERSION_NOT_SUPPORTED	505

#define RRR_HTTP_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

enum rrr_http_transport {
	RRR_HTTP_TRANSPORT_ANY,
	RRR_HTTP_TRANSPORT_HTTP,
	RRR_HTTP_TRANSPORT_HTTPS
};

enum rrr_http_method {
	RRR_HTTP_METHOD_GET,
	RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA,
	RRR_HTTP_METHOD_POST_URLENCODED,
	RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING,
	RRR_HTTP_METHOD_POST_APPLICATION_OCTET_STREAM,
	RRR_HTTP_METHOD_POST_TEXT_PLAIN,
	RRR_HTTP_METHOD_OPTIONS,
	RRR_HTTP_METHOD_HEAD,
	RRR_HTTP_METHOD_DELETE,
	RRR_HTTP_METHOD_PUT,
};

enum rrr_http_upgrade_mode {
	RRR_HTTP_UPGRADE_MODE_NONE,
	RRR_HTTP_UPGRADE_MODE_WEBSOCKET,
	RRR_HTTP_UPGRADE_MODE_HTTP2
};

enum rrr_http_application_type {
	RRR_HTTP_APPLICATION_UNSPECIFIED,
	RRR_HTTP_APPLICATION_HTTP1,
	RRR_HTTP_APPLICATION_HTTP2
};

enum rrr_http_parse_type {
	RRR_HTTP_PARSE_REQUEST,
	RRR_HTTP_PARSE_RESPONSE,
	RRR_HTTP_PARSE_MULTIPART
};

extern const char *rrr_http_transport_str_any;
extern const char *rrr_http_transport_str_http;
extern const char *rrr_http_transport_str_https;

#define RRR_HTTP_TRANSPORT_TO_STR(transport)												\
	(transport == RRR_HTTP_TRANSPORT_ANY ? rrr_http_transport_str_any :						\
	(transport == RRR_HTTP_TRANSPORT_HTTP ? rrr_http_transport_str_http :					\
	(transport == RRR_HTTP_TRANSPORT_HTTPS ? rrr_http_transport_str_https : ("unknown")		\
	)))

extern const char *rrr_http_method_str_get;
extern const char *rrr_http_method_str_head;
extern const char *rrr_http_method_str_put;
extern const char *rrr_http_method_str_delete;
extern const char *rrr_http_method_str_post;
extern const char *rrr_http_method_str_post_multipart_form_data;
extern const char *rrr_http_method_str_post_urlencoded;
extern const char *rrr_http_method_str_post_urlencoded_no_quoting;
extern const char *rrr_http_method_str_post_application_octet_stream;
extern const char *rrr_http_method_str_post_application_text_plain;

#define RRR_HTTP_METHOD_TO_STR(method)																				\
	(method == RRR_HTTP_METHOD_GET ? rrr_http_method_str_get :														\
	(method == RRR_HTTP_METHOD_HEAD ? rrr_http_method_str_head :													\
	(method == RRR_HTTP_METHOD_PUT ? rrr_http_method_str_put :														\
	(method == RRR_HTTP_METHOD_DELETE ? rrr_http_method_str_delete :												\
	(method == RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA ? rrr_http_method_str_post_multipart_form_data :			\
	(method == RRR_HTTP_METHOD_POST_URLENCODED ? rrr_http_method_str_post_urlencoded :								\
	(method == RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING ? rrr_http_method_str_post_urlencoded_no_quoting :		\
	(method == RRR_HTTP_METHOD_POST_APPLICATION_OCTET_STREAM ? rrr_http_method_str_post_application_octet_stream :	\
	(method == RRR_HTTP_METHOD_POST_TEXT_PLAIN ? rrr_http_method_str_post_application_text_plain : ("unknown")		\
	)))))))))

#define RRR_HTTP_METHOD_TO_STR_CONFORMING(method)																	\
	(method == RRR_HTTP_METHOD_GET ? rrr_http_method_str_get :														\
	(method == RRR_HTTP_METHOD_HEAD ? rrr_http_method_str_head :													\
	(method == RRR_HTTP_METHOD_PUT ? rrr_http_method_str_put :														\
	(method == RRR_HTTP_METHOD_DELETE ? rrr_http_method_str_delete :												\
	rrr_http_method_str_post																						\
	))))

extern const char *rrr_http_upgrade_mode_str_none;
extern const char *rrr_http_upgrade_mode_str_websocket;
extern const char *rrr_http_upgrade_mode_str_http2;

#define RRR_HTTP_UPGRADE_MODE_TO_STR(transport)													\
	(transport == RRR_HTTP_UPGRADE_MODE_NONE ? rrr_http_upgrade_mode_str_none :					\
	(transport == RRR_HTTP_UPGRADE_MODE_WEBSOCKET ? rrr_http_upgrade_mode_str_websocket :		\
	(transport == RRR_HTTP_UPGRADE_MODE_HTTP2 ? rrr_http_upgrade_mode_str_http2 : ("unknown")	\
	)))

extern const char *rrr_http_application_str_http1;
extern const char *rrr_http_application_str_http2;

#define RRR_HTTP_APPLICATION_TO_STR(transport)												\
	(transport == RRR_HTTP_APPLICATION_HTTP1 ? rrr_http_application_str_http1 :				\
	(transport == RRR_HTTP_APPLICATION_HTTP2 ? rrr_http_application_str_http2 : ("unknown")	\
	))

typedef uint64_t rrr_http_unique_id;

#define RRR_HTTP_COMMON_RAW_RECEIVE_CALLBACK_ARGS			\
	const char *data,										\
	size_t data_size,										\
	struct rrr_http_transaction *transaction,				\
	rrr_http_unique_id unique_id,							\
	enum rrr_http_application_type next_protocol_version,	\
	void *arg

#define RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS \
	const void *data, ssize_t data_size, void *arg

#endif /* RRR_HTTP_COMMON_H */
