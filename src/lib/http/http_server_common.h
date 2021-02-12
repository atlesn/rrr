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

#ifndef RRR_HTTP_SERVER_COMMON_H
#define RRR_HTTP_SERVER_COMMON_H

#include <stdio.h>

#include "http_common.h"
#include "http_session.h"

struct rrr_thread;

#define RRR_HTTP_SERVER_WORKER_RECEIVE_CALLBACK_ARGS           \
    struct rrr_thread *thread,                                 \
    const struct sockaddr *sockaddr,                           \
    socklen_t socklen,                                         \
    RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS

#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS    \
    void **websocket_application_data,                              \
    RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS

#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_FRAME_CALLBACK_ARGS   \
    void **websocket_application_data,                         \
    const struct sockaddr *addr,                               \
    socklen_t addr_len,                                        \
    RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS

#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS \
    void **websocket_application_data,                              \
    RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS

struct rrr_http_server_callbacks {
	int (*unique_id_generator_callback)(RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS);
	void *unique_id_generator_callback_arg;
	int (*websocket_handshake_callback)(RRR_HTTP_SERVER_WORKER_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS);
	void *websocket_handshake_callback_arg;
	int (*websocket_frame_callback)(RRR_HTTP_SERVER_WORKER_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *websocket_frame_callback_arg;
	int (*websocket_get_response_callback)(RRR_HTTP_SERVER_WORKER_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS);
	void *websocket_get_response_callback_arg;
	int (*final_callback)(RRR_HTTP_SERVER_WORKER_RECEIVE_CALLBACK_ARGS);
	void *final_callback_arg;
};

#endif /* RRR_HTTP_SERVER_COMMON_H */
