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

#ifndef RRR_HTTP_SERVER_H
#define RRR_HTTP_SERVER_H

#include <stdint.h>

#include "http_session.h"

struct rrr_net_transport;
struct rrr_thread_collection;
struct rrr_net_transport_config;
struct rrr_http_part;

struct rrr_http_server {
	struct rrr_net_transport *transport_http;
	struct rrr_net_transport *transport_https;

	int handle_http;
	int handle_https;

	struct rrr_thread_collection *threads;
};

void rrr_http_server_destroy (
		struct rrr_http_server *server
);
void rrr_http_server_destroy_void (
		void *server
);
int rrr_http_server_new (
		struct rrr_http_server **target
);
int rrr_http_server_start_plain (
		struct rrr_http_server *server,
		uint16_t port
);
int rrr_http_server_start_tls (
		struct rrr_http_server *server,
		uint16_t port,
		const struct rrr_net_transport_config *net_transport_config_template,
		int net_transport_flags
);
int rrr_http_server_tick (
		int *accept_count_final,
		struct rrr_http_server *server,
		int (*final_callback)(RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS),
		void *final_callback_arg
);

#endif /* RRR_HTTP_SERVER_H */
