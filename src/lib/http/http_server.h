/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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
#include "http_server_common.h"

struct rrr_net_transport;
struct rrr_net_transport_config;
struct rrr_event_queue;

struct rrr_http_server {
	struct rrr_net_transport *transport_http;

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	struct rrr_net_transport *transport_https;
#endif

#if defined(RRR_WITH_HTTP3)
	struct rrr_net_transport *transport_quic;
#endif

	struct rrr_http_server_callbacks callbacks;

	struct rrr_http_rules rules;

	int shutdown_started;
};

void rrr_http_server_destroy (
		struct rrr_http_server *server
);
void rrr_http_server_destroy_void (
		void *server
);
int rrr_http_server_new (
		struct rrr_http_server **target,
		const struct rrr_http_server_callbacks *callbacks
);
void rrr_http_server_set_no_body_parse (
		struct rrr_http_server *server,
		int set
);
void rrr_http_server_set_server_request_max_size (
		struct rrr_http_server *server,
		rrr_biglength set
);
int rrr_http_server_start_plain (
		struct rrr_http_server *server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit
);
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
int rrr_http_server_start_tls (
		struct rrr_http_server *server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit,
		const struct rrr_net_transport_config *net_transport_config_template,
		int net_transport_flags
);
#endif
#if defined(RRR_WITH_HTTP3)
int rrr_http_server_start_quic (
		struct rrr_http_server *server,
		struct rrr_event_queue *queue,
		uint16_t port,
		uint64_t first_read_timeout_ms,
		uint64_t read_timeout_ms,
		rrr_length send_chunk_count_limit,
		const struct rrr_net_transport_config *net_transport_config_template,
		int net_transport_flags
);
#endif
void rrr_http_server_response_available_notify (
		struct rrr_http_server *server
);
void rrr_http_server_start_shutdown (
		struct rrr_http_server *server
);
int rrr_http_server_shutdown_complete (
		struct rrr_http_server *server
);

#endif /* RRR_HTTP_SERVER_H */
