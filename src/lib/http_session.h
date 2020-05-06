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

#ifndef RRR_HTTP_SESSION_H
#define RRR_HTTP_SESSION_H

#include "http_common.h"
#include "http_fields.h"
#include "http_part.h"

struct rrr_http_session {
	int is_client;
	enum rrr_http_method method;
	char *uri_str;
	char *user_agent;
	struct rrr_http_part *request_part;
	struct rrr_http_part *response_part;
};

struct rrr_net_transport;
struct rrr_net_transport_handle;

int rrr_http_session_transport_ctx_server_new (
		struct rrr_net_transport_handle *handle
);
int rrr_http_session_transport_ctx_client_new (
		struct rrr_net_transport_handle *handle,
		enum rrr_http_method method,
		const char *endpoint,
		const char *user_agent
);
int rrr_http_session_transport_ctx_add_query_field (
		struct rrr_net_transport_handle *handle,
		const char *name,
		const char *value
);
int rrr_http_session_transport_ctx_send_request (
		struct rrr_net_transport_handle *handle,
		const char *host
);
int rrr_http_session_transport_ctx_receive (
		struct rrr_net_transport_handle *handle,
		int (*callback)(struct rrr_http_part *part, void *arg),
		void *callback_arg
);
int rrr_http_session_transport_ctx_send_response (
		struct rrr_net_transport_handle *handle
);

#endif /* RRR_HTTP_SESSION_H */
