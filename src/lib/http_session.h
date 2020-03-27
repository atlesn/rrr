/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "http_fields.h"
#include "http_part.h"
#include "net_transport.h"

enum rrr_http_method {
	RRR_HTTP_METHOD_GET,
	RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA,
	RRR_HTTP_METHOD_POST_URLENCODED,
	RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING
};

enum rrr_http_transport {
	RRR_HTTP_TRANSPORT_HTTP,
	RRR_HTTP_TRANSPORT_HTTPS
};

struct rrr_http_session {
	struct rrr_net_transport *transport;
	int transport_handle;
	enum rrr_http_method method;
	char *host;
	char *endpoint;
	char *user_agent;
	struct rrr_http_part *request_part;
	struct rrr_http_part *response_part;
	uint16_t port;
};

void rrr_http_session_destroy (struct rrr_http_session *session);
int rrr_http_session_new (
		struct rrr_http_session **target,
		enum rrr_http_transport transport,
		enum rrr_http_method method,
		const char *host,
		uint16_t port,
		const char *endpoint,
		const char *user_agent
);
int rrr_http_session_add_query_field (
		struct rrr_http_session *session,
		const char *name,
		const char *value
);
int rrr_http_session_add_query_field_binary (
		struct rrr_http_session *session,
		const char *name,
		void *value,
		ssize_t size
);
int rrr_http_session_send_request (
		struct rrr_http_session *session
);
int rrr_http_session_receive (
		struct rrr_http_session *session,
		int (*callback)(struct rrr_http_session *session, const char *start, const char *end, void *arg),
		void *callback_arg
);
int rrr_http_session_connect (struct rrr_http_session *session);
void rrr_http_session_close (struct rrr_http_session *session);

#endif /* RRR_HTTP_SESSION_H */
