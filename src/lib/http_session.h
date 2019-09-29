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
#include "rrr_socket_read.h"

enum rrr_http_method {
	RRR_HTTP_METHOD_GET,
	RRR_HTTP_METHOD_POST
};

struct rrr_http_part;

struct rrr_http_session {
	int fd;
	enum rrr_http_method method;
	char *host;
	char *endpoint;
	struct rrr_http_field_collection fields;
	char *user_agent;
	struct rrr_http_part *data;
	struct rrr_socket_read_session_collection read_sessions;
	uint16_t port;
};

void rrr_http_session_destroy (struct rrr_http_session *session);
int rrr_http_session_new (
		struct rrr_http_session **target,
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
		int (*callback)(struct rrr_http_session *session, void *arg),
		void *callback_arg
);
int rrr_http_session_connect (struct rrr_http_session *session);
void rrr_http_session_close (struct rrr_http_session *session);

#endif /* RRR_HTTP_SESSION_H */
