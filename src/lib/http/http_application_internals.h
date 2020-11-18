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

#define RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS	\
	struct rrr_http_application *application,	\
	struct rrr_net_transport_handle *handle,	\
	const char *host

struct rrr_http_application_constants {
	enum rrr_http_application_type type;
	void (*destroy)(struct rrr_http_application);
	int (*request_send)(RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS);
};

#define RRR_HTTP_APPLICATION_HEAD \
		const struct rrr_http_application_constants *constants

struct rrr_http_application {
	RRR_HTTP_APPLICATION_HEAD;
};

#endif /* RRR_HTTP_APPLICATION_INTERNALS_H */
