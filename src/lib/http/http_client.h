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

#ifndef RRR_HTTP_CLIENT_H
#define RRR_HTTP_CLIENT_H

#include <inttypes.h>
#include <sys/types.h>

#include "http_common.h"

#define RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS				\
		struct rrr_http_client_data *data, 				\
		int response_code,								\
		const char *response_argument,					\
		int chunk_idx,									\
		int chunk_total,								\
		const char *data_start,							\
		ssize_t data_size,								\
		void *arg

struct rrr_http_client_data {
	char *protocol;
	char *server;
	char *endpoint;
	char *query;
	char *user_agent;
	uint16_t http_port;
	int plain_force;
	int ssl_force;
	int ssl_no_cert_verify;

	int do_retry;
};

struct rrr_http_client_receive_callback_data {
	int response_code;
	char *response_argument;

	// Errors do not propagate through net transport framework. Return
	// value of http callbacks is saved here.
	int http_receive_ret;

	struct rrr_http_client_data *data;
	int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS);
	void *final_callback_arg;
};

int rrr_http_client_data_init (
		struct rrr_http_client_data *data,
		const char *user_agent
);
void rrr_http_client_data_cleanup (
		struct rrr_http_client_data *data
);
// Note that data in the struct may change if there are any redirects
int rrr_http_client_send_request (
		struct rrr_http_client_data *data,
		int (*final_callback)(RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);


#endif /* RRR_HTTP_CLIENT_H */
