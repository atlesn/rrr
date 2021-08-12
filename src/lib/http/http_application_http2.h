/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_APPLICATION_HTTP2_H
#define RRR_HTTP_APPLICATION_HTTP2_H

#include "../rrr_types.h"
#include "http_transaction.h"

struct rrr_http_application;

void rrr_http_application_http2_alpn_protos_get (
		const char **target,
		unsigned int *length
);
int rrr_http_application_http2_new (
		struct rrr_http_application **target,
		int is_server,
		void **initial_receive_data,
		rrr_length initial_receive_data_len
);
int rrr_http_application_http2_new_from_upgrade (
		struct rrr_http_application **target,
		void **initial_receive_data,
		rrr_length initial_receive_data_len,
		struct rrr_http_transaction *transaction,
		int is_server
);
int rrr_http_application_http2_response_submit (
		struct rrr_http_application *app,
		struct rrr_http_transaction *transaction,
		int32_t stream_id
);
int rrr_http_application_http2_response_to_upgrade_submit (
		struct rrr_http_application *app,
		struct rrr_http_transaction *transaction
);
void rrr_http_application_http2_response_to_upgrade_async_prepare (
		struct rrr_http_application *app,
		struct rrr_http_transaction *transaction
);

#endif /* RRR_HTTP_APPLICATION_HTTP2_H */
