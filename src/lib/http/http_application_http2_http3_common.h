/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_APPLICATION_HTTP2_HTTP3_COMMON_H
#define RRR_HTTP_APPLICATION_HTTP2_HTTP3_COMMON_H

#include "../rrr_types.h"

struct rrr_http_application;
struct rrr_net_transport_handle;
struct rrr_http_transaction;
struct rrr_http_rules;

int rrr_http_application_http2_http3_common_stream_read_end (
		struct rrr_http_application *application,
		int is_server,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_transaction *transaction,
		int64_t stream_id,
		const char *stream_error_msg,
		const struct rrr_http_rules *rules,
		void *data,
		rrr_biglength data_size,
		int (*response_submit_callback)(struct rrr_http_application *app, struct rrr_http_transaction *transaction, int64_t stream_id, void *arg),
		void *response_submit_callback_arg
);

#endif /* RRR_HTTP_APPLICATION_HTTP2_HTTP3_COMMON_H */
