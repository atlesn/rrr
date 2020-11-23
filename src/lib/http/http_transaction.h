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

#ifndef RRR_HTTP_TRANSACTION_H
#define RRR_HTTP_TRANSACTION_H

#include <stdint.h>
#include <stdio.h>

#include "http_common.h"

struct rrr_http_part;

struct rrr_http_transaction {
	int usercount;
	uint64_t id;

	enum rrr_http_method method;
	char *uri_str;

	struct rrr_http_part *request_part;
	struct rrr_http_part *response_part;
};

int rrr_http_transaction_new (
		struct rrr_http_transaction **target,
		enum rrr_http_method method,
		uint64_t id
);
void rrr_http_transaction_decref_if_not_null (
		struct rrr_http_transaction *transaction
);
void rrr_http_transaction_decref_if_not_null_void (
		void *transaction
);
void rrr_http_transaction_incref (
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_query_field_add (
		struct rrr_http_transaction *transaction,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
);
void rrr_http_transaction_query_fields_dump (
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_keepalive_set (
		struct rrr_http_transaction *transaction,
		int set
);
int rrr_http_transaction_endpoint_set (
		struct rrr_http_transaction *transaction,
		const char *endpoint
);

#endif /* RRR_HTTP_TRANSACTION_H */
