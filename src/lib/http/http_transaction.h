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

#ifndef RRR_HTTP_TRANSACTION_H
#define RRR_HTTP_TRANSACTION_H

#include <stdint.h>
#include <stdio.h>

#include "http_common.h"
#include "../string_builder.h"

struct rrr_http_part;

struct rrr_http_transaction {
	int usercount;

	enum rrr_http_method method;
	enum rrr_http_body_format body_format;
	char *endpoint_str;

	struct rrr_nullsafe_str *request_body_raw;

	struct rrr_http_part *request_part;
	struct rrr_http_part *response_part;

	rrr_length send_data_pos;
	struct rrr_nullsafe_str *send_data_tmp;

	rrr_biglength remaining_redirects;

	void *application_data;
	void (*application_data_destroy)(void *arg);
};

int rrr_http_transaction_new (
		struct rrr_http_transaction **target,
		enum rrr_http_method method,
		rrr_biglength remaining_redirects,
		void **application_data,
		void (*application_data_destroy)(void *arg)
);
int rrr_http_transaction_response_reset (
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_request_reset (
		struct rrr_http_transaction *transaction
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
void rrr_http_transaction_method_set (
		struct rrr_http_transaction *transaction,
		enum rrr_http_method method
);
int rrr_http_transaction_endpoint_set (
		struct rrr_http_transaction *transaction,
		const char *endpoint
);
void rrr_http_transaction_body_format_set (
		struct rrr_http_transaction *transaction,
		enum rrr_http_body_format body_format
);
int rrr_http_transaction_request_body_set_allocated (
		struct rrr_http_transaction *transaction,
		void **data,
		rrr_length data_size
);
int rrr_http_transaction_endpoint_path_get (
		char **result,
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_endpoint_with_query_string_create (
		struct rrr_nullsafe_str **target,
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_form_data_generate_if_needed (
		int *form_data_was_made,
		struct rrr_http_transaction *transaction
);

#endif /* RRR_HTTP_TRANSACTION_H */
