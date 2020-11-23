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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "http_common.h"
#include "http_transaction.h"
#include "http_part.h"
#include "http_fields.h"

int rrr_http_transaction_new (
		struct rrr_http_transaction **target,
		enum rrr_http_method method
) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_transaction *result = NULL;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory for transaction in rrr_http_transaction_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((ret = rrr_http_part_new(&result->request_part)) != 0) {
		goto out_free;
	}

	if ((ret = rrr_http_part_new(&result->response_part)) != 0) {
		goto out_free_request;
	}

	if ((result->uri_str = strdup("/")) == NULL) {
		RRR_MSG_0("Could not allocate memory for URI in rrr_http_transaction_new\n");
		ret = 1;
		goto out_free_response;
	}

	result->method = method;
	result->usercount = 1;

	*target = result;

	goto out;
//	out_free_uri:
//		free(result->uri_str);
	out_free_response:
		rrr_http_part_destroy(result->response_part);
	out_free_request:
		rrr_http_part_destroy(result->request_part);
	out_free:
		free(result);
	out:
		return ret;
}

int rrr_http_transaction_response_reset (
		struct rrr_http_transaction *transaction
) {
	return rrr_http_part_prepare(&transaction->response_part);
}

void rrr_http_transaction_decref_if_not_null (
		struct rrr_http_transaction *transaction
) {
	if (transaction == NULL) {
		return;
	}
	if (transaction->usercount == 0) {
		RRR_BUG("BUG: Usercount was already 0 in rrr_http_transaction_decref\n");
	}
	if (--(transaction->usercount) > 0) {
		return;
	}

	RRR_FREE_IF_NOT_NULL(transaction->uri_str);
	rrr_http_part_destroy(transaction->response_part);
	rrr_http_part_destroy(transaction->request_part);
	free(transaction);
}

void rrr_http_transaction_decref_if_not_null_void (
		void *transaction
) {
	rrr_http_transaction_decref_if_not_null(transaction);
}

void rrr_http_transaction_incref (
		struct rrr_http_transaction *transaction
) {
	if (transaction->usercount == 0) {
		RRR_BUG("BUG: Usercount was 0 in rrr_http_transaction_incref\n");
	}

	++(transaction->usercount);
}

int rrr_http_transaction_query_field_add (
		struct rrr_http_transaction *transaction,
		const char *name,
		const char *value,
		ssize_t value_size,
		const char *content_type
) {
	return rrr_http_field_collection_add (
			&transaction->request_part->fields,
			name,
			(name != NULL ? strlen(name) : 0),
			value,
			value_size,
			content_type,
			(content_type != NULL ? strlen(content_type) : 0)
	);
}

void rrr_http_transaction_query_fields_dump (
		struct rrr_http_transaction *transaction
) {
	rrr_http_field_collection_dump(&transaction->request_part->fields);
}

int rrr_http_transaction_keepalive_set (
		struct rrr_http_transaction *transaction,
		int set
) {
	int ret = 0;

	rrr_http_part_header_field_remove(transaction->request_part, "Connection");

	if (set) {
		ret = rrr_http_part_header_field_push(transaction->request_part, "Connection", "keep-alive");
	}

	return ret;
}

int rrr_http_transaction_endpoint_set (
		struct rrr_http_transaction *transaction,
		const char *endpoint
) {
	RRR_FREE_IF_NOT_NULL(transaction->uri_str);

	if (endpoint != NULL && *endpoint != '\0') {
		transaction->uri_str = strdup(endpoint);
	}
	else {
		transaction->uri_str = strdup("/");
	}

	if (transaction->uri_str == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_transaction_endpoint_set\n");
		return 1;
	}

	return 0;
}
