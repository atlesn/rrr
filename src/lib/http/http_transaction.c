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
#include "http_part_multipart.h"
#include "http_fields.h"

int rrr_http_transaction_new (
		struct rrr_http_transaction **target,
		enum rrr_http_method method,
		void **application_data,
		void (*application_data_destroy)(void *arg)
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

	if (application_data != NULL) {
		result->application_data = *application_data;
		result->application_data_destroy = application_data_destroy;
		*application_data = NULL;
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
	rrr_nullsafe_str_destroy_if_not_null(&transaction->send_data_tmp);
	if (transaction->application_data != NULL) {
		transaction->application_data_destroy(transaction->application_data);
	}
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

int rrr_http_transaction_endpoint_with_query_string_create (
		char **new_endpoint,
		struct rrr_http_transaction *transaction
) {
	*new_endpoint = NULL;

	int ret = 0;

	char *uri_tmp = NULL;

	rrr_length extra_uri_size = 0;
	char *extra_uri_tmp = NULL;

	if (transaction->method != RRR_HTTP_METHOD_GET || RRR_LL_COUNT(&transaction->request_part->fields) > 0) {
		if ((uri_tmp = strdup(transaction->uri_str)) == NULL) {
			RRR_MSG_0("Could not allocate memory for new URI in rrr_http_transaction_endpoint_with_query_string_create\n");
			ret = 1;
			goto out;
		}
		goto out_save;
	}

	extra_uri_tmp = rrr_http_field_collection_to_urlencoded_form_data(&extra_uri_size, &transaction->request_part->fields);

	const char *extra_uri_separator;
	if (strchr(transaction->uri_str, '?') != NULL) {
		// Append to existing ?-query string in GET URI
		extra_uri_separator = "&";
	}
	else {
		extra_uri_separator = "?";
	}

	rrr_biglength uri_orig_len = strlen(transaction->uri_str);
	RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(uri_orig_len,"rrr_http_application_http1_request_send");

	if ((uri_tmp = malloc(uri_orig_len + extra_uri_size + 1 + 1)) == NULL) { // + separator + 0
		RRR_MSG_0("Could not allocate memory for new URI in rrr_http_transaction_endpoint_with_query_string_create\n");
		ret = 1;
		goto out;
	}

	char *wpos = uri_tmp;

	memcpy(wpos, transaction->uri_str, uri_orig_len);
	wpos += uri_orig_len;

	*wpos = *extra_uri_separator;
	wpos++;

	memcpy(wpos, extra_uri_tmp, extra_uri_size);
	wpos += extra_uri_size;

	*wpos = '\0';

	out_save:
	*new_endpoint = uri_tmp;
	uri_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(uri_tmp);
	RRR_FREE_IF_NOT_NULL(extra_uri_tmp);
	return ret;
}

int __rrr_http_transaction_form_data_make_if_needed_chunk_callback (
		RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS
) {
	struct rrr_http_transaction *transaction = arg;
	return rrr_nullsafe_str_append(transaction->send_data_tmp, data, data_size);
}

int rrr_http_transaction_form_data_generate_if_needed (
		int *form_data_was_made,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	*form_data_was_made = 0;

	if (transaction->method == RRR_HTTP_METHOD_GET || RRR_LL_COUNT(&transaction->request_part->fields) == 0) {
		goto out;
	}

	transaction->send_data_pos = 0;
	if ((ret = rrr_nullsafe_str_new_or_replace(&transaction->send_data_tmp, NULL, 0)) != 0) {
		goto out;
	}

	if (transaction->method == RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA) {
		if ((ret = rrr_http_part_multipart_form_data_make(transaction->request_part, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}
	else if (transaction->method == RRR_HTTP_METHOD_POST_URLENCODED) {
		if ((ret = rrr_http_part_post_x_www_form_body_make(transaction->request_part, 0, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}
	else if (transaction->method == RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING) {
		// Application may choose to quote itself (influxdb has special quoting)
		if ((ret = rrr_http_part_post_x_www_form_body_make(transaction->request_part, 1, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}

	// TODO : If we use plain text or octet stream method, simply concatenate and encode all fields

	else {
		RRR_MSG_0("Unknown HTTP request method %s for request with fields set\n", RRR_HTTP_METHOD_TO_STR(transaction->method));
		ret = 1;
		goto out;
	}

	*form_data_was_made = 1;

	out:
	return ret;
}
