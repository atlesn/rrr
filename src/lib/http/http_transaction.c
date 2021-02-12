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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "http_common.h"
#include "http_transaction.h"
#include "http_part.h"
#include "http_part_multipart.h"
#include "http_fields.h"
#include "../util/rrr_time.h"

int rrr_http_transaction_new (
		struct rrr_http_transaction **target,
		enum rrr_http_method method,
		enum rrr_http_body_format format,
		rrr_biglength remaining_redirects,
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

	if ((result->endpoint_str = strdup("/")) == NULL) {
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
	result->request_body_format = format;
	result->usercount = 1;
	result->remaining_redirects = remaining_redirects;
	result->creation_time = rrr_time_get_64();

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

int rrr_http_transaction_request_reset (
		struct rrr_http_transaction *transaction
) {
	return rrr_http_part_prepare(&transaction->request_part);
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

	if (RRR_DEBUGLEVEL_3) {
		uint64_t total_time = rrr_time_get_64() - transaction->creation_time;
		RRR_MSG_3("HTTP Transaction lifetime at destruction: %" PRIu64 " ms\n", total_time / 1000);
	}

	RRR_FREE_IF_NOT_NULL(transaction->endpoint_str);
	rrr_http_part_destroy(transaction->response_part);
	rrr_http_part_destroy(transaction->request_part);
	rrr_nullsafe_str_destroy_if_not_null(&transaction->send_body);
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
		const char *content_type,
		const struct rrr_type_value *value_orig
) {
	return rrr_http_field_collection_add (
			&transaction->request_part->fields,
			name,
			(name != NULL ? strlen(name) : 0),
			value,
			value_size,
			content_type,
			(content_type != NULL ? strlen(content_type) : 0),
			value_orig
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

void rrr_http_transaction_method_set (
		struct rrr_http_transaction *transaction,
		enum rrr_http_method method
) {
	transaction->method = method;
}

int rrr_http_transaction_endpoint_set (
		struct rrr_http_transaction *transaction,
		const char *endpoint
) {
	RRR_FREE_IF_NOT_NULL(transaction->endpoint_str);

	if (endpoint != NULL && *endpoint != '\0') {
		transaction->endpoint_str = strdup(endpoint);
	}
	else {
		transaction->endpoint_str = strdup("/");
	}

	if (transaction->endpoint_str == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_transaction_endpoint_set\n");
		return 1;
	}

	return 0;
}

void rrr_http_transaction_request_body_format_set (
		struct rrr_http_transaction *transaction,
		enum rrr_http_body_format body_format
) {
	transaction->request_body_format = body_format;
}

int rrr_http_transaction_endpoint_path_get (
		char **result,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	*result = NULL;

	char *tmp = strdup(transaction->endpoint_str);
	if (tmp == NULL) {
		RRR_MSG_0("Could not allocate memory in  rrr_http_transaction_endpoint_path_get\n");
		ret = 1;
		goto out;
	}

	char *pos = tmp + strlen(tmp) - 1;
	while (pos >= tmp && *pos != '/') {
		*pos = '\0';
		pos--;
	}

	*result = tmp;

	out:
	return ret;
}

static int __rrr_http_transaction_endpoint_with_query_string_create_urlencoded_form_data_callback (
		struct rrr_nullsafe_str **target,
		void *arg
) {
	struct rrr_http_field_collection *fields = arg;
	return rrr_http_field_collection_to_urlencoded_form_data(target, fields);
}

int rrr_http_transaction_endpoint_with_query_string_create (
		struct rrr_nullsafe_str **target,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	*target = NULL;

	struct rrr_nullsafe_str *result = NULL;

	if ((rrr_nullsafe_str_new_or_replace_empty(&result)) != 0) {
		goto out;
	}

	if ((ret = rrr_nullsafe_str_append_raw(result, transaction->endpoint_str, strlen(transaction->endpoint_str))) != 0) {
		goto out;
	}

	if (transaction->method != RRR_HTTP_METHOD_GET || RRR_LL_COUNT(&transaction->request_part->fields) == 0) {
		goto out_save;
	}

	const char extra_uri_separator = (strchr(transaction->endpoint_str, '?') ? '&' : '?');
	if ((ret = rrr_nullsafe_str_append_raw(result, &extra_uri_separator, 1)) != 0) {
		goto out;
	}

	if ((ret = rrr_nullsafe_str_append_with_creator (
			result,
			__rrr_http_transaction_endpoint_with_query_string_create_urlencoded_form_data_callback,
			&transaction->request_part->fields
	)) != 0) {
		goto out;
	}

	out_save:
	*target = result;
	result = NULL;

	out:
	rrr_nullsafe_str_destroy_if_not_null(&result);
	return ret;
}

int __rrr_http_transaction_form_data_make_if_needed_chunk_callback (
		RRR_HTTP_COMMON_DATA_MAKE_CALLBACK_ARGS
) {
	struct rrr_http_transaction *transaction = arg;
	return rrr_nullsafe_str_append(transaction->send_body, str);
}

int rrr_http_transaction_form_data_generate_if_needed (
		int *form_data_was_made,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	*form_data_was_made = 0;

	if ( (transaction->method != RRR_HTTP_METHOD_PUT && transaction->method != RRR_HTTP_METHOD_POST) ||
	     (RRR_LL_COUNT(&transaction->request_part->fields)) == 0) {
		goto out;
	}

	if ((ret = rrr_nullsafe_str_new_or_replace_raw(&transaction->send_body, NULL, 0)) != 0) {
		goto out;
	}

	if (transaction->request_body_format == RRR_HTTP_BODY_FORMAT_MULTIPART_FORM_DATA) {
		if ((ret = rrr_http_part_multipart_form_data_make(transaction->request_part, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}
	else if (transaction->request_body_format == RRR_HTTP_BODY_FORMAT_URLENCODED) {
		if ((ret = rrr_http_part_post_x_www_form_body_make(transaction->request_part, 0, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}
	else if (transaction->request_body_format == RRR_HTTP_BODY_FORMAT_URLENCODED_NO_QUOTING) {
		// Application may choose to quote by itself (influxdb has special quoting)
		if ((ret = rrr_http_part_post_x_www_form_body_make(transaction->request_part, 1, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}
	else if (transaction->request_body_format == RRR_HTTP_BODY_FORMAT_JSON) {
		if ((ret = rrr_http_part_json_make(transaction->request_part, __rrr_http_transaction_form_data_make_if_needed_chunk_callback, transaction)) != 0) {
			goto out;
		}
	}
	else {
		RRR_MSG_0("Unknown HTTP request body format %s for request with fields set\n", RRR_HTTP_BODY_FORMAT_TO_STR(transaction->request_body_format));
		ret = 1;
		goto out;
	}

	*form_data_was_made = 1;

	out:
	return ret;
}

int rrr_http_transaction_send_body_set (
		struct rrr_http_transaction *transaction,
		const void *data,
		rrr_length data_size
) {
	return rrr_nullsafe_str_new_or_replace_raw (
			&transaction->send_body,
			data,
			data_size
	);
}

int rrr_http_transaction_send_body_set_allocated (
		struct rrr_http_transaction *transaction,
		void **data,
		rrr_length data_size
) {
	return rrr_nullsafe_str_new_or_replace_raw_allocated (
			&transaction->send_body,
			data,
			data_size
	);
}

static int __rrr_http_transaction_part_content_length_set (
		struct rrr_http_transaction *transaction,
		struct rrr_http_part *part
) {
	char content_length_str[64];
	sprintf(content_length_str, "%u", rrr_nullsafe_str_len(transaction->send_body));
	return rrr_http_part_header_field_push_and_replace (part, "content-length", content_length_str);
}

static void __rrr_http_transaction_response_code_ensure (
		struct rrr_http_transaction *transaction
) {
	int response_code = transaction->response_part->response_code;

	if (response_code < 100 || response_code > 599) {
		response_code = rrr_nullsafe_str_len(transaction->send_body) > 0
			? RRR_HTTP_RESPONSE_CODE_OK
			: RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT
		;
	}

	// Predict that we are going to send data later on stream 1 (during ticking)?
	if (response_code == RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT && rrr_nullsafe_str_len(transaction->send_body) > 0) {
		response_code = RRR_HTTP_RESPONSE_CODE_OK;
	}

	RRR_DBG_3("HTTP response code ensured %i => %i\n", transaction->response_part->response_code, response_code);

	transaction->response_part->response_code = response_code;
}

static int __rrr_http_transaction_response_content_length_ensure (
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	if (rrr_nullsafe_str_len(transaction->send_body) > 0 && transaction->response_part->response_code == 204) {
		RRR_MSG_0("HTTP response to send had a body while response code was 204 No Content, this is an error.\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ( rrr_nullsafe_str_len(transaction->send_body) > 0 ||
	     ( transaction->response_part->response_code >= 200 &&
	       transaction->response_part->response_code <= 299 &&
	       transaction->response_part->response_code != 204
	     )
	) {
		if ((ret = __rrr_http_transaction_part_content_length_set(transaction, transaction->response_part)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_http_transaction_response_prepare_wrapper (
		struct rrr_http_transaction *transaction,
		int (*header_field_callback)(struct rrr_http_header_field *field, void *arg),
		int (*response_code_callback)(int response_code, void *arg),
		int (*final_callback)(struct rrr_http_part *response_part, const struct rrr_nullsafe_str *send_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	// The order of the function calls matter

	__rrr_http_transaction_response_code_ensure (transaction);

	if ((ret = __rrr_http_transaction_response_content_length_ensure(transaction)) != 0) {
		goto out;
	}

	if ((ret = response_code_callback (
			transaction->response_part->response_code, callback_arg)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_fields_iterate (
			transaction->response_part,
			header_field_callback,
			callback_arg
	)) != 0) {
		goto out;
	}

	if ((ret = final_callback(transaction->response_part, transaction->send_body, callback_arg)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_transaction_request_prepare_wrapper (
		struct rrr_http_transaction *transaction,
		enum rrr_http_upgrade_mode upgrade_mode,
		const char *user_agent,
		int (*preliminary_callback)(
			enum rrr_http_method method,
			enum rrr_http_upgrade_mode upgrade_mode,
			struct rrr_http_part *request_part,
			const struct rrr_nullsafe_str *request,
			void *arg
		),
		int (*headers_callback)(struct rrr_http_header_field *field, void *arg),
		int (*final_callback)(struct rrr_http_part *request_part, const struct rrr_nullsafe_str *send_body, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_nullsafe_str *request_nullsafe = NULL;

	if ((ret = rrr_http_transaction_endpoint_with_query_string_create(&request_nullsafe, transaction)) != 0) {
		goto out;
	}

	if ((ret = preliminary_callback(transaction->method, upgrade_mode, transaction->request_part, request_nullsafe, callback_arg)) != 0) {
		goto out;
	}

	if (rrr_nullsafe_str_len(transaction->send_body)) {
		if ((ret = rrr_http_part_header_field_push_if_not_exists(transaction->request_part, "content-type", "application/octet-stream")) != 0) {
			goto out;
		}
	}
	else {
		// Note : Might add more headers to request part
		int form_data_was_made_dummy = 0;
		if ((ret = rrr_http_transaction_form_data_generate_if_needed (&form_data_was_made_dummy, transaction)) != 0) {
			goto out;
		}
	}

	if (transaction->method == RRR_HTTP_METHOD_PUT || transaction->method == RRR_HTTP_METHOD_POST) {
		if ((ret = __rrr_http_transaction_part_content_length_set(transaction, transaction->request_part)) != 0) {
			goto out;
		}
	}

	// Don't push Host: here. HTTP1 must push Host: itself, and HTTP2 pushes autority:

	if ((ret = rrr_http_part_header_field_push_and_replace (transaction->request_part, "user-agent", user_agent)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push_and_replace (transaction->request_part, "accept-charset", "UTF-8")) != 0) {
		goto out;
	}

	if (rrr_http_part_header_fields_iterate (
			transaction->request_part,
			headers_callback,
			callback_arg
	) != 0) {
		goto out;
	}

	if ((ret = final_callback(transaction->request_part, transaction->send_body, callback_arg)) != 0) {
		goto out;
	}

	out:
	rrr_nullsafe_str_destroy_if_not_null(&request_nullsafe);
	return ret;
}
