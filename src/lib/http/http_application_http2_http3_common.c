/*

Read Route Record

Copyright (C) 2020-2022 Atle Solbakken atle@goliathdns.no

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

#include "http_application_http2_http3_common.h"
#include "http_application.h"
#include "http_application_internals.h"
#include "http_common.h"
#include "http_transaction.h"
#include "http_part.h"
#include "http_part_parse.h"

#include <assert.h>

int rrr_http_application_http2_http3_common_stream_read_end (
		struct rrr_http_application *application,
		int is_server,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_transaction *transaction,
		int64_t stream_id,
		const char *stream_error_msg,
		const struct rrr_http_rules *rules,
		const void *data,
		rrr_biglength data_size,
		int (*response_submit_callback)(struct rrr_http_application *app, struct rrr_http_transaction *transaction, int64_t stream_id, void *arg),
		void *response_submit_callback_arg
) {
	int ret = 0;

	if (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_DELIVERED)) {
		// Data or error already delivered to callback
		goto out;
	}

	if (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_STREAM_ERROR)) {
		rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_DELIVERED);

		if (application->callbacks.callback_arg == NULL) {
			if (is_server) {
				RRR_DBG_3("HTTP stream error from client: %s\n", stream_error_msg != NULL ? stream_error_msg : "(unknown error)");
			}
			else {
				RRR_MSG_0("HTTP request failed and no failure delivery is defined. Data is lost.\n");
			}
			goto out;
		}

		ret = application->callbacks.failure_callback (
				handle,
				transaction,
				stream_error_msg,
				application->callbacks.callback_arg
		);

		goto out;
	}

	if (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_STREAM_CLOSE|RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_DELIVERED)) {
		printf("Data stream closing and data delivered\n");
		// Stream is closing and data is delivered
		goto out;
	}

	if (!rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_END)) {
		printf("Wait for data\n");
		// Wait for any DATA frames and END DATA
		goto out;
	}

	assert (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_HEADERS_END));

	if (is_server) {
		// Is server

		const struct rrr_http_header_field *path = rrr_http_part_header_field_get(transaction->request_part, ":path");
		const struct rrr_http_header_field *method = rrr_http_part_header_field_get(transaction->request_part, ":method");

		if (method == NULL) {
			RRR_DBG_3("http field :method missing in request\n");
			goto out_send_response_bad_request;
		}

		if (path == NULL) {
			RRR_DBG_3("http field :path missing in request\n");
			goto out_send_response_bad_request;
		}

		// Set data which is otherwise set by the parser in HTTP/1.1
		if ((ret = rrr_http_part_parse_request_data_set (
				transaction->request_part,
				data_size,
				application->constants->type,
				RRR_HTTP_VERSION_UNSPECIFIED,
				method->value,
				path->value
		)) != 0) {
			if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
				goto out_send_response_bad_request;
			}
			goto out;
		}

		if ((ret = rrr_http_part_multipart_and_fields_process (transaction->request_part, data, rules->do_no_body_parse)) != 0) {
			if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
				goto out_send_response_bad_request;
			}
			goto out;
		}

		if (RRR_DEBUGLEVEL_3) {
			rrr_http_field_collection_dump (&transaction->request_part->fields);
		}
	}
	else {
		// Is client

		const struct rrr_http_header_field *status = rrr_http_part_header_field_get(transaction->response_part, ":status");
		if (status == NULL) {
			RRR_MSG_0("Field :status missing in HTTP response header\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		if (transaction->response_part->response_code != 0) {
			// Looks like we received data on the stream when we did not expect it, ignore the data
			goto out;
		}

		if (status->value_unsigned > 999) {
			RRR_MSG_0("Field :status contains invalid value %llu in HTTP response header\n",
					status->value_unsigned);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		transaction->response_part->response_code = (unsigned int) status->value_unsigned;

		const struct rrr_http_header_field *content_length = rrr_http_part_header_field_get(transaction->response_part, "content-length");
		if (content_length != NULL && content_length->value_unsigned != data_size) {
			RRR_MSG_0("Malformed HTTP2 response. Reported content-length was %llu while actual data length was %llu\n",
					(unsigned long long) content_length->value_unsigned, (unsigned long long) data_size);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		if ((ret = rrr_http_part_parse_response_data_set (transaction->response_part, data_size)) != 0) {
			goto out;
		}
	}

	rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_DELIVERED);

	if ((ret = application->callbacks.callback (
			handle,
			transaction,
			data,
			0,
			RRR_HTTP_APPLICATION_HTTP2,
			application->callbacks.callback_arg
	)) != 0) {
		if (is_server) {
			// Is server

			if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
				goto out_send_response_bad_request;
			}
			else if (ret == RRR_HTTP_NO_RESULT) {
				transaction->need_response = 1;
				ret = 0;
			}
		}
		goto out;
	}

	if (application->callbacks.unique_id_generator_callback != NULL) {
		// Is server
		goto out_send_response;
	}

	// Is client
	goto out;

	out_send_response_bad_request:
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
	out_send_response:
		if (transaction->response_part->response_code != 0) {
			RRR_DBG_3("HTTP submit response %u\n", transaction->response_part->response_code);

			if ((ret = response_submit_callback (
					application,
					transaction,
					stream_id,
					response_submit_callback_arg
			)) != 0) {
				goto out;
			}
		}
	out:
	return ret;

}
