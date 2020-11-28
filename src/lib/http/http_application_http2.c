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
#include "http_application.h"
#include "http_application_http2.h"
#include "http_application_internals.h"
#include "http_transaction.h"
#include "http_part.h"
#include "http_part_parse.h"
#include "http_part_multipart.h"
#include "http_header_fields.h"
#include "http_util.h"
#include "../net_transport/net_transport.h"
#include "../http2/http2.h"
#include "../helpers/nullsafe_str.h"
#include "../util/base64.h"
#include "../util/macro_utils.h"

struct rrr_http_application_http2 {
	RRR_HTTP_APPLICATION_HEAD;
	struct rrr_http2_session *http2_session;
};

static const char rrr_http_application_http2_alpn_protos[] = {
	     2, 'h', '2',
	     6, 'h', 't', 't', 'p', '/', '2',
	     8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

static void __rrr_http_application_http2_destroy (struct rrr_http_application *app) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;
	rrr_http2_session_destroy_if_not_null(&http2->http2_session);
	free(http2);
}

static int __rrr_http_application_http2_request_send (
		RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) application;

	int ret = 0;

	char *endpoint_tmp = NULL;

	int32_t stream_id = 0;

	int form_data_was_made = 0;
	if ((ret = rrr_http_transaction_form_data_generate_if_needed (&form_data_was_made, transaction)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_transaction_endpoint_with_query_string_create(&endpoint_tmp, transaction)) != 0) {
		goto out;
	}

	if  ((ret = rrr_http2_request_submit (
			&stream_id,
			http2->http2_session,
			rrr_net_transport_ctx_is_tls(handle),
			transaction->method,
			host,
			endpoint_tmp
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_http2_session_stream_application_data_set (
			http2->http2_session,
			stream_id,
			transaction,
			rrr_http_transaction_decref_if_not_null_void
	)) != 0) {
		goto out;
	}

	rrr_http_transaction_incref(transaction);

	out:
	RRR_FREE_IF_NOT_NULL(endpoint_tmp);
	return ret;
}

struct rrr_http_application_http2_callback_data {
	struct rrr_http_application_http2 *http2;
	struct rrr_net_transport_handle *handle;
	uint64_t unique_id;
	int is_client;
	int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_application_http2_callback (
		RRR_HTTP2_DATA_CALLBACK_ARGS
) {
	struct rrr_http_application_http2_callback_data *callback_data = callback_arg;

	int ret = 0;

	struct rrr_http_transaction *transaction_to_destroy = NULL;
	struct rrr_http_transaction *transaction = stream_application_data;

	if (callback_data->is_client) {
		if (RRR_LL_COUNT(&transaction->response_part->headers) != 0) {
			RRR_BUG("BUG: Header field list in response part not empty in __rrr_http_application_http2_callback\n");
		}

		RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&transaction->response_part->headers, headers);

		const struct rrr_http_header_field *status = rrr_http_part_header_field_get(transaction->response_part, ":status");
		if (status == NULL) {
			RRR_MSG_0("Field :status missing in HTTP2 response header\n");
			ret = RRR_HTTP2_SOFT_ERROR;
			goto out;
		}

		const struct rrr_http_header_field *content_length = rrr_http_part_header_field_get(transaction->response_part, "content-length");
		if (content_length != NULL && content_length->value_unsigned != 0) {
			// Wait for DATA frames and END DATA
			goto out;
		}

		if (transaction->response_part->response_code != 0) {
			// Looks like we received data on the stream when we did not expect it, ignore the data
			goto out;
		}

		transaction->response_part->response_code = status->value_unsigned;
	}
	else {
		if (transaction == NULL) {
			if ((ret = rrr_http_transaction_new(&transaction_to_destroy, 0)) != 0) {
				RRR_MSG_0("Could not create transaction in __rrr_http_application_http2_callback\n");
				goto out;
			}
			if ((ret = rrr_http2_session_stream_application_data_set(callback_data->http2->http2_session, stream_id, transaction_to_destroy, rrr_http_transaction_decref_if_not_null_void)) != 0) {
				goto out;
			}
			// Don't set to NULL, will be decrefed at function out
			rrr_http_transaction_incref(transaction_to_destroy);
			transaction = transaction_to_destroy;
		}

		RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&transaction->request_part->headers, headers);

		const struct rrr_http_header_field *post = rrr_http_part_header_field_get_with_value_case(transaction->request_part, ":method", "POST");
		const struct rrr_http_header_field *put = rrr_http_part_header_field_get_with_value_case(transaction->request_part, ":method", "PUT");

		const struct rrr_http_header_field *path = rrr_http_part_header_field_get(transaction->request_part, ":path");
		const struct rrr_http_header_field *method = rrr_http_part_header_field_get(transaction->request_part, ":method");
		const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(transaction->request_part, "content-type");

		if (method == NULL) {
			RRR_DBG_3("http2 field :method missing in request\n");
			goto out_send_response_bad_request;
		}

		if (path == NULL) {
			RRR_DBG_3("http2 field :path missing in request\n");
			goto out_send_response_bad_request;
		}

		if ((post || put) && (data == NULL || data_size == 0)) {
			// Wait for DATA frames and END DATA
			goto out;
		}

		if (transaction->request_part->parse_complete) {
			// Looks like we received data on the stream when we did not expect it, ignore the data
			goto out;
		}

		// Set data which is otherwise set by the parser in HTTP/1.1
		if ((ret = rrr_http_part_parse_request_data_set (
				transaction->request_part,
				data_size,
				RRR_HTTP_APPLICATION_HTTP2,
				method->value,
				path->value,
				(content_type != NULL ? content_type->value : NULL)
		)) != 0) {
			if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
				goto out_send_response_bad_request;
			}
			goto out;
		}

		if ((ret = rrr_http_part_multipart_process(transaction->request_part, data)) != 0) {
			if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
				goto out_send_response_bad_request;
			}
			goto out;
		}

		if ((ret = rrr_http_part_post_and_query_fields_extract(transaction->request_part, data)) != 0) {
			if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
				goto out_send_response_bad_request;
			}
			goto out;
		}
	}

	if ((ret = callback_data->callback (
			callback_data->handle,
			transaction,
			data,
			0,
			callback_data->unique_id,
			callback_data->callback_arg
	)) != 0) {
		if (ret == RRR_HTTP_PARSE_SOFT_ERR) {
			goto out_send_response_bad_request;
		}
		goto out;
	}

	if (!callback_data->is_client) {
		goto out_send_response;
	}

	goto out;
	out_send_response_bad_request:
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
	out_send_response:
		if (transaction->response_part->response_code != 0) {
			RRR_DBG_3("HTTP2 submit response %u\n", transaction->response_part->response_code);

			if ((ret = rrr_http_application_http2_response_submit((struct rrr_http_application *) callback_data->http2, transaction, stream_id)) != 0) {
				goto out;
			}
		}
	out:
		rrr_http_transaction_decref_if_not_null(transaction_to_destroy);
	return ret;
}

static int __rrr_http_application_http2_data_source_callback (
		RRR_HTTP2_DATA_SOURCE_CALLBACK_ARGS
) {
	struct rrr_http_application_http2_callback_data *callback_data = callback_arg;

	int ret = 0;

	*done = 0;
	*written_bytes = 0;

	struct rrr_http_transaction *transaction = rrr_http2_session_stream_application_data_get(callback_data->http2->http2_session, stream_id);
	if (transaction == NULL) {
		ret = 1;
		goto out;
	}

	if (transaction->send_data_tmp == NULL || transaction->send_data_pos >= transaction->send_data_tmp->len) {
		*done = 1;
		goto out;
	}

	rrr_length bytes_to_send = transaction->send_data_tmp->len;
	if (bytes_to_send > buf_size) {
		bytes_to_send = buf_size;
	}

	RRR_DBG_3("http2 source %" PRIrrrl "/%" PRIrrrl " bytes to send\n",
			transaction->send_data_tmp->len - transaction->send_data_pos, transaction->send_data_tmp->len);

	memcpy(buf, transaction->send_data_tmp->str, bytes_to_send);
	transaction->send_data_pos += bytes_to_send;
	*written_bytes = bytes_to_send;

	// Saves an extra call to this function
	if (transaction->send_data_pos >= transaction->send_data_tmp->len) {
		RRR_DBG_3("http2 source complete\n", bytes_to_send);
		*done = 1;
	}

	out:
	return ret;
}

static int __rrr_http_application_http2_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	int ret = 0;

	struct rrr_http_application_http2_callback_data callback_data = {
			http2,
			handle,
			unique_id,
			is_client,
			callback,
			callback_arg
	};

	if ((ret = rrr_http2_transport_ctx_tick (
			http2->http2_session,
			handle,
			__rrr_http_application_http2_callback,
			__rrr_http_application_http2_data_source_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void __rrr_http_application_http2_alpn_protos_get (
		RRR_HTTP_APPLICATION_ALPN_PROTOS_GET_ARGS
) {
	*target = rrr_http_application_http2_alpn_protos;
	*length = sizeof(rrr_http_application_http2_alpn_protos);
}

void rrr_http_application_http2_alpn_protos_get (
		const char **target,
		unsigned int *length
) {
	return __rrr_http_application_http2_alpn_protos_get(target, length);
}

static void __rrr_http_application_http2_polite_close (
		RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;
	rrr_http2_transport_ctx_terminate(http2->http2_session, handle);
}

static const struct rrr_http_application_constants rrr_http_application_http2_constants = {
	RRR_HTTP_APPLICATION_HTTP2,
	__rrr_http_application_http2_destroy,
	__rrr_http_application_http2_request_send,
	__rrr_http_application_http2_tick,
	__rrr_http_application_http2_alpn_protos_get,
	__rrr_http_application_http2_polite_close
};

static int __rrr_http_application_http2_new (
		struct rrr_http_application_http2 **target,
		void **initial_receive_data,
		size_t initial_receive_data_len,
		int is_server
) {
	struct rrr_http_application_http2 *result = NULL;

	int ret = 0;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_application_http2_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((ret = rrr_http2_session_new_or_reset (
			&result->http2_session,
			initial_receive_data,
			initial_receive_data_len,
			is_server
	)) != 0) {
		goto out_destroy;
	}

	result->constants = &rrr_http_application_http2_constants;

	*target = result;

	goto out;
	out_destroy:
		__rrr_http_application_http2_destroy((struct rrr_http_application *) result);
	out:
		return ret;
}

int rrr_http_application_http2_new (
		struct rrr_http_application **target,
		int is_server,
		void **initial_receive_data,
		size_t initial_receive_data_len
) {
	int ret = 0;

	if ((ret = __rrr_http_application_http2_new((struct rrr_http_application_http2 **) target, initial_receive_data, initial_receive_data_len, is_server)) != 0) {
		goto out;
	}

	if ((ret = rrr_http2_session_settings_submit(((struct rrr_http_application_http2 *) *target)->http2_session)) != 0) {
		goto out_destroy;
	}

	goto out;
	out_destroy:
		__rrr_http_application_http2_destroy(*target);
	out:
		return ret;
}

static int __rrr_http_application_http2_upgrade_postprocess (
		struct rrr_http_application_http2 *app,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	char *orig_http2_settings_tmp = NULL;

	// The HTTP2-Settings field will always be in the request part regardless of whether we are server or client
	const struct rrr_http_header_field *orig_http2_settings = rrr_http_part_header_field_get_raw(transaction->request_part, "http2-settings");
	if (orig_http2_settings == NULL) {
		RRR_BUG("BUG: Original HTTP2-Settings field not present in request upon upgrade in __rrr_application_http1_response_receive_callback\n");
	}

	size_t orig_http2_settings_length = 0;
	orig_http2_settings_tmp = (char *) rrr_base64url_decode(orig_http2_settings->value->str, orig_http2_settings->value->len, &orig_http2_settings_length);

	if ((ret = rrr_http2_session_upgrade_postprocess (
			app->http2_session,
			orig_http2_settings_tmp,
			orig_http2_settings_length,
			transaction->request_part->request_method
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_http2_session_stream_application_data_set(app->http2_session, 1, transaction, rrr_http_transaction_decref_if_not_null_void)) != 0) {
		goto out;
	}
	rrr_http_transaction_incref(transaction);

	out:
	RRR_FREE_IF_NOT_NULL(orig_http2_settings_tmp);
	return ret;
}

int rrr_http_application_http2_new_from_upgrade (
		struct rrr_http_application **target,
		void **initial_receive_data,
		size_t initial_receive_data_len,
		struct rrr_http_transaction *transaction,
		int is_server
) {
	struct rrr_http_application_http2 *result = NULL;

	int ret = 0;

	*target = NULL;

	if ((ret = __rrr_http_application_http2_new (
			&result,
			initial_receive_data,
			initial_receive_data_len,
			is_server
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_application_http2_upgrade_postprocess (
			result,
			transaction
	)) != 0) {
		goto out_destroy;
	}

	if (is_server && (ret = rrr_http2_session_settings_submit(result->http2_session)) != 0) {
		goto out_destroy;
	}

	*target = (struct rrr_http_application *) result;

	goto out;
	out_destroy:
		__rrr_http_application_http2_destroy((struct rrr_http_application *) result);
	out:
		return ret;
}

struct rrr_http_application_http2_header_fields_submit_callback_data {
	struct rrr_http_application_http2 *app;
	int32_t stream_id;
};

static int __rrr_http_application_http2_header_fields_submit_callback (
		struct rrr_http_header_field *field,
		void *arg
) {
	struct rrr_http_application_http2_header_fields_submit_callback_data *callback_data = arg;

	int ret = 0;

	if (!rrr_nullsafe_str_isset(field->name) || !rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: Name or value was NULL in __rrr_http_application_http2_header_fields_submit_callbacks\n");
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in __rrr_http_application_http2_header_fields_submit_callback, this is not supported\n");
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, field->value);

	if ((ret = rrr_http2_header_submit(callback_data->app->http2_session, 1, name, value)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_application_http2_response_submit (
		struct rrr_http_application *app,
		struct rrr_http_transaction *transaction,
		int32_t stream_id
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	int ret = 0;

	if (rrr_nullsafe_str_len(transaction->response_part->response_raw_data_nullsafe) > 0) {
		rrr_nullsafe_str_move(&transaction->send_data_tmp, &transaction->response_part->response_raw_data_nullsafe);
	}

	int response_code = transaction->response_part->response_code;

	if (response_code == 0) {
		response_code = RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT;
	}

	// Predict that we are going to send data later on stream 1 (during ticking)?
	if (response_code == RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT && rrr_nullsafe_str_len(transaction->send_data_tmp) > 0) {
		response_code = RRR_HTTP_RESPONSE_CODE_OK;
	}

	if ((ret = rrr_http2_header_status_submit(http2->http2_session, stream_id, response_code)) != 0) {
		goto out;
	}

	if (rrr_nullsafe_str_len(transaction->send_data_tmp) > 0) {
		char content_length_str[64];
		sprintf(content_length_str, "%u", rrr_nullsafe_str_len(transaction->send_data_tmp));
		if ((ret = rrr_http2_header_submit(http2->http2_session, stream_id, "content-length", content_length_str)) != 0) {
			goto out;
		}
		if ((ret = rrr_http2_header_submit(http2->http2_session, stream_id, "content-type", "text/plain")) != 0) {
			goto out;
		}
	}

	struct rrr_http_application_http2_header_fields_submit_callback_data callback_data = {
			http2,
			stream_id
	};

	if ((ret = rrr_http_part_header_fields_iterate (
			transaction->response_part,
			__rrr_http_application_http2_header_fields_submit_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_http2_headers_end(http2->http2_session, stream_id)) != 0) {
		goto out;
	}

	// Misc. callbacks will product the actual response during ticking, if any
	if ((ret = rrr_http2_data_submit(http2->http2_session, stream_id)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_application_http2_response_to_upgrade_submit (
		struct rrr_http_application *app,
		struct rrr_http_transaction *transaction
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	int ret = 0;

	if ((ret = rrr_http_application_http2_response_submit (
			app,
			transaction,
			1 // Stream-ID is always one when we upgrade
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
