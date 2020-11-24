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
#include "http_header_fields.h"
#include "../http2/http2.h"
#include "../helpers/nullsafe_str.h"
#include "../util/base64.h"
#include "../util/macro_utils.h"

struct rrr_http_application_http2 {
	RRR_HTTP_APPLICATION_HEAD;
	struct rrr_http2_session *http2_session;
};

static const char rrr_http_application_http2_alpn_protos[] = {
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
	printf("HTTP2 request send\n");
	return 0;
}

static int __rrr_http_application_http2_response_send (
		RRR_HTTP_APPLICATION_RESPONSE_SEND_ARGS
) {

}

struct rrr_http_application_http2_callback_data {
	struct rrr_net_transport_handle *handle;
	uint64_t unique_id;
	int is_client;
	int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_application_http2_callback (
		RRR_HTTP2_GET_RESPONSE_CALLBACK_ARGS
) {
	struct rrr_http_application_http2_callback_data *callback_data = callback_arg;

	int ret = 0;

	struct rrr_http_transaction *transaction = stream_application_data;

	if (callback_data->is_client) {
		if (RRR_LL_COUNT(&transaction->response_part->headers) != 0) {
			RRR_BUG("BUG: Header field list in response part not empty in __rrr_http_application_http2_callback\n");
		}

		RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&transaction->response_part->headers, headers);

		const struct rrr_http_header_field *status = rrr_http_part_header_field_get(transaction->response_part, ":status");
		if (status == NULL) {
			RRR_MSG_0("Field :status missing in HTTP2 response header\n");
			return RRR_HTTP2_SOFT_ERROR;
		}

		transaction->response_part->response_code = status->value_unsigned;
		transaction->response_part->data_length = data_size;
		transaction->response_part->parse_complete = 1;
		transaction->response_part->header_complete = 1;
		transaction->response_part->parsed_protocol_version = 1;
	}
	else {
		RRR_BUG("BUG: Server mode not implemented in __rrr_http_application_http2_callback\n");
	}

	return callback_data->callback (
			callback_data->handle,
			transaction,
			data,
			0,
			callback_data->unique_id,
			callback_data->callback_arg
	);
}

static int __rrr_http_application_http2_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	int ret = 0;

	struct rrr_http_application_http2_callback_data callback_data = {
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
	__rrr_http_application_http2_response_send,
	__rrr_http_application_http2_tick,
	__rrr_http_application_http2_alpn_protos_get,
	__rrr_http_application_http2_polite_close
};

static int __rrr_http_application_http2_new (
		struct rrr_http_application_http2 **target,
		void **initial_receive_data,
		size_t initial_receive_data_len
) {
	struct rrr_http_application_http2 *result = NULL;

	int ret = 0;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_application_http2_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((ret = rrr_http2_session_client_new_or_reset (
			&result->http2_session,
			initial_receive_data,
			initial_receive_data_len
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
		struct rrr_http_application **target
) {
	return __rrr_http_application_http2_new((struct rrr_http_application_http2 **) target, NULL, 0);
}

static int __rrr_http_application_http2_upgrade_postprocess (
		struct rrr_http_application_http2 *app,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	char *orig_http2_settings_tmp = NULL;

	if ((ret = rrr_http_transaction_response_reset(transaction)) != 0) {
		goto out;
	}

	const struct rrr_http_header_field *orig_http2_settings = rrr_http_part_header_field_get_raw(transaction->request_part, "http2-settings");
	if (orig_http2_settings == NULL) {
		RRR_BUG("BUG: Original HTTP2-Settings field not present in request upon upgrade in __rrr_application_http1_response_receive_callback\n");
	}

	size_t orig_http2_settings_length = 0;
	orig_http2_settings_tmp = (char *) rrr_base64url_decode(orig_http2_settings->value->str, orig_http2_settings->value->len, &orig_http2_settings_length);

	if ((ret = rrr_http2_session_client_upgrade_postprocess(app->http2_session, orig_http2_settings_tmp, orig_http2_settings_length)) != 0) {
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
		struct rrr_http_transaction *transaction
) {
	struct rrr_http_application_http2 *result = NULL;

	int ret = 0;

	*target = NULL;

	if ((ret = __rrr_http_application_http2_new (&result, initial_receive_data, initial_receive_data_len)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_application_http2_upgrade_postprocess (
			result,
			transaction
	)) != 0) {
		goto out_destroy;
	}

	*target = (struct rrr_http_application *) result;

	goto out;
	out_destroy:
		__rrr_http_application_http2_destroy((struct rrr_http_application *) result);
	out:
		return ret;
}
