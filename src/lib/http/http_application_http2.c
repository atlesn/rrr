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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../log.h"
#include "../allocator.h"
#include "http_application.h"
#include "http_application_http1.h"
#include "http_application_http2.h"
#include "http_application_http2_http3_common.h"
#include "http_application_internals.h"
#include "http_transaction.h"
#include "http_part.h"
#include "http_part_parse.h"
#include "http_header_fields.h"
#include "http_util.h"
#include "../net_transport/net_transport.h"
#include "../http2/http2.h"
#include "../helpers/nullsafe_str.h"
#include "../util/base64.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"

struct rrr_http_application_http2 {
	RRR_HTTP_APPLICATION_HEAD;
	struct rrr_http2_session *http2_session;
	struct rrr_http_transaction *transaction_incomplete_upgrade;
	int need_slow_tick;
};

static const char rrr_http_application_http2_alpn_protos[] = {
	     2, 'h', '2',
	     6, 'h', 't', 't', 'p', '/', '2',
	     8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

static void __rrr_http_application_http2_destroy (struct rrr_http_application *app) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	if (http2->http2_session != NULL) {
		uint64_t streams = rrr_http2_streams_count_and_maintain(http2->http2_session);
		if (streams > 0) {
			RRR_DBG_2("HTTP2 destroys application with %" PRIu64 " active transactions\n", streams);
		} 
	}

	rrr_http2_session_destroy_if_not_null(&http2->http2_session);
	rrr_http_transaction_decref_if_not_null(http2->transaction_incomplete_upgrade);
	rrr_free(http2);
}

static uint64_t __rrr_http_application_http2_active_transaction_count_get_and_maintain (
		RRR_HTTP_APPLICATION_TRANSACTION_COUNT_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) application;

	(void)(handle);

	return rrr_http2_streams_count_and_maintain(http2->http2_session);
}

struct rrr_http_application_http2_send_prepare_callback_data {
	struct rrr_http_application_http2 *app;
	int32_t stream_id;
};

static int __rrr_http_application_http2_header_fields_submit_callback (
		struct rrr_http_header_field *field,
		void *arg
) {
	struct rrr_http_application_http2_send_prepare_callback_data *callback_data = arg;

	int ret = 0;

	if (!rrr_nullsafe_str_isset(field->name) || !rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: Name or value was NULL in %s\n", __func__);
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in %s, this is not supported\n", __func__);
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, field->value);

	if ((ret = rrr_http2_header_submit(callback_data->app->http2_session, callback_data->stream_id, name, value)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct rrr_http_application_http2_request_send_header_submit_callback_data {
	struct rrr_http_application_http2 *http2;
	int32_t stream_id;
	const char *name;
};

static int __rrr_http_application_http2_header_submit_nullsafe_callback (
		const char *str,
		void *arg
) {
	struct rrr_http_application_http2_request_send_header_submit_callback_data *callback_data = arg;
	return rrr_http2_header_submit (
			callback_data->http2->http2_session,
			callback_data->stream_id,
			callback_data->name,
			str
	);
}

static int __rrr_http_application_http2_header_submit_nullsafe (
		struct rrr_http_application_http2 *http2,
		int32_t stream_id,
		const char *name,
		const struct rrr_nullsafe_str *value
) {
	struct rrr_http_application_http2_request_send_header_submit_callback_data callback_data = {
			http2,
			stream_id,
			name
	};
	return rrr_nullsafe_str_with_raw_null_terminated_do (
			value,
			__rrr_http_application_http2_header_submit_nullsafe_callback,
			&callback_data
	);
}

static int __rrr_http_application_http2_request_send_possible (
		RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) application;

	*is_possible = (rrr_http2_streams_count_and_maintain(http2->http2_session) < rrr_http2_stream_max());

	return 0;
}

static int __rrr_http_application_http2_request_send_preliminary_callback (
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		struct rrr_http_part *request_part,
		const struct rrr_nullsafe_str *request,
		void *arg
) {
	struct rrr_http_application_http2_send_prepare_callback_data *callback_data = arg;
	struct rrr_http_application_http2 *http2 = callback_data->app;

	(void)(method);
	(void)(upgrade_mode);
	(void)(protocol_version);
	(void)(request_part);

	return __rrr_http_application_http2_header_submit_nullsafe(http2, callback_data->stream_id, ":path", request);
}

static int __rrr_http_application_http2_request_send_final_callback (
		struct rrr_http_transaction *transaction,
		void *arg
) {
	struct rrr_http_application_http2_send_prepare_callback_data *callback_data = arg;
	struct rrr_http_application_http2 *http2 = callback_data->app;

	(void)(transaction);

	int ret = 0;

	// Will detect that the stream ID is not allocated yet and pass ID -1 to library to trigger allocation
	if ((ret = rrr_http2_headers_end(http2->http2_session, callback_data->stream_id)) != 0) {
		goto out;
	}

	if ((ret = rrr_http2_data_submission_request_set(http2->http2_session, callback_data->stream_id)) != 0) {
		goto out;
	}
	out:
	return ret;
}

static int __rrr_http_application_http2_request_send (
		RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) application;

	*upgraded_app = NULL;

	int ret = 0;

	char *selected_proto = NULL;
	struct rrr_http_application *http1 = NULL;

	if (rrr_net_transport_ctx_is_tls(handle)) {
		if ((ret = rrr_net_transport_ctx_selected_proto_get(&selected_proto, handle)) != 0) {
			goto out;
		}

		RRR_DBG_3("HTTP2 ALPN selected protocol: %s\n", (selected_proto != NULL ? selected_proto : "none"));

		if (selected_proto == NULL || strcmp("h2", selected_proto) != 0) {
			RRR_DBG_3("HTTP2 downgrading to HTTP1 as TLS ALPN negotiation failed\n");
			if ((ret = rrr_http_application_http1_new(&http1, &http2->callbacks)) != 0) {
				goto out;
			}

			struct rrr_http_application *upgraded_app_dummy = NULL;
			if ((ret = rrr_http_application_transport_ctx_request_send (
					&upgraded_app_dummy,
					http1,
					handle,
					user_agent,
					host,
					RRR_HTTP_UPGRADE_MODE_NONE,
					protocol_version,
					transaction
			)) != 0) {
				RRR_MSG_0("Failed to send HTTP1 request after downgrade from HTTP2, return was %i\n", ret);
				goto out;
			}

			*upgraded_app = http1;
			http1 = NULL;

			if (upgraded_app_dummy != NULL) {
				RRR_BUG("BUG: Recursive upgrades in %s\n", __func__);
			}

			goto out;
		}
	}

	RRR_DBG_7("http2 request submit method %s send data length %" PRIrrr_nullsafe_len "\n",
			RRR_HTTP_METHOD_TO_STR_CONFORMING(transaction->method),
			rrr_nullsafe_str_len(transaction->send_body));

	// The ID retrieved does not have a stream yet, stream is created in final_callback
	int32_t stream_id_preliminary = 0;
	if  ((ret = rrr_http2_request_start (
			&stream_id_preliminary,
			http2->http2_session
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_http2_header_submit(http2->http2_session, stream_id_preliminary, ":method", RRR_HTTP_METHOD_TO_STR_CONFORMING(transaction->method))) != 0) {
		// Probably busy, return value propagates
		goto out;
	}

	ret |= rrr_http2_header_submit(http2->http2_session, stream_id_preliminary, ":scheme", (rrr_net_transport_ctx_is_tls(handle) ? "https" : "http"));
	ret |= rrr_http2_header_submit(http2->http2_session, stream_id_preliminary, ":authority", host);

	if (ret != 0) {
		goto out;
	}

	if ((ret = rrr_http2_session_stream_application_data_set (
			http2->http2_session,
			stream_id_preliminary,
			transaction,
			rrr_http_transaction_decref_if_not_null_void
	)) != 0) {
		goto out;
	}

	rrr_http_transaction_incref(transaction);

	struct rrr_http_application_http2_send_prepare_callback_data callback_data = {
		http2,
		stream_id_preliminary
	};

	if ((ret = rrr_http_transaction_request_prepare_wrapper (
			transaction,
			upgrade_mode,
			protocol_version,
			user_agent,
			__rrr_http_application_http2_request_send_preliminary_callback,
			__rrr_http_application_http2_header_fields_submit_callback,
			__rrr_http_application_http2_request_send_final_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(selected_proto);
	rrr_http_application_destroy_if_not_null(&http1);
	return ret;
}

struct rrr_http_application_http2_callback_data {
	struct rrr_http_application_http2 *http2;
	struct rrr_net_transport_handle *handle;
	const struct rrr_http_rules *rules;
};

static int __rrr_http_application_http2_data_receive_response_submit_callback (
		struct rrr_http_application *application,
		struct rrr_http_transaction *transaction,
		int64_t stream_id,
		void *callback_arg
) {
	(void)(callback_arg);

	assert(stream_id < INT32_MAX);

	return rrr_http_application_http2_response_submit (
			application,
			transaction,
			(int32_t) stream_id
	);
}

static int __rrr_http_application_http2_data_receive_callback (
		RRR_HTTP2_DATA_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_application_http2_callback_data *callback_data = callback_arg;
	struct rrr_http_application_http2 *http2 = callback_data->http2;
	struct rrr_http_transaction *transaction = stream_application_data;

	// NOTE ! Callback can be reach two times (after headers and after data)

	(void)(session);

	int ret = 0;

	const int is_server = callback_data->http2->callbacks.unique_id_generator_callback != NULL;
	struct rrr_http_transaction *transaction_to_destroy = NULL;

	if (is_server) {
		if (transaction == NULL) {
			RRR_DBG_3("HTTP2 stream [%" PRIi64 "] data receive callback server new transaction\n", stream_id);

			if ((ret = rrr_http_transaction_new (
					&transaction_to_destroy,
					0,
					0,
					0,
					callback_data->http2->callbacks.unique_id_generator_callback,
					callback_data->http2->callbacks.callback_arg,
					NULL,
					NULL
			)) != 0) {
				RRR_MSG_0("Could not create transaction in %s\n", __func__);
				goto out;
			}

			if ((ret = rrr_http2_session_stream_application_data_set (
					callback_data->http2->http2_session,
					stream_id,
					transaction_to_destroy,
					rrr_http_transaction_decref_if_not_null_void
			)) != 0) {
				goto out;
			}

			// Don't set to NULL, will be decrefed at function out
			rrr_http_transaction_incref(transaction_to_destroy);
			transaction = transaction_to_destroy;
		}
		else {
			RRR_DBG_3("HTTP2 stream [%" PRIi64 "] data receive callback server existing transaction\n", stream_id);
		}

		rrr_http_transaction_stream_flags_add(transaction, flags);

		if (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_SEND_FLAG_IS_HEADERS_END)) {
			RRR_DBG_3("HTTP2 stream [%" PRIi64 "] send headers end\n",
				stream_id);
			goto out;
		}

		RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&transaction->request_part->headers, headers);
	}
	else {
		RRR_DBG_3("HTTP2 stream [%" PRIi64 "] data receive callback client\n", stream_id);

		rrr_http_transaction_stream_flags_add(transaction, flags);

		RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&transaction->response_part->headers, headers);
	}

	if ((ret = rrr_http_application_http2_http3_common_stream_read_end (
			(struct rrr_http_application *) http2,
			is_server,
			callback_data->handle,
			transaction,
			stream_id,
			stream_error_msg,
			callback_data->rules,
			data,
			data_size,
			__rrr_http_application_http2_data_receive_response_submit_callback,
			callback_data
	)) != 0) {
		goto out;
	}

	if (transaction->need_response) {
		http2->need_slow_tick = 1;
	}

	out:
	rrr_http_transaction_decref_if_not_null(transaction_to_destroy);
	return ret;
}

static int __rrr_http_application_http2_data_source_truncated_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	uint8_t *buf = arg;
	rrr_memcpy(buf, str, len);
	return 0;
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

	if (transaction->send_body == NULL || transaction->send_body_pos >= rrr_nullsafe_str_len(transaction->send_body)) {
		*done = 1;
		goto out;
	}

	rrr_nullsafe_len bytes_to_send = rrr_nullsafe_str_len(transaction->send_body) - transaction->send_body_pos;

	if (bytes_to_send > buf_size) {
		bytes_to_send = buf_size;
	}

	RRR_DBG_3("http2 source %" PRIrrr_nullsafe_len "/%" PRIrrr_nullsafe_len " bytes to send\n",
			rrr_nullsafe_str_len(transaction->send_body) - transaction->send_body_pos, rrr_nullsafe_str_len(transaction->send_body));

	if ((ret = rrr_nullsafe_str_with_raw_truncated_do (
			transaction->send_body,
			transaction->send_body_pos,
			(rrr_nullsafe_len) bytes_to_send,
			__rrr_http_application_http2_data_source_truncated_callback,
			buf
	)) != 0) {
		goto out;
	}

	transaction->send_body_pos += bytes_to_send;
	*written_bytes = bytes_to_send;

	// Saves an extra call to this function
	if (transaction->send_body_pos >= rrr_nullsafe_str_len(transaction->send_body)) {
		RRR_DBG_3("http2 source complete\n");
		*done = 1;
	}

	out:
	return ret;
}

static int __rrr_http_application_http2_streams_iterate_callback (
		int64_t stream_id,
		void *application_data,
		void *arg
) {
	struct rrr_http_application_http2_callback_data *callback_data = arg;
	struct rrr_http_application_http2 *http2 = callback_data->http2;
	struct rrr_http_transaction *transaction = application_data;

	int ret = 0;

	if (transaction && transaction->need_response) {
		if ((ret = callback_data->http2->callbacks.async_response_get_callback(transaction, callback_data->http2->callbacks.callback_arg)) != 0) {
			if (ret == RRR_HTTP_NO_RESULT) {
				// Try again shortly. Note that we need not worry about the
				// net transport noread counter since the HTTP2 ping packets
				// will keep the connection alive.
				http2->need_slow_tick = 1;
				ret = 0;
			}
			goto out;
		}

		assert(stream_id <= INT32_MAX);

		if ((ret = rrr_http_application_http2_response_submit (
				(struct rrr_http_application *) callback_data->http2,
				transaction,
				(int32_t) stream_id
		)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_http_application_http2_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	int ret = 0;

	(void)(received_bytes);
	(void)(upgraded_app);
	(void)(read_max_size);

	struct rrr_http_application_http2_callback_data callback_data = {
			http2,
			handle,
			rules
	};

	if (http2->transaction_incomplete_upgrade != NULL) {
		if ((ret = http2->callbacks.async_response_get_callback(http2->transaction_incomplete_upgrade, http2->callbacks.callback_arg)) == 0) {
			ret = rrr_http_application_http2_response_to_upgrade_submit(app, http2->transaction_incomplete_upgrade);

			rrr_http_transaction_decref_if_not_null(http2->transaction_incomplete_upgrade);
			http2->transaction_incomplete_upgrade = NULL;
		}

		if ((ret & ~(RRR_HTTP_NO_RESULT)) != 0) {
			goto out;
		}
	}
	else {
		if (http2->callbacks.async_response_get_callback != NULL) {
			if ((ret = rrr_http2_streams_iterate (
					http2->http2_session,
					__rrr_http_application_http2_streams_iterate_callback,
					&callback_data
			)) != 0) {
				goto out;
			}
		}
	}

	if ((ret = rrr_http2_transport_ctx_tick (
			http2->http2_session,
			handle,
			__rrr_http_application_http2_data_receive_callback,
			__rrr_http_application_http2_data_source_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void __rrr_http_application_http2_need_tick (
		RRR_HTTP_APPLICATION_NEED_TICK_ARGS
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	if (rrr_http2_need_tick(http2->http2_session)) {
		*speed = RRR_HTTP_TICK_SPEED_FAST;
	}
	else if (http2->transaction_incomplete_upgrade || http2->need_slow_tick) {
		*speed = RRR_HTTP_TICK_SPEED_SLOW;
	}

	http2->need_slow_tick = 0;
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
	__rrr_http_application_http2_alpn_protos_get(target, length);
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
	__rrr_http_application_http2_active_transaction_count_get_and_maintain,
	__rrr_http_application_http2_request_send_possible,
	__rrr_http_application_http2_request_send,
	__rrr_http_application_http2_tick,
	__rrr_http_application_http2_need_tick,
	__rrr_http_application_http2_polite_close,
	NULL
};

static int __rrr_http_application_http2_new (
		struct rrr_http_application_http2 **target,
		void **initial_receive_data,
		rrr_length initial_receive_data_len,
		int is_server,
		const struct rrr_http_application_callbacks *callbacks
) {
	struct rrr_http_application_http2 *result = NULL;

	int ret = 0;

	if ((result = rrr_allocate(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
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
	result->callbacks = *callbacks;

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
		rrr_length initial_receive_data_len,
		const struct rrr_http_application_callbacks *callbacks
) {
	int ret = 0;

	if ((ret = __rrr_http_application_http2_new((struct rrr_http_application_http2 **) target, initial_receive_data, initial_receive_data_len, is_server, callbacks)) != 0) {
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

static char *__rrr_http_application_http2_upgrade_postprocess_header_parse_base64_value_callback (
		const void *str,
		rrr_biglength len,
		void *arg
) {
	rrr_biglength *result_len = arg;
	return (char *) rrr_base64url_decode (
			str,
			len,
			result_len
	);
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
		RRR_BUG("BUG: Original HTTP2-Settings field not present in request upon upgrade in %s\n", __func__);
	}

	rrr_biglength orig_http2_settings_length = 0;
	if ((orig_http2_settings_tmp = rrr_nullsafe_str_with_raw_do_const_return_str (
			orig_http2_settings->value,
			__rrr_http_application_http2_upgrade_postprocess_header_parse_base64_value_callback,
			&orig_http2_settings_length
	)) == NULL) {
		RRR_MSG_0("Base64 decoding failed for HTTP2-Settings field\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_http2_session_upgrade_postprocess (
			app->http2_session,
			orig_http2_settings_tmp,
			rrr_size_from_biglength_bug_const (orig_http2_settings_length),
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
		rrr_length initial_receive_data_len,
		struct rrr_http_transaction *transaction,
		int is_server,
		const struct rrr_http_application_callbacks *callbacks
) {
	struct rrr_http_application_http2 *result = NULL;

	int ret = 0;

	*target = NULL;

	if ((ret = __rrr_http_application_http2_new (
			&result,
			initial_receive_data,
			initial_receive_data_len,
			is_server,
			callbacks
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


static int __rrr_http_application_http2_response_submit_response_code_callback (
	unsigned int response_code,
	enum rrr_http_version protocol_version,
	void *arg
) {
	struct rrr_http_application_http2_send_prepare_callback_data *callback_data = arg;

	(void)(protocol_version);

	return rrr_http2_header_status_submit(callback_data->app->http2_session, callback_data->stream_id, response_code);
}

static int __rrr_http_application_http2_response_submit_final_callback (
		struct rrr_http_transaction *transaction,
		void *arg
) {
	struct rrr_http_application_http2_send_prepare_callback_data *callback_data = arg;

	(void)(transaction);

	int ret = 0;

	if ((ret = rrr_http2_headers_end(callback_data->app->http2_session, callback_data->stream_id)) != 0) {
		goto out;
	}

	// Misc. callbacks will produce the actual response during ticking, if any
	if ((ret = rrr_http2_data_submission_request_set(callback_data->app->http2_session, callback_data->stream_id)) != 0) {
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

	if (app->callbacks.response_postprocess_callback != NULL && (ret = app->callbacks.response_postprocess_callback (
			transaction,
			app->callbacks.callback_arg
	)) != 0) {
		goto out;
	}

	struct rrr_http_application_http2_send_prepare_callback_data callback_data = {
			http2,
			stream_id
	};

	RRR_DBG_7("http2 response submit status %i send data length %" PRIrrr_nullsafe_len "\n",
			transaction->response_part->response_code, rrr_nullsafe_str_len(transaction->send_body));

	if ((ret = rrr_http_transaction_response_prepare_wrapper (
			transaction,
			__rrr_http_application_http2_header_fields_submit_callback,
			__rrr_http_application_http2_response_submit_response_code_callback,
			__rrr_http_application_http2_response_submit_final_callback,
			&callback_data
	)) != 0) {
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

	(void)(http2);

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

void rrr_http_application_http2_response_to_upgrade_async_prepare (
		struct rrr_http_application *app,
		struct rrr_http_transaction *transaction
) {
	struct rrr_http_application_http2 *http2 = (struct rrr_http_application_http2 *) app;

	http2->transaction_incomplete_upgrade = transaction;
	rrr_http_transaction_incref(transaction);
}
