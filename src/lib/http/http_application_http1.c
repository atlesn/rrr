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

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include "../log.h"

#include "http_application.h"
#include "http_application_http1.h"
#ifdef RRR_WITH_NGHTTP2
#	include "http_application_http2.h"
#endif
#include "http_application_internals.h"

#include "http_transaction.h"
#include "http_part.h"
#include "http_part_parse.h"
#include "http_part_multipart.h"
#include "http_util.h"
#include "http_common.h"
#include "../random.h"
#include "../string_builder.h"
#include "../websocket/websocket.h"
#include "../net_transport/net_transport.h"
#include "../util/gnu.h"
#include "../sha1/sha1.h"
#include "../util/base64.h"
#ifdef RRR_WITH_NGHTTP2
#	include "../http2/http2.h"
#endif

struct rrr_http_application_http1 {
	RRR_HTTP_APPLICATION_HEAD;
	enum rrr_http_upgrade_mode upgrade_active;
	struct rrr_websocket_state ws_state;

	// HTTP1 only has one active transaction at a time
	struct rrr_http_transaction *active_transaction;
};

static void __rrr_http_application_http1_destroy (struct rrr_http_application *app) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) app;
	rrr_websocket_state_clear_all(&http1->ws_state);
	rrr_http_transaction_decref_if_not_null(http1->active_transaction);
	free(http1);
}

static void __rrr_http_application_http1_transaction_clear (
		struct rrr_http_application_http1 *http1
) {
	rrr_http_transaction_decref_if_not_null(http1->active_transaction);
	http1->active_transaction = NULL;
}

static void __rrr_http_application_http1_transaction_set (
		struct rrr_http_application_http1 *http1,
		struct rrr_http_transaction *transaction
) {
	__rrr_http_application_http1_transaction_clear(http1);
	rrr_http_transaction_incref(transaction);
	http1->active_transaction = transaction;
}

static int __rrr_http_application_http1_request_send_make_headers_callback (
		struct rrr_http_header_field *field,
		void *arg
) {
	struct rrr_string_builder *builder = arg;

	// Note : Only plain values supported
	if (!rrr_nullsafe_str_isset(field->value)) {
		return 0;
	}

	int ret = 0;

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,field->value);

	ret |= rrr_string_builder_append(builder, name);
	ret |= rrr_string_builder_append(builder, ": ");
	ret |= rrr_string_builder_append(builder, value);
	ret |= rrr_string_builder_append(builder, "\r\n");

	return ret;
}

struct rrr_http_application_http1_send_header_field_callback_data {
	struct rrr_net_transport_handle *handle;
};

static int __rrr_http_application_http1_response_send_header_field_callback (struct rrr_http_header_field *field, void *arg) {
	struct rrr_http_application_http1_send_header_field_callback_data *callback_data = arg;

	int ret = 0;

	char *send_data = NULL;
	size_t send_data_length = 0;

	if (!rrr_nullsafe_str_isset(field->name) || !rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: Name or value was NULL in __rrr_http_application_http1_send_header_field_callback\n");
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in __rrr_http_application_http1_send_header_field_callback, this is not supported\n");
	}

	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &send_data);

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, field->value);

	if ((send_data_length = rrr_asprintf(&send_data, "%s: %s\r\n", name, value)) <= 0) {
		RRR_MSG_0("Could not allocate memory for header line in __rrr_http_application_http1_send_header_field_callback\n");
		ret = 1;
		goto out;
	}

	// Hack to create Camel-Case header names (before : only)
	int next_to_upper = 1;
	for (size_t i = 0; i < send_data_length; i++) {
		if (send_data[i] == ':' || send_data[i] == '\0') {
			break;
		}

		if (next_to_upper) {
			if (send_data[i] >= 'a' && send_data[i] <= 'z') {
				send_data[i] -= ('a' - 'A');
			}
		}

		next_to_upper = (send_data[i] == '-' ? 1 : 0);
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(callback_data->handle, send_data, send_data_length)) != 0) {
		RRR_DBG_1("Error: Send failed in __rrr_http_application_http1_send_header_field_callback\n");
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_application_http1_blocking_send_callback (
		const void *str,
		rrr_length len,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;
	return rrr_net_transport_ctx_send_blocking (
			handle,
			str,
			len
	);
}

static int __rrr_http_application_http1_response_send (
		struct rrr_http_application *application,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	(void)(application);

	struct rrr_http_part *response_part = transaction->response_part;

	if (response_part->response_raw_data_nullsafe != NULL) {
		if ((ret = rrr_nullsafe_str_with_raw_do_const (
				response_part->response_raw_data_nullsafe,
				__rrr_http_application_http1_blocking_send_callback,
				handle
		)) != 0) {
			goto out_err;
		}
		goto out;
	}

	if (response_part->response_code == 0) {
		RRR_BUG("BUG: Response code was not set in rrr_http_application_http1_send_response\n");
	}

	const char *response_str = NULL;

	switch (response_part->response_code) {
		case RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS:
			response_str = "HTTP/1.1 101 Switching Protocols\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_OK:
			response_str = "HTTP/1.1 200 OK\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT:
			response_str = "HTTP/1.1 204 No Content\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST:
			response_str = "HTTP/1.1 400 Bad Request\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_ERROR_NOT_FOUND:
			response_str = "HTTP/1.1 404 Not Found\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR:
			response_str = "HTTP/1.1 500 Internal Server Error\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT:
			response_str = "HTTP/1.1 504 Gateway Timeout\r\n";
			break;
		case RRR_HTTP_RESPONSE_CODE_VERSION_NOT_SUPPORTED:
			response_str = "HTTP/1.1 504 Version Not Supported\r\n";
			break;
		default:
			RRR_BUG("BUG: Response code %i not implemented in rrr_http_application_http1_send_response\n",
					response_part->response_code);
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(handle, response_str, strlen(response_str))) != 0) {
		goto out_err;
	}

	struct rrr_http_application_http1_send_header_field_callback_data callback_data = {
			handle
	};

	if ((ret = rrr_http_part_header_fields_iterate(response_part, __rrr_http_application_http1_response_send_header_field_callback, &callback_data)) != 0) {
		goto out_err;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking(handle, "\r\n", 2)) != 0 ) {
		goto out_err;
	}

	goto out;
	out_err:
		RRR_MSG_0("Error while sending headers for HTTP client %i in rrr_http_application_http1_transport_ctx_send_response\n",
				handle->handle);
	out:
		return ret;

}

struct rrr_http_application_http1_receive_data {
	struct rrr_net_transport_handle *handle;
	struct rrr_http_application_http1 *http1;
	ssize_t received_bytes; // Used only for stall timeout and sleeping
	rrr_http_unique_id unique_id;
	int is_client;
	struct rrr_http_application **upgraded_application;
	int (*upgrade_verify_callback)(RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS);
	void *upgrade_verify_callback_arg;
	int (*websocket_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS);
	void *websocket_callback_arg;
	int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
	int (*raw_callback)(RRR_HTTP_APPLICATION_RECEIVE_RAW_CALLBACK_ARGS);
	void *raw_callback_arg;
};

static int __rrr_http_application_http1_websocket_make_accept_string (
		char **accept_str,
		const char *sec_websocket_key
) {
	int ret = 0;

	char *accept_str_tmp = NULL;
	char *accept_base64_tmp = NULL;

	if (rrr_asprintf(&accept_str_tmp, "%s%s", sec_websocket_key, RRR_HTTP_WEBSOCKET_GUID) <= 0) {
		RRR_MSG_0("Failed to concatenate accept-string in __rrr_http_session_make_websocket_accept_string\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	rrr_SHA1Context sha1_ctx = {0};
	rrr_SHA1Reset(&sha1_ctx);
	rrr_SHA1Input(&sha1_ctx, (const unsigned char *) accept_str_tmp, strlen(accept_str_tmp));

	if (!rrr_SHA1Result(&sha1_ctx) || sha1_ctx.Corrupted != 0 || sha1_ctx.Computed != 1) {
		RRR_MSG_0("Computation of SHA1 failed in __rrr_http_session_websocket_make_accept_string (Corrupt: %i - Computed: %i)\n",
				sha1_ctx.Corrupted, sha1_ctx.Computed);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	rrr_SHA1toBE(&sha1_ctx);

	size_t accept_base64_length = 0;
	if ((accept_base64_tmp = (char *) rrr_base64_encode (
			(const unsigned char *) sha1_ctx.Message_Digest,
			sizeof(sha1_ctx.Message_Digest),
			&accept_base64_length
	)) == NULL) {
		RRR_MSG_0("Base64 encoding failed in __rrr_http_session_websocket_make_accept_string\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	char *newline = strchr(accept_base64_tmp, '\n');
	if (newline) {
		*newline = '\0';
	}

	*accept_str = accept_base64_tmp;
	accept_base64_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(accept_base64_tmp);
	RRR_FREE_IF_NOT_NULL(accept_str_tmp);
	return ret;
}

static int __rrr_http_application_http1_websocket_response_check_headers (
		struct rrr_http_part *response_part,
		struct rrr_websocket_state *ws_state
) {
	int ret = 0;

	char *sec_websocket_key_tmp = NULL;
	char *accept_str_tmp = NULL;

	const struct rrr_http_header_field *field_connection = rrr_http_part_header_field_get_with_value_case(response_part, "connection", "upgrade");
	const struct rrr_http_header_field *field_accept = rrr_http_part_header_field_get(response_part, "sec-websocket-accept");

	if (field_connection == NULL) {
		RRR_MSG_0("Missing 'Connection: upgrade' field in HTTP server WebSocket upgrade response\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (field_accept == NULL) {
		RRR_MSG_0("Missing 'Sec-Websocket-Accept' field in HTTP server WebSocket upgrade response\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_websocket_state_get_key_base64(&sec_websocket_key_tmp, ws_state)) != 0) {
		RRR_MSG_0("Failed to get key from WebSocket state in __rrr_http_session_request_receive_try_websocket\n");
		goto out;
	}

	if ((ret = __rrr_http_application_http1_websocket_make_accept_string(&accept_str_tmp, sec_websocket_key_tmp)) != 0) {
		RRR_MSG_0("Failed to make accept-string in __rrr_http_session_request_receive_try_websocket\n");
		goto out;
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(response_accept_str,field_accept->value);
	if (strcmp(accept_str_tmp, response_accept_str) != 0) {
		RRR_MSG_0("WebSocket accept string from server mismatch (got '%s' but expected  '%s')\n",
				response_accept_str, accept_str_tmp);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(sec_websocket_key_tmp);
	RRR_FREE_IF_NOT_NULL(accept_str_tmp);
	return ret;
}

struct rrr_http_application_http1_receive_raw_nullsafe_callback_data {
	struct rrr_http_application_http1_receive_data *receive_data;
	struct rrr_http_transaction *transaction;
};

static int __rrr_http_application_http1_receive_raw_nullsafe_callback (
		const struct rrr_nullsafe_str *str,
		void *arg
) {
	struct rrr_http_application_http1_receive_raw_nullsafe_callback_data *callback_data = arg;

	return callback_data->receive_data->raw_callback (
			str,
			callback_data->transaction,
			0,
			callback_data->transaction->response_part->parsed_protocol_version,
			callback_data->receive_data->raw_callback_arg
	);
}


static int __rrr_http_application_http1_receive_raw_if_required (
		struct rrr_http_application_http1_receive_data *receive_data,
		struct rrr_http_transaction *transaction,
		struct rrr_read_session *read_session
) {
	int ret = 0;

	if (receive_data->raw_callback == NULL) {
		goto out;
	}

	struct rrr_http_application_http1_receive_raw_nullsafe_callback_data callback_data = {
			receive_data,
			transaction
	};
	if ((ret = rrr_nullsafe_str_with_tmp_str_do (
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			__rrr_http_application_http1_receive_raw_nullsafe_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error %i from raw callback in __rrr_http_application_http1_receive_raw_if_required\n", ret);
		goto out;
	}

	out:
	return ret;
}


static int __rrr_http_application_http1_response_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_application_http1_receive_data *receive_data = arg;
	struct rrr_http_transaction *transaction = receive_data->http1->active_transaction;

	char *orig_http2_settings_tmp = NULL;

	int ret = 0;

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_header_dump(transaction->response_part);
	}

	RRR_DBG_3("HTTP response reading complete, data length is %li response length is %li header length is %li\n",
			transaction->response_part->data_length,
			transaction->response_part->headroom_length,
			transaction->response_part->header_length
	);

	if ((ret = __rrr_http_application_http1_receive_raw_if_required(receive_data, transaction, read_session)) != 0) {
		goto out;
	}

	enum rrr_http_upgrade_mode upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;

	if (transaction->response_part->response_code == RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS) {
		if (rrr_http_part_header_field_get_raw(transaction->request_part, "upgrade") == 0) {
			RRR_MSG_0("Unexpected HTTP 101 Switching Protocols response from server, no upgrade was requested\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		const struct rrr_http_header_field *field_response_upgrade_websocket = rrr_http_part_header_field_get_with_value_case(transaction->response_part, "upgrade", "websocket");
		const struct rrr_http_header_field *field_response_upgrade_h2c = rrr_http_part_header_field_get_with_value_case(transaction->response_part, "upgrade", "h2c");

		if (field_response_upgrade_websocket != NULL) {
			const struct rrr_http_header_field *field_request_upgrade_websocket = rrr_http_part_header_field_get_with_value_case (
					transaction->request_part,
					"upgrade",
					"websocket"
			);

			if (field_request_upgrade_websocket == NULL) {
				RRR_MSG_0("Unexpected 101 Switching Protocols response with Upgrade: websocket set, an upgrade was requested but not WebSocket upgrade\n");
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			if ((ret = __rrr_http_application_http1_websocket_response_check_headers(transaction->response_part, &receive_data->http1->ws_state)) != 0) {
				goto out;
			}

			int do_websocket = 0;
			if ((ret = receive_data->websocket_callback (
					&do_websocket,
					receive_data->handle,
					transaction,
					read_session->rx_buf_ptr,
					read_session->rx_overshoot_size,
					0,
					transaction->response_part->parsed_protocol_version,
					receive_data->websocket_callback_arg
			))) {
				goto out;
			}

			if (do_websocket != 1) {
				// Application regrets websocket upgrade, close connection
				goto out;
			}

			upgrade_mode = RRR_HTTP_UPGRADE_MODE_WEBSOCKET;
		}
		else if (field_response_upgrade_h2c != NULL) {
			const struct rrr_http_header_field *field_request_upgrade_h2c = rrr_http_part_header_field_get_with_value_case(
					transaction->request_part,
					"upgrade",
					"h2c"
			);

			if (field_request_upgrade_h2c == NULL) {
				RRR_MSG_0("Unexpected 101 Switching Protocols response with Upgrade: h2c set, an upgrade was requested but not HTTP2 upgrade\n");
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

#ifdef RRR_WITH_NGHTTP2
			RRR_DBG_3("Upgrade to HTTP2 size is %li overshoot is %li\n", read_session->rx_buf_wpos, read_session->rx_overshoot_size);

			if ((ret = rrr_http_transaction_response_reset(transaction)) != 0) {
				goto out;
			}

			// Pass any extra data received to http2 session for processing there. Overshoot pointer will
			// be set to NULL if http2_session takes control of the pointer.
			ret = rrr_http_application_http2_new_from_upgrade (
					receive_data->upgraded_application,
					(void **) &read_session->rx_overshoot,
					read_session->rx_overshoot_size,
					transaction,
					0 // Is not server
			);

			// Make sure these two variables are always both either 0 or set
			RRR_FREE_IF_NOT_NULL(read_session->rx_overshoot);
			read_session->rx_overshoot_size = 0;

			if (ret != 0) {
				RRR_MSG_0("Failed to initialize HTTP2 application in __rrr_application_http1_response_receive_callback\n");
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}

			upgrade_mode = RRR_HTTP_UPGRADE_MODE_HTTP2;
#else
			RRR_BUG("HTTP Client sent a Upgrade: h2c request to which the server responded correctly, but NGHTTP2 support is not built in __rrr_application_http1_response_receive_callback\n");
#endif /* RRR_WITH_NGHTTP2 */
		}
		else {
			RRR_MSG_0("Missing Upgrade: field in HTTP server 101 Switcing Protocols response or value was not h2c or websocket\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
	}

	if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_NONE) {
		if ((ret = receive_data->callback (
				receive_data->handle,
				transaction,
				read_session->rx_buf_ptr,
				read_session->rx_overshoot_size,
				0,
				transaction->response_part->parsed_protocol_version,
				receive_data->callback_arg
		)) != 0) {
			goto out;
		}
	}

	receive_data->http1->complete_transaction_count++;
	receive_data->http1->upgrade_active = upgrade_mode;

	out:
	__rrr_http_application_http1_transaction_clear(receive_data->http1);
	RRR_FREE_IF_NOT_NULL(orig_http2_settings_tmp);
	return ret;
}

static int __rrr_http_application_http1_websocket_request_check_version (
		struct rrr_http_part *request_part
) {
	const struct rrr_http_header_field *sec_websocket_version = rrr_http_part_header_field_get(request_part, "sec-websocket-version");
	if (sec_websocket_version == NULL) {
		RRR_DBG_1("Field Sec-WebSocket-Version missing in HTTP request with Connection: Upgrade and Upgrade: websocket headers set\n");
		return 1;
	}

	if (rrr_nullsafe_str_cmpto(sec_websocket_version->value, "13") != 0) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,sec_websocket_version->value);
		RRR_DBG_1("Received HTTP request with WebSocket upgrade and version '%s' set, but only version '13' is supported\n",
				value);
		return 1;
	}
	return 0;
}

static int __rrr_http_application_http1_request_upgrade_try_websocket (
		int *do_websocket,
		struct rrr_http_application_http1_receive_data *receive_data,
		struct rrr_read_session *read_session,
		const char *data_to_use
) {
	*do_websocket = 0;

	struct rrr_http_transaction *transaction = receive_data->http1->active_transaction;

	int ret = 0;

	char *accept_base64_tmp = NULL;

	*do_websocket = 1;

	if (transaction->request_part->request_method != RRR_HTTP_METHOD_GET) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(method_name,transaction->request_part->request_method_str_nullsafe);
		RRR_DBG_1("Received websocket upgrade request which was not a GET request but '%s'\n", method_name);
		goto out_bad_request;
	}

	if (read_session->rx_overshoot_size) {
		RRR_DBG_1("Error: Extra data received from client after websocket HTTP request\n");
		goto out_bad_request;
	}

	if (__rrr_http_application_http1_websocket_request_check_version(transaction->request_part) != 0) {
		goto out_bad_request;
	}

	const struct rrr_http_header_field *sec_websocket_key = rrr_http_part_header_field_get(transaction->request_part, "sec-websocket-key");
	if (sec_websocket_key == NULL) {
		RRR_DBG_1("HTTP request with WebSocket upgrade missing field Sec-WebSocket-Key\n");
		goto out_bad_request;
	}

	if (!rrr_nullsafe_str_isset(sec_websocket_key->binary_value_nullsafe)) {
		RRR_BUG("BUG: Binary value was not set for sec-websocket-key header field in __rrr_application_http1_request_receive_try_websocket\n");
	}

	if (rrr_nullsafe_str_len(sec_websocket_key->binary_value_nullsafe) != 16) {
		RRR_DBG_1("Incorrect length for Sec-WebSocket-Key header field in HTTP request with WebSocket upgrade. 16 bytes are required but got %" PRIrrrl "\n",
				rrr_nullsafe_str_len(sec_websocket_key->binary_value_nullsafe));
		goto out_bad_request;
	}

	if (receive_data->upgrade_verify_callback && (ret = receive_data->upgrade_verify_callback (
			do_websocket,
			RRR_HTTP_APPLICATION_HTTP1,
			RRR_HTTP_UPGRADE_MODE_WEBSOCKET,
			receive_data->upgrade_verify_callback_arg
	) != 0)) {
		goto out;
	}

	if (*do_websocket != 1) {
		// Application refuses websocket
		goto out_bad_request;
	}

	if ((ret = receive_data->websocket_callback (
			do_websocket,
			receive_data->handle,
			transaction,
			data_to_use,
			read_session->rx_overshoot_size,
			receive_data->unique_id,
			transaction->response_part->parsed_protocol_version,
			receive_data->websocket_callback_arg
	)) != RRR_HTTP_OK || transaction->response_part->response_code != 0) {
		goto out;
	}

	if (*do_websocket != 1) {
		// Application refuses websocket
		goto out_bad_request;
	}

	if ((ret = rrr_http_part_header_field_push(transaction->response_part, "connection", "upgrade")) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(transaction->response_part, "upgrade", "websocket")) != 0) {
		goto out;
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(sec_websocket_key_str, sec_websocket_key->value);
	if ((ret = __rrr_http_application_http1_websocket_make_accept_string(&accept_base64_tmp, sec_websocket_key_str)) != 0) {
		RRR_MSG_0("Failed to make accept-string in __rrr_application_http1_request_receive_try_websocket\n");
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(transaction->response_part, "sec-websocket-accept", accept_base64_tmp)) != 0) {
		goto out;
	}

	transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS;

	goto out;
	out_bad_request:
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
	out:
		RRR_FREE_IF_NOT_NULL(accept_base64_tmp);
		return ret;
}

static int __rrr_http_application_http1_request_upgrade_try_http2 (
		struct rrr_http_application **upgraded_application,
		struct rrr_http_application_http1_receive_data *receive_data,
		struct rrr_http_transaction *transaction,
		struct rrr_read_session *read_session
) {
	struct rrr_http_part *request_part = transaction->request_part;
	struct rrr_http_part *response_part = transaction->response_part;

	*upgraded_application = NULL;

	int ret = 0;

	struct rrr_http_application *http2 = NULL;

	const struct rrr_http_header_field *connection_http2_settings = rrr_http_part_header_field_get_with_value_case(request_part, "connection", "http2-settings");
	const struct rrr_http_header_field *http2_settings = rrr_http_part_header_field_get(request_part, "http2-settings");

	if (connection_http2_settings == NULL) {
		RRR_DBG_1("Value HTTP2-Settings was missing in Connection: header field while upgrade was requested\n");
		goto out_bad_request;
	}

	if (http2_settings == NULL) {
		RRR_DBG_1("Field HTTP2-Settings: was missing in header while upgrade was requested\n");
		goto out_bad_request;
	}

	if (request_part->request_method != RRR_HTTP_METHOD_GET && request_part->request_method != RRR_HTTP_METHOD_OPTIONS) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(method_name,request_part->request_method_str_nullsafe);
		RRR_DBG_1("Received HTTP2 upgrade request which was not a GET or OPTION request but '%s'\n", method_name);
		goto out_bad_request;
	}

	int upgrade_ok = 1;
	if (receive_data->upgrade_verify_callback && (ret = receive_data->upgrade_verify_callback (
			&upgrade_ok,
			RRR_HTTP_APPLICATION_HTTP1,
			RRR_HTTP_UPGRADE_MODE_HTTP2,
			receive_data->upgrade_verify_callback_arg
	) != 0)) {
		goto out;
	}

	if (!upgrade_ok) {
		goto out;
	}

#ifdef RRR_WITH_NGHTTP2
	if ((ret = rrr_http_part_header_field_push(response_part, "connection", "upgrade")) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_header_field_push(response_part, "upgrade", "h2c")) != 0) {
		goto out;
	}

	ret = rrr_http_application_http2_new_from_upgrade (
			&http2,
			(void **) &read_session->rx_overshoot,
			read_session->rx_overshoot_size,
			transaction,
			1 // Is server
	);

	// Make sure these two variables are always both either 0 or set
	RRR_FREE_IF_NOT_NULL(read_session->rx_overshoot);
	read_session->rx_overshoot_size = 0;

	if (ret != 0) {
		goto out;
	}

	*upgraded_application = http2;
	http2 = NULL;
	response_part->response_code = RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS;

#else
	(void)(read_session);
	RRR_DBG_3("Upgrade to HTTP2 was requested by client, but this RRR is not built with NGHTTP2 bindings. Proceeding with HTTP/1.1\n");
#endif /* RRR_WITH_NGHTTP2 */

	goto out;
	out_bad_request:
		response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
	out:
		rrr_http_application_destroy_if_not_null(&http2);
		return ret;
}

static int __rrr_http_application_http1_request_upgrade_try (
		enum rrr_http_upgrade_mode *upgrade_mode,
		struct rrr_http_application_http1_receive_data *receive_data,
		struct rrr_read_session *read_session,
		const char *data_to_use
) {
	*upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;

	int ret = 0;

	struct rrr_http_transaction *transaction = receive_data->http1->active_transaction;

	const struct rrr_http_header_field *connection = rrr_http_part_header_field_get_with_value_case(transaction->request_part, "connection", "upgrade");
	const struct rrr_http_header_field *upgrade_websocket = rrr_http_part_header_field_get_with_value_case(transaction->request_part, "upgrade", "websocket");
	const struct rrr_http_header_field *upgrade_h2c = rrr_http_part_header_field_get_with_value_case(transaction->request_part, "upgrade", "h2c");

	if (connection == NULL) {
		goto out;
	}

	if (upgrade_websocket != NULL && upgrade_h2c != NULL) {
		goto out_bad_request;
	}

	if (upgrade_websocket != NULL) {
		int do_websocket = 0;
		if ((ret = __rrr_http_application_http1_request_upgrade_try_websocket (
				&do_websocket,
				receive_data,
				read_session,
				data_to_use
		)) == 0 && do_websocket) {
			*upgrade_mode = RRR_HTTP_UPGRADE_MODE_WEBSOCKET;
		}
	}
	else if (upgrade_h2c != NULL) {
		if ((ret = __rrr_http_application_http1_request_upgrade_try_http2 (
				receive_data->upgraded_application,
				receive_data,
				transaction,
				read_session
		)) == 0 && receive_data->upgraded_application != NULL) {
			*upgrade_mode = RRR_HTTP_UPGRADE_MODE_HTTP2;
		}
	}

	goto out;
	out_bad_request:
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
	out:
		return ret;
}

static int __rrr_http_application_http1_request_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_application_http1_receive_data *receive_data = arg;
	struct rrr_http_transaction *transaction = receive_data->http1->active_transaction;

	int ret = 0;

	char *merged_chunks = NULL;

//	const struct rrr_http_header_field *content_type = rrr_http_part_get_header_field(part, "content-type");

	if (transaction->request_part->request_method == 0) {
		RRR_DBG_2("Request parsing was incomplete in HTTP final callback, sending bad request to client.\n");
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
		goto out_send_response;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_header_dump(transaction->request_part);
	}

	// Upgrade was performed in get target size function, nothing to do
	if (*(receive_data->upgraded_application) != 0) {
		goto out;
	}

	RRR_DBG_3("HTTP request reading complete, data length is %li response length is %li header length is %li\n",
			transaction->request_part->data_length,
			transaction->request_part->headroom_length,
			transaction->request_part->header_length
	);

	if ((ret = __rrr_http_application_http1_receive_raw_if_required(receive_data, transaction, read_session)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_chunks_merge(&merged_chunks, transaction->request_part, read_session->rx_buf_ptr)) != 0) {
		goto out;
	}

	const char *data_to_use = (merged_chunks != NULL ? merged_chunks : read_session->rx_buf_ptr);

	if ((ret = rrr_http_part_multipart_process(transaction->request_part, data_to_use)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_fields_from_post_extract(transaction->request_part, data_to_use)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_part_fields_from_uri_extract(transaction->request_part)) != 0) {
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_field_collection_dump (&transaction->request_part->fields);
	}

	enum rrr_http_upgrade_mode upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
	if ((ret = __rrr_http_application_http1_request_upgrade_try (
			&upgrade_mode,
			receive_data,
			read_session,
			data_to_use
	)) != 0) {
		goto out;
	}

	if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_WEBSOCKET && receive_data->websocket_callback == NULL) {
		RRR_MSG_1("Warning: Received HTTP request with WebSocket update, but no WebSocket callback is set in configuration\n");
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
		goto out_send_response;
	}

	if (upgrade_mode != RRR_HTTP_UPGRADE_MODE_NONE) {
		if (transaction->response_part->response_code == RRR_HTTP_RESPONSE_CODE_SWITCHING_PROTOCOLS) {
			RRR_DBG_3("Upgrading HTTP connection to %s\n", RRR_HTTP_UPGRADE_MODE_TO_STR(upgrade_mode));
			receive_data->http1->upgrade_active = upgrade_mode;
		}
		else {
			RRR_DBG_4("Note: Upgrade HTTP connection to %s failed, response is now %i\n",
					RRR_HTTP_UPGRADE_MODE_TO_STR(upgrade_mode), transaction->response_part->response_code);
		}
	}

	// If upgrade is HTTP2
	// - The HTTP2 upgrade function has already stored this transaction and bound it to stream ID 1
	// - Send HTTP1 response with 101 switching protocols
	// - Reset the response part.
	// - Let callback do something if it wishes
	// - Queue the response for sending upon next tick
	// - Jump out of HTTP1 ticking, caller will tick again with HTTP2 which sends the actual response
	//   based on the response part

#ifdef RRR_WITH_NGHTTP2
	if (receive_data->http1->upgrade_active == RRR_HTTP_UPGRADE_MODE_HTTP2) {
		if ((ret = __rrr_http_application_http1_response_send((struct rrr_http_application *) receive_data->http1, receive_data->handle, transaction)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_transaction_response_reset(transaction)) != 0) {
			goto out;
		}
		if ((ret = receive_data->callback (
				receive_data->handle,
				transaction,
				data_to_use,
				read_session->rx_overshoot_size,
				receive_data->unique_id,
				RRR_HTTP_APPLICATION_HTTP2, // Note, next protocol is HTTP2
				receive_data->callback_arg
		)) != RRR_HTTP_OK) {
			goto out;
		}

		if ((ret = rrr_http_application_http2_response_to_upgrade_submit (
				*(receive_data->upgraded_application),
				transaction
		)) != 0) {
			goto out;
		}

		// HTTP2 application will send the actual response during the next tick
		goto out;
	}
	else {
#endif /* RRR_WITH_NGHTTP2 */
		if ((ret = receive_data->callback (
				receive_data->handle,
				transaction,
				data_to_use,
				read_session->rx_overshoot_size,
				receive_data->unique_id,
				transaction->request_part->parsed_protocol_version,
				receive_data->callback_arg
		)) != RRR_HTTP_OK) {
			goto out;
		}
#ifdef RRR_WITH_NGHTTP2
	}
#endif /* RRR_WITH_NGHTTP2 */

	out_send_response:
	if ((ret = __rrr_http_application_http1_response_send((struct rrr_http_application *) receive_data->http1, receive_data->handle, transaction)) != 0) {
		goto out;
	}

	receive_data->http1->complete_transaction_count++;

	out:
	__rrr_http_application_http1_transaction_clear(receive_data->http1);
	RRR_FREE_IF_NOT_NULL(merged_chunks);
	return ret;
}

static int __rrr_http_application_http1_receive_get_target_size_validate_request (
		const struct rrr_http_part *part
) {
	int ret = 0;

	const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(part, "content-type");
	const struct rrr_http_header_field *content_length = rrr_http_part_header_field_get(part, "content-length");
	const struct rrr_http_header_field *transfer_encoding = rrr_http_part_header_field_get(part, "transfer-encoding");

	if (part->request_method_str_nullsafe == NULL) {
		RRR_BUG("BUF: Request method not set in rrr_http_part_parse after header completed\n");
	}

	if (part->request_method == 0) {
		RRR_BUG("BUG: Numeric request method was zero in __rrr_http_application_http1_receive_get_target_size_validate_request\n");
	}

	if (part->request_method == RRR_HTTP_METHOD_GET ||
		part->request_method == RRR_HTTP_METHOD_OPTIONS ||
		part->request_method == RRR_HTTP_METHOD_HEAD ||
		part->request_method == RRR_HTTP_METHOD_DELETE
	) {
		if (content_length != NULL && content_length->value_unsigned != 0) {
			RRR_MSG_0("Content-Length was non-zero for GET, HEAD, DELETE or OPTIONS request, this is an error.\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
		}

		if (transfer_encoding != NULL) {
			RRR_MSG_0("Transfer-Encoding header was set for GET, HEAD, DELETE or OPTIONS request, this is an error.\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
		}

		if (content_type != NULL) {
			RRR_MSG_0("Content-Type was set for GET, HEAD, DELETE or OPTIONS request, this is an error.\n");
			ret = RRR_HTTP_PARSE_SOFT_ERR;
		}
	}

	return ret;
}

static int __rrr_http_application_http1_receive_get_target_size (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_http_application_http1_receive_data *receive_data = arg;

	int ret = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH;

	const char *end = read_session->rx_buf_ptr + read_session->rx_buf_wpos;

	size_t target_size;
	size_t parsed_bytes = 0;

	struct rrr_http_part *part_to_use = NULL;
	enum rrr_http_parse_type parse_type = 0;

	if (receive_data->is_client == 1) {
		if (receive_data->http1->active_transaction == NULL) {
			RRR_MSG_0("Received unexpected data from HTTP server, no transaction was active\n");
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}
		part_to_use = receive_data->http1->active_transaction->response_part;
		parse_type = RRR_HTTP_PARSE_RESPONSE;
	}
	else {
		if (read_session->parse_pos == 0) {
			struct rrr_http_transaction *transaction = NULL;

			// HTTP1 only supports one active transaction. Make a new and delete any old one. Method
			// does not matter.
			if ((ret = rrr_http_transaction_new (&transaction, RRR_HTTP_METHOD_GET, 0, NULL, NULL)) != 0) {
				RRR_MSG_0("Could not create transaction for request in __rrr_application_http1_receive_get_target_size\n");
				goto out;
			}

			__rrr_http_application_http1_transaction_set(receive_data->http1, transaction);
			rrr_http_transaction_decref_if_not_null(transaction);
		}
		part_to_use = receive_data->http1->active_transaction->request_part;
		parse_type = RRR_HTTP_PARSE_REQUEST;
	}


#ifdef RRR_WITH_NGHTTP2
	if (read_session->parse_pos == 0 && !receive_data->is_client) {
		const char http2_magic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
		if (	(rrr_biglength) read_session->rx_buf_wpos >= (rrr_biglength) sizeof(http2_magic) - 1 &&
				memcmp(read_session->rx_buf_ptr, http2_magic, sizeof(http2_magic) - 1) == 0
		) {
			RRR_DBG_3("HTTP2 magic found, upgrading to native HTTP2 with %llu bytes read so far\n", (long long int) read_session->rx_buf_wpos);
			if ((ret = rrr_http_application_http2_new (
					receive_data->upgraded_application,
					1, // Is server
					(void **) &read_session->rx_buf_ptr,
					read_session->rx_buf_wpos
			)) != 0) {
				goto out;
			}

			read_session->target_size = read_session->rx_buf_wpos;
			ret = RRR_HTTP_OK;
			goto out;
		}
	}
#endif /* RRR_WITH_NGHTTP2 */

	// There might be more than one chunk in each read cycle, we have to
	// go through all of them in a loop here. The parser will always return
	// after a chunk is found.
	do {
		ret = rrr_http_part_parse (
				part_to_use,
				&target_size,
				&parsed_bytes,
				read_session->rx_buf_ptr,
				read_session->parse_pos,
				end,
				parse_type
		);

		read_session->parse_pos += parsed_bytes;
	} while (parsed_bytes != 0 && ret == RRR_HTTP_PARSE_INCOMPLETE);

	// Do not overwrite ret value here

	// Used only for stall timeout
	receive_data->received_bytes = read_session->rx_buf_wpos;

	if (ret == RRR_HTTP_PARSE_OK) {
		if (!receive_data->is_client) {
			if ((ret = __rrr_http_application_http1_receive_get_target_size_validate_request (
					receive_data->http1->active_transaction->request_part
			)) != 0) {
				// Ignore any body
				target_size = RRR_HTTP_PART_TOP_LENGTH(receive_data->http1->active_transaction->request_part);

				// Delete everything in the request part to prevent haywire, the final callback will generate bad request response
				if ((ret = rrr_http_transaction_request_reset(receive_data->http1->active_transaction)) != 0) {
					goto out;
				}

				ret = RRR_HTTP_PARSE_OK;
			}
		}

		if (target_size > SSIZE_MAX) {
			RRR_MSG_0("Target size %lu exceeds maximum value of %li while parsing HTTP part\n",
					target_size, SSIZE_MAX);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}

		read_session->target_size = target_size;
	}
	else if (ret == RRR_HTTP_PARSE_INCOMPLETE) {
		if (part_to_use->data_length_unknown) {
			read_session->read_complete_method = RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE;
			ret = RRR_NET_TRANSPORT_READ_OK;
		}
	}
	else {
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
	}

	out:
	if (ret != RRR_HTTP_PARSE_INCOMPLETE) {
		read_session->parse_pos = 0;
	}
	return ret;
}

struct rrr_http_application_http1_frame_callback_data {
	rrr_http_unique_id unique_id;
	int (*callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_application_http1_websocket_frame_callback (
		RRR_WEBSOCKET_FRAME_CALLBACK_ARGS
) {
	struct rrr_http_application_http1_frame_callback_data *callback_data = arg;

	if (opcode == RRR_WEBSOCKET_OPCODE_BINARY || opcode == RRR_WEBSOCKET_OPCODE_TEXT) {
		return callback_data->callback (
				payload,
				(opcode == RRR_WEBSOCKET_OPCODE_BINARY ? 1 : 0),
				callback_data->unique_id,
				callback_data->callback_arg
		);
	}

	return RRR_HTTP_OK;
}

static int __rrr_http_application_http1_websocket_responses_get (
		struct rrr_websocket_state *ws_state,
		int (*callback)(RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	void *response_data = NULL;
	ssize_t response_data_len = 0;
	int response_is_binary = 0;

	do {
		RRR_FREE_IF_NOT_NULL(response_data);
		if ((ret = callback (
				&response_data,
				&response_data_len,
				&response_is_binary,
				callback_arg
		)) != 0) {
			goto out;
		}
		if (response_data) {
			if ((ret = rrr_websocket_frame_enqueue (
					ws_state,
					(response_is_binary ? RRR_WEBSOCKET_OPCODE_BINARY : RRR_WEBSOCKET_OPCODE_TEXT),
					(char**) &response_data,
					response_data_len
			)) != 0) {
				goto out;
			}
		}
	} while (response_data != NULL);

	out:
	RRR_FREE_IF_NOT_NULL(response_data);
	return ret;
}

static int __rrr_http_application_http1_transport_ctx_tick_websocket (
		struct rrr_http_application_http1 *http1,
		struct rrr_net_transport_handle *handle,
		ssize_t read_max_size,
		rrr_http_unique_id unique_id,
		int ping_interval_s,
		int timeout_s,
		int (*callback)(RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg
) {
	int ret = 0;

	struct rrr_http_application_http1_frame_callback_data callback_data = {
			unique_id,
			frame_callback,
			frame_callback_arg
	};

	if (rrr_websocket_check_timeout(&http1->ws_state, timeout_s) != 0) {
		RRR_DBG_2("HTTP websocket session timed out after %i seconds of inactivity\n", timeout_s);
		ret = RRR_READ_EOF;
		goto out;
	}

	if ((ret = rrr_websocket_enqueue_ping_if_needed(&http1->ws_state, ping_interval_s)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_application_http1_websocket_responses_get (
			&http1->ws_state,
			callback,
			get_response_callback_arg
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_websocket_transport_ctx_send_frames (
			handle,
			&http1->ws_state
	)) != 0) {
		goto out;
	}

	if ((ret = (rrr_websocket_transport_ctx_read_frames (
			handle,
			&http1->ws_state,
			100,
			4096,
			65535,
			read_max_size,
			__rrr_http_application_http1_websocket_frame_callback,
			&callback_data
	)) & ~(RRR_NET_TRANSPORT_READ_INCOMPLETE)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http1_request_send_possible (
		RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS
) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) application;
	*is_possible = (http1->active_transaction == NULL);
	return 0;
}

static int __rrr_http_application_http1_request_send (
		RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS
) {
	int ret = 0;

	// DO NOT do any upgrades here, HTTP1 may do this during ticking only.
	// Upgrades here may cause infinite recursion as HTTP2 upgrades in its request_send function.
	*upgraded_app = NULL;

	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) application;
	struct rrr_http_part *request_part = transaction->request_part;

	char *host_buf = NULL;
	char *user_agent_buf = NULL;
	char *websocket_key_tmp = NULL;
	char *http2_upgrade_settings_tmp = NULL;
	struct rrr_nullsafe_str *request_nullsafe = NULL;

	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &host_buf);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &user_agent_buf);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &websocket_key_tmp);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &http2_upgrade_settings_tmp);
	pthread_cleanup_push(rrr_nullsafe_str_destroy_if_not_null_void, &request_nullsafe);

	struct rrr_string_builder *header_builder = NULL;

	if (http1->active_transaction != NULL) {
		RRR_BUG("BUG: Existing transaction was not clear in  __rrr_http_application_http1_request_send, caller must check with request_send_possible\n");
	}

	__rrr_http_application_http1_transaction_set(http1, transaction);

	if (rrr_string_builder_new(&header_builder) != 0) {
		RRR_MSG_0("Failed to create string builder in __rrr_http_application_http1_request_send\n");
		ret = 1;
		goto out_final;
	}

	pthread_cleanup_push(rrr_string_builder_destroy_void, header_builder);

	host_buf = rrr_http_util_header_value_quote(host, strlen(host), '"', '"');
	if (host_buf == NULL) {
		RRR_MSG_0("Invalid host '%s' in __rrr_http_application_http1_request_send\n", host);
		ret = 1;
		goto out;
	}

	user_agent_buf = rrr_http_util_header_value_quote(user_agent, strlen(user_agent), '"', '"');
	if (user_agent_buf == NULL) {
		RRR_MSG_0("Invalid user agent '%s' in __rrr_http_application_http1_request_send\n", user_agent);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_http_transaction_endpoint_with_query_string_create(&request_nullsafe, transaction)) != 0) {
		goto out;
	}

	if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_WEBSOCKET) {
		if (transaction->method != RRR_HTTP_METHOD_GET) {
			RRR_BUG("BUG: HTTP method was not GET while upgrade mode was WebSocket\n");
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "connection", "Upgrade")) != 0) {
			goto out;
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "upgrade", "websocket")) != 0) {
			goto out;
		}
		if ((ret = rrr_websocket_state_get_key_base64 (&websocket_key_tmp, &http1->ws_state)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "sec-websocket-key", websocket_key_tmp)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "sec-websocket-version", "13")) != 0) {
			goto out;
		}

		rrr_websocket_state_set_client_mode(&http1->ws_state);
	}
	else if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2) {
#ifdef RRR_WITH_NGHTTP2
		if (transaction->method != RRR_HTTP_METHOD_GET && transaction->method != RRR_HTTP_METHOD_HEAD) {
			RRR_DBG_3("Note: HTTP1 upgrade to HTTP2 not possible, query is not GET or HEAD\n");
		}
		else {
			if ((ret = rrr_http_part_header_field_push(request_part, "connection", "Upgrade, HTTP2-Settings")) != 0) {
				goto out;
			}
			if ((ret = rrr_http_part_header_field_push(request_part, "upgrade", "h2c")) != 0) {
				goto out;
			}
			if (rrr_http2_upgrade_request_settings_pack(&http2_upgrade_settings_tmp) != 0) {
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}
			if ((ret = rrr_http_part_header_field_push(request_part, "http2-settings", http2_upgrade_settings_tmp)) != 0) {
				goto out;
			}
		}
#else
		RRR_MSG_3("Note: HTTP client attempted to send request with upgrade to HTTP2, but RRR is not built with NGHTTP2. Proceeding using HTTP/1.1.\n");
#endif /* RRR_WITH_NGHTTP2 */
	}

	// Prepend "GET " etc. before endpoint
	if ((ret = rrr_nullsafe_str_prepend_asprintf (
			request_nullsafe,
			"%s ",
			RRR_HTTP_METHOD_TO_STR_CONFORMING(transaction->method)
	)) < 0) {
		RRR_MSG_0("Error while making request string in rrr_http_application_http1_request_send return was %i\n", ret);
		ret = 1;
		goto out;
	}

	// Append the rest of the header after endpoint
	if ((ret = rrr_nullsafe_str_append_asprintf (
			request_nullsafe,
			" HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept-Charset: UTF-8\r\n",
			host_buf,
			user_agent_buf
	)) < 0) {
		RRR_MSG_0("Error while making request string in rrr_http_application_http1_request_send return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_blocking_nullsafe (handle, request_nullsafe)) != 0) {
		RRR_MSG_0("Could not send first part of HTTP request header in __rrr_http_application_http1_request_send\n");
		goto out;
	}

	rrr_string_builder_clear(header_builder);

	// Note : Might add more headers to request part
	int form_data_was_made = 0;
	if ((ret = rrr_http_transaction_form_data_generate_if_needed (&form_data_was_made, transaction)) != 0) {
		goto out;
	}

	if (rrr_nullsafe_str_len(transaction->send_data_tmp)) {
		char content_length[64];
		sprintf(content_length, "%" PRIrrrl, rrr_nullsafe_str_len(transaction->send_data_tmp));
		if ((ret = rrr_http_part_header_field_push(request_part, "content-length", content_length)) != 0) {
				goto out;
		}
	}

	if (rrr_http_part_header_fields_iterate (
			request_part,
			__rrr_http_application_http1_request_send_make_headers_callback,
			header_builder
	) != 0) {
		RRR_MSG_0("Failed to make header fields in __rrr_http_application_http1_request_send\n");
		ret = 1;
		goto out;
	}

	if (rrr_string_builder_length(header_builder) > 0) {
		if ((ret = rrr_net_transport_ctx_send_blocking (handle, header_builder->buf, header_builder->wpos)) != 0) {
			RRR_MSG_0("Could not send second part of HTTP request header in __rrr_http_application_http1_request_send\n");
			goto out;
		}
	}

	if ((ret = rrr_net_transport_ctx_send_blocking (handle, "\r\n", 2)) != 0) {
		RRR_MSG_0("Could not send HTTP header end in __rrr_http_application_http1_request_send\n");
		goto out;
	}

	if (rrr_nullsafe_str_len(transaction->send_data_tmp)) {
		if ((ret = rrr_nullsafe_str_with_raw_do_const (
				transaction->send_data_tmp,
				__rrr_http_application_http1_blocking_send_callback,
				handle
		)) != 0) {
			RRR_MSG_0("Could not send HTTP request body in __rrr_http_application_http1_request_send\n");
			goto out;
		}
	}

	out:
		pthread_cleanup_pop(1);
	out_final:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		return ret;
}

int __rrr_http_application_http1_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) app;

	int ret = RRR_HTTP_OK;

	*upgraded_app = NULL;

	if (http1->upgrade_active == RRR_HTTP_UPGRADE_MODE_WEBSOCKET) {
		ret = __rrr_http_application_http1_transport_ctx_tick_websocket (
				http1,
				handle,
				read_max_size,
				unique_id,
				10,
				15,
				get_response_callback,
				get_response_callback_arg,
				frame_callback,
				frame_callback_arg
		);
	}
	else if (http1->upgrade_active == RRR_HTTP_UPGRADE_MODE_NONE) {
		struct rrr_http_application_http1_receive_data callback_data = {
				handle,
				http1,
				*received_bytes,
				unique_id,
				is_client,
				upgraded_app,
				upgrade_verify_callback,
				upgrade_verify_callback_arg,
				websocket_callback,
				websocket_callback_arg,
				callback,
				callback_arg,
				raw_callback,
				raw_callback_arg
		};

		ret = rrr_net_transport_ctx_read_message (
					handle,
					100,
					4096,
					65535,
					read_max_size,
					__rrr_http_application_http1_receive_get_target_size,
					&callback_data,
					is_client
						? __rrr_http_application_http1_response_receive_callback
						: __rrr_http_application_http1_request_receive_callback,
					&callback_data
		);

		*received_bytes = callback_data.received_bytes;
	}
	else {
		RRR_BUG("__rrr_http_application_http1_tick called while active upgrade was not NONE or WEBSOCKET but %i, maybe caller forgot to switch to HTTP2?\n", http1->upgrade_active);
	}

	return ret;
}

static void __rrr_http_application_http1_polite_close (
		RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS
) {
	(void)(app);
	(void)(handle);
	return;
}

static const struct rrr_http_application_constants rrr_http_application_http1_constants = {
	RRR_HTTP_APPLICATION_HTTP1,
	__rrr_http_application_http1_destroy,
	__rrr_http_application_http1_request_send_possible,
	__rrr_http_application_http1_request_send,
	__rrr_http_application_http1_tick,
	__rrr_http_application_http1_polite_close
};

int rrr_http_application_http1_new (struct rrr_http_application **target) {
	int ret = 0;

	struct rrr_http_application_http1 *result = NULL;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_application_http1_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	result->constants = &rrr_http_application_http1_constants;

	*target = (struct rrr_http_application *) result;

	out:
	return ret;
}


