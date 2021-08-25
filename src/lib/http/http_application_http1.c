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

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include "../log.h"
#include "../allocator.h"

#include "http_application.h"
#include "http_application_http1.h"
#ifdef RRR_WITH_NGHTTP2
#	include "http_application_http2.h"
#endif
#include "http_application_internals.h"

#include "http_transaction.h"
#include "http_part.h"
#include "http_part_parse.h"
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
	char *application_websocket_topic;

	uint64_t complete_transaction_count;

	// HTTP1 only has one active transaction at a time
	struct rrr_http_transaction *active_transaction;
	rrr_http_unique_id last_unique_id;
};

static void __rrr_http_application_http1_destroy (struct rrr_http_application *app) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) app;

	if (http1->active_transaction != NULL) {
		RRR_DBG_2("HTTP1 destroys application with 1 active transaction\n");
	}

	RRR_FREE_IF_NOT_NULL(http1->application_websocket_topic);
	rrr_websocket_state_clear_all(&http1->ws_state);
	rrr_http_transaction_decref_if_not_null(http1->active_transaction);
	rrr_free(http1);
}

static uint64_t __rrr_http_application_http1_active_transaction_count_get (
		struct rrr_http_application *app
) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) app;

	return (http1->active_transaction != NULL ? 1 : 0);
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

	// Websocket uses this after upgrade
	http1->last_unique_id = transaction->unique_id;
}

static int __rrr_http_application_http1_header_field_make (
		struct rrr_string_builder *builder,
		struct rrr_http_header_field *field
) {
	int ret = 0;

//	char *value_tmp = NULL;

	if (!rrr_nullsafe_str_isset(field->value) || rrr_nullsafe_str_len(field->value) == 0) {
		goto out;
	}

/*	if ((value_tmp = rrr_http_util_header_value_quote_nullsafe(field->value, '"', '"')) == NULL) {
		ret = 1;
		goto out;
	}*/

	// TODO : Smart escape of values

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,field->name);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,field->value);

	ret |= rrr_string_builder_append(builder, name);
	ret |= rrr_string_builder_append(builder, ": ");
//	ret |= rrr_string_builder_append(builder, value_tmp);
	ret |= rrr_string_builder_append(builder, value);
	ret |= rrr_string_builder_append(builder, "\r\n");

	out:
//	RRR_FREE_IF_NOT_NULL(value_tmp);
	return ret;
}

struct rrr_http_application_http1_response_send_callback_data {
	struct rrr_net_transport_handle *handle;
};

static int __rrr_http_application_http1_response_send_header_field_callback (struct rrr_http_header_field *field, void *arg) {
	struct rrr_http_application_http1_response_send_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_string_builder string_builder = {0}; 

	if (!rrr_nullsafe_str_isset(field->name) || !rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: Name or value was NULL in __rrr_http_application_http1_send_header_field_callback\n");
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in __rrr_http_application_http1_send_header_field_callback, this is not supported\n");
	}

	pthread_cleanup_push(rrr_string_builder_clear_void, &string_builder);

	if ((ret = __rrr_http_application_http1_header_field_make(&string_builder, field)) != 0) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_push_const (callback_data->handle, string_builder.buf, string_builder.wpos)) != 0) {
		RRR_DBG_1("Error: Send failed in __rrr_http_application_http1_send_header_field_callback\n");
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_application_http1_send_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;
	return rrr_net_transport_ctx_send_push_const (
			handle,
			str,
			len
	);
}

static int __rrr_http_application_http1_response_send_response_code_callback (
		unsigned int response_code,
		enum rrr_http_version protocol_version,
		void *arg
) {
	struct rrr_http_application_http1_response_send_callback_data *callback_data = arg;

	int ret = 0;

	char *response_str_tmp = NULL;

	if (rrr_asprintf (
			&response_str_tmp,
			"%s %u %s\r\n",
			(protocol_version == RRR_HTTP_VERSION_10 ? "HTTP/1.0" : "HTTP/1.1"),
			response_code,
			rrr_http_util_iana_response_phrase_from_status_code(response_code)
	) <= 0) {
		RRR_MSG_0("rrr_asprintf failed in __rrr_http_application_http1_response_send_response_code_callback\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_push_const(callback_data->handle, response_str_tmp, strlen(response_str_tmp))) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(response_str_tmp);
	return ret;
}

static int __rrr_http_application_http1_response_send_final (
	struct rrr_http_part *request_part,
	struct rrr_http_part *response_part,
	const struct rrr_nullsafe_str *send_data,
	void *arg
) {
	struct rrr_http_application_http1_response_send_callback_data *callback_data = arg;

	(void)(response_part);

	int ret = 0;

	if ((ret = rrr_net_transport_ctx_send_push_const(callback_data->handle, "\r\n", 2)) != 0 ) {
		goto out;
	}

	if (rrr_nullsafe_str_len(send_data)) {
		if ((ret = rrr_nullsafe_str_with_raw_do_const (
				send_data,
				__rrr_http_application_http1_send_callback,
				callback_data->handle
		)) != 0) {
			RRR_MSG_0("Could not send HTTP request body in __rrr_http_application_http1_response_send_final\n");
			goto out;
		}
	}

	if (request_part->parsed_connection != RRR_HTTP_CONNECTION_KEEPALIVE) {
		rrr_net_transport_ctx_close_when_send_complete_set(callback_data->handle);
	}

	out:
	return ret;
}

static int __rrr_http_application_http1_response_send (
		struct rrr_http_application *application,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_transaction *transaction
) {
	int ret = 0;

	if ((ret = rrr_http_part_header_field_push (
			transaction->response_part,
			"connection",
			transaction->request_part->parsed_connection == RRR_HTTP_CONNECTION_KEEPALIVE
				? "keep-alive"
				: "close"
	)) != 0) {
		RRR_MSG_0("Failed to push connection header in __rrr_http_application_http1_response_send\n");
		goto out;
	}

	struct rrr_http_application_http1_response_send_callback_data callback_data = {
			handle
	};

	if ((ret = rrr_http_transaction_response_prepare_wrapper (
			transaction,
			__rrr_http_application_http1_response_send_header_field_callback,
			__rrr_http_application_http1_response_send_response_code_callback,
			__rrr_http_application_http1_response_send_final,
			&callback_data
	)) != 0) {
		RRR_DBG_2("Failed to send response to HTTP client\n");
		goto out;
	}

	((struct rrr_http_application_http1 *) application)->complete_transaction_count++;

	out:
	return ret;
}

struct rrr_http_application_http1_receive_data {
	struct rrr_net_transport_handle *handle;
	struct rrr_http_application_http1 *http1;
	rrr_biglength received_bytes; // Used only for stall timeout and sleeping
	struct rrr_http_application **upgraded_application;
	const struct rrr_http_rules *rules;
	int (*unique_id_generator_callback)(RRR_HTTP_APPLICATION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS);
	void *unique_id_generator_callback_arg;
	int (*upgrade_verify_callback)(RRR_HTTP_APPLICATION_UPGRADE_VERIFY_CALLBACK_ARGS);
	void *upgrade_verify_callback_arg;
	int (*websocket_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS);
	void *websocket_callback_arg;
	int (*callback)(RRR_HTTP_APPLICATION_RECEIVE_CALLBACK_ARGS);
	void *callback_arg;
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
	rrr_SHA1Input(&sha1_ctx, (const unsigned char *) accept_str_tmp, (unsigned int) strlen(accept_str_tmp));

	if (!rrr_SHA1Result(&sha1_ctx) || sha1_ctx.Corrupted != 0 || sha1_ctx.Computed != 1) {
		RRR_MSG_0("Computation of SHA1 failed in __rrr_http_session_websocket_make_accept_string (Corrupt: %i - Computed: %i)\n",
				sha1_ctx.Corrupted, sha1_ctx.Computed);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	rrr_SHA1toBE(&sha1_ctx);

	rrr_biglength accept_base64_length = 0;
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

	RRR_DBG_3("HTTP response reading complete, data length is %" PRIrrrbl " response length is %" PRIrrrbl " using protocol %s header length is %" PRIrrrbl "\n",
			transaction->response_part->data_length,
			transaction->response_part->headroom_length,
			RRR_HTTP_VERSION_TO_STR(transaction->response_part->parsed_version),
			transaction->response_part->header_length
	);

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

			RRR_FREE_IF_NOT_NULL(receive_data->http1->application_websocket_topic);

			int do_websocket = 0;
			if ((ret = receive_data->websocket_callback (
					&do_websocket,
					&receive_data->http1->application_websocket_topic,
					receive_data->handle,
					transaction,
					read_session->rx_buf_ptr,
					read_session->rx_overshoot_size,
					transaction->response_part->parsed_application_type,
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
			RRR_DBG_3("Upgrade to HTTP2 size is %" PRIrrrbl " overshoot is %" PRIrrrbl "\n", read_session->rx_buf_wpos, read_session->rx_overshoot_size);

			if ((ret = rrr_http_transaction_response_reset(transaction)) != 0) {
				goto out;
			}

			if (read_session->rx_overshoot_size > RRR_LENGTH_MAX) {
				RRR_MSG_0("Overshoot too big while upgrading response to HTTP2 (%llu>%llu)\n",
					(unsigned long long) read_session->rx_overshoot_size,
					(unsigned long long) RRR_LENGTH_MAX
				);
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			// Pass any extra data received to http2 session for processing there. Overshoot pointer will
			// be set to NULL if http2_session takes control of the pointer.
			ret = rrr_http_application_http2_new_from_upgrade (
					receive_data->upgraded_application,
					(void **) &read_session->rx_overshoot,
					rrr_length_from_biglength_bug_const(read_session->rx_overshoot_size),
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
				transaction->response_part->parsed_application_type,
				receive_data->callback_arg
		)) != 0) {
			goto out;
		}
	}

	receive_data->http1->complete_transaction_count++;
	receive_data->http1->upgrade_active = upgrade_mode;

	out:
	if (ret == RRR_HTTP_OK) {
		if (transaction->response_part->parsed_connection != RRR_HTTP_CONNECTION_KEEPALIVE && upgrade_mode == RRR_HTTP_UPGRADE_MODE_NONE) {
			ret = RRR_HTTP_DONE;
		}
	}
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
		RRR_DBG_1("Incorrect length for Sec-WebSocket-Key header field in HTTP request with WebSocket upgrade. 16 bytes are required but got %" PRIrrr_nullsafe_len "\n",
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

	RRR_FREE_IF_NOT_NULL(receive_data->http1->application_websocket_topic);

	if ((ret = receive_data->websocket_callback (
			do_websocket,
			&receive_data->http1->application_websocket_topic,
			receive_data->handle,
			transaction,
			data_to_use,
			read_session->rx_overshoot_size,
			transaction->response_part->parsed_application_type,
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

	if (read_session->rx_overshoot_size > RRR_LENGTH_MAX) {
		RRR_MSG_0("Overshoot too big while upgrading request to HTTP2 (%llu>%llu)\n",
				(unsigned long long) read_session->rx_overshoot_size,
				(unsigned long long) RRR_LENGTH_MAX
			 );
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	ret = rrr_http_application_http2_new_from_upgrade (
			&http2,
			(void **) &read_session->rx_overshoot,
			rrr_length_from_biglength_bug_const(read_session->rx_overshoot_size),
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
	else if (!receive_data->rules->do_no_server_http2 && upgrade_h2c != NULL) {
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

	if (*(receive_data->upgraded_application) != NULL) {
		// Upgrade was performed in get target size function, nothing to do
		goto out;
	}

	if (transaction->request_part->request_method == 0) {
		RRR_DBG_2("Request parsing was incomplete in HTTP final callback, sending bad request to client.\n");
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
		goto out_send_response;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_part_header_dump(transaction->request_part);
	}

	RRR_DBG_3("HTTP request reading complete, data length is %" PRIrrrbl " response length is %" PRIrrrbl " header length is %" PRIrrrbl "\n",
			transaction->request_part->data_length,
			transaction->request_part->headroom_length,
			transaction->request_part->header_length
	);

	if ((ret = rrr_http_part_chunks_merge(&merged_chunks, transaction->request_part, read_session->rx_buf_ptr)) != 0) {
		goto out;
	}

	const char *data_to_use = (merged_chunks != NULL ? merged_chunks : read_session->rx_buf_ptr);

	if ((ret = rrr_http_part_multipart_and_fields_process (transaction->request_part, data_to_use, receive_data->rules->do_no_body_parse)) != 0) {
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_http_field_collection_dump (&transaction->request_part->fields);
	}

	enum rrr_http_upgrade_mode upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
	if (transaction->request_part->parsed_version != RRR_HTTP_VERSION_10) {
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
				RRR_DBG_3("Note: Upgrade HTTP connection to %s failed, response is now %i\n",
						RRR_HTTP_UPGRADE_MODE_TO_STR(upgrade_mode), transaction->response_part->response_code);
			}
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
				RRR_HTTP_APPLICATION_HTTP2, // Note, next protocol is HTTP2
				receive_data->callback_arg
		)) != RRR_HTTP_OK) {
			if (ret == RRR_HTTP_NO_RESULT) {
				ret = 0;

				rrr_http_application_http2_response_to_upgrade_async_prepare (
						*(receive_data->upgraded_application),
						transaction
				);
			}
		}
		else {
			ret = rrr_http_application_http2_response_to_upgrade_submit (
					*(receive_data->upgraded_application),
					transaction
			);
		}

		// HTTP2 application will send the actual response during the next tick (unless an error occured)
		goto out;
	}
	else {
#endif /* RRR_WITH_NGHTTP2 */
		if ((ret = receive_data->callback (
				receive_data->handle,
				transaction,
				data_to_use,
				read_session->rx_overshoot_size,
				transaction->request_part->parsed_application_type,
				receive_data->callback_arg
		)) != RRR_HTTP_OK) {
			if (ret == RRR_HTTP_NO_RESULT) {
				ret = 0;
				transaction->need_response = 1;
				goto out_no_clear;
			}
			goto out;
		}
#ifdef RRR_WITH_NGHTTP2
	}
#endif /* RRR_WITH_NGHTTP2 */

	out_send_response:
		if ((ret = __rrr_http_application_http1_response_send((struct rrr_http_application *) receive_data->http1, receive_data->handle, transaction)) != 0) {
			goto out;
		}
	out:
		__rrr_http_application_http1_transaction_clear(receive_data->http1);
	out_no_clear:
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
		RRR_BUG("BUG: Request method not set in rrr_http_part_parse after header completed\n");
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

	rrr_biglength target_size;
	rrr_biglength parsed_bytes = 0;

	struct rrr_http_part *part_to_use = NULL;
	enum rrr_http_parse_type parse_type = 0;

	if (rrr_net_transport_ctx_close_when_send_complete_get(receive_data->handle)) {
		// Data received after completed parse of HTTP/1.0 request, drop data as
		// connection is to be closed.
		ret = RRR_HTTP_PARSE_INCOMPLETE;
		goto out;
	}

	if (receive_data->unique_id_generator_callback == NULL) {
		// Is client
		if (receive_data->http1->active_transaction == NULL) {
			RRR_MSG_0("Received unexpected data from HTTP server, no transaction was active\n");
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}
		part_to_use = receive_data->http1->active_transaction->response_part;
		parse_type = RRR_HTTP_PARSE_RESPONSE;
	}
	else {
		// Is server
		if (read_session->parse_pos == 0) {
			struct rrr_http_transaction *transaction = NULL;

			// HTTP1 only supports one active transaction. Make a new and delete any old one. Method
			// does not matter.
			if ((ret = rrr_http_transaction_new (
					&transaction,
					RRR_HTTP_METHOD_GET,
					0,
					0,
					receive_data->unique_id_generator_callback,
					receive_data->unique_id_generator_callback_arg,
					NULL,
					NULL
			)) != 0) {
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
	if (!receive_data->rules->do_no_server_http2 && read_session->parse_pos == 0 && receive_data->unique_id_generator_callback != NULL) {
		// Is server

		const char http2_magic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
		if (	(rrr_biglength) read_session->rx_buf_wpos >= (rrr_biglength) sizeof(http2_magic) - 1 &&
				memcmp(read_session->rx_buf_ptr, http2_magic, sizeof(http2_magic) - 1) == 0
		) {
			if (read_session->rx_buf_wpos > RRR_LENGTH_MAX) {
				RRR_MSG_0("Preliminary data too big during plain HTTP2 initialization (%llu>%llu)\n",
					(unsigned long long) read_session->rx_buf_wpos,
					(unsigned long long) RRR_LENGTH_MAX
				);
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			RRR_DBG_3("HTTP2 magic found, upgrading to native HTTP2 with %llu bytes read so far\n", (long long int) read_session->rx_buf_wpos);
			if ((ret = rrr_http_application_http2_new (
					receive_data->upgraded_application,
					1, // Is server
					(void **) &read_session->rx_buf_ptr,
					rrr_length_from_biglength_bug_const(read_session->rx_buf_wpos)
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
		if (receive_data->unique_id_generator_callback != NULL) {
			// Is server
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

#if RRR_BIGLENGTH_MAX > SIZE_MAX
		if (target_size > SIZE_MAX) {
			RRR_MSG_0("Target size %" PRIrrrbl " exceeds maximum value of %llu while parsing HTTP part\n",
					target_size, (long long unsigned) SIZE_MAX);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}
#endif

		read_session->eof_ok_now = 1;
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
	struct rrr_http_application_http1 *http1;
	struct rrr_net_transport_handle *handle;
	int (*callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_application_http1_websocket_frame_callback (
		RRR_WEBSOCKET_FRAME_CALLBACK_ARGS
) {
	struct rrr_http_application_http1_frame_callback_data *callback_data = arg;

	if (opcode == RRR_WEBSOCKET_OPCODE_BINARY || opcode == RRR_WEBSOCKET_OPCODE_TEXT) {
		return callback_data->callback (
				callback_data->http1->application_websocket_topic,
				callback_data->handle,
				payload,
				(opcode == RRR_WEBSOCKET_OPCODE_BINARY ? 1 : 0),
				callback_data->http1->last_unique_id,
				callback_data->callback_arg
		);
	}

	return RRR_HTTP_OK;
}

static int __rrr_http_application_http1_websocket_responses_get (
		struct rrr_http_application_http1 *http1,
		struct rrr_websocket_state *ws_state,
		rrr_http_unique_id unique_id,
		int (*callback)(RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	void *response_data = NULL;
	rrr_biglength response_data_len = 0;
	int response_is_binary = 0;

	do {
		RRR_FREE_IF_NOT_NULL(response_data);
		if ((ret = callback (
				http1->application_websocket_topic,
				&response_data,
				&response_data_len,
				&response_is_binary,
				unique_id,
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
		rrr_biglength read_max_size,
		rrr_length ping_interval_s,
		rrr_length timeout_s,
		int (*callback)(RRR_HTTP_APPLICATION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS),
		void *get_response_callback_arg,
		int (*frame_callback)(RRR_HTTP_APPLICATION_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *frame_callback_arg
) {
	int ret = 0;

	struct rrr_http_application_http1_frame_callback_data callback_data = {
			http1,
			handle,
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
			http1,
			&http1->ws_state,
			http1->last_unique_id,
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
			0, // No ratelimit interval
			0, // No ratelimit max bytes
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

struct rrr_http_application_http1_request_send_callback_data {
	struct rrr_http_application_http1 *http1;
	struct rrr_net_transport_handle *handle;
	struct rrr_string_builder *header_builder;
};

static int __rrr_http_application_http1_request_send_preliminary_callback (
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		struct rrr_http_part *request_part,
		const struct rrr_nullsafe_str *request,
		void *arg
) {
	struct rrr_http_application_http1_request_send_callback_data *callback_data = arg;

	int ret = 0;

	char *websocket_key_tmp = NULL;
	char *http2_upgrade_settings_tmp = NULL;
	struct rrr_nullsafe_str *request_tmp = NULL;

	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &websocket_key_tmp);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &http2_upgrade_settings_tmp);
	pthread_cleanup_push(rrr_nullsafe_str_destroy_if_not_null_void, &request_tmp);

	if ((ret = rrr_nullsafe_str_dup(&request_tmp, request)) != 0) {
		goto out;
	}

	if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_WEBSOCKET) {
		if (method != RRR_HTTP_METHOD_GET) {
			RRR_BUG("BUG: HTTP method was not GET while upgrade mode was WebSocket\n");
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "connection", "Upgrade")) != 0) {
			goto out;
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "upgrade", "websocket")) != 0) {
			goto out;
		}
		if ((ret = rrr_websocket_state_get_key_base64 (&websocket_key_tmp, &callback_data->http1->ws_state)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "sec-websocket-key", websocket_key_tmp)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_part_header_field_push(request_part, "sec-websocket-version", "13")) != 0) {
			goto out;
		}

		rrr_websocket_state_set_client_mode(&callback_data->http1->ws_state);
	}
	else if (upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2) {
#ifdef RRR_WITH_NGHTTP2
		if (method != RRR_HTTP_METHOD_GET && method != RRR_HTTP_METHOD_HEAD) {
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
	else {
		if ((ret = rrr_http_part_header_field_push (
				request_part,
				"connection",
				protocol_version == RRR_HTTP_VERSION_10
					? "close"
					: "keep-alive"
		)) != 0) {
			goto out;
		}
	}

	// Prepend "GET " etc. before endpoint
	if ((ret = rrr_nullsafe_str_prepend_asprintf (
			request_tmp,
			"%s ",
			RRR_HTTP_METHOD_TO_STR_CONFORMING(method)
	)) < 0) {
		RRR_MSG_0("Error while making request string in rrr_http_application_http1_request_send return was %i\n", ret);
		ret = 1;
		goto out;
	}

	// Append the rest of the header after endpoint
	// Caller should check that version 1.0 is not used together with upgrades as this might cause connection to close after the first response
	if ((ret = rrr_nullsafe_str_append_asprintf (
			request_tmp,
			(protocol_version == RRR_HTTP_VERSION_10 ? " HTTP/1.0\r\n" : " HTTP/1.1\r\n")
	)) < 0) {
		RRR_MSG_0("Error while making request string in rrr_http_application_http1_request_send return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_send_push_nullsafe (callback_data->handle, request_tmp)) != 0) {
		RRR_MSG_0("Could not send first part of HTTP request header in __rrr_http_application_http1_request_send\n");
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_application_http1_request_send_make_headers_callback (
		struct rrr_http_header_field *field,
		void *arg
) {
	struct rrr_http_application_http1_request_send_callback_data *callback_data = arg;
	return __rrr_http_application_http1_header_field_make(callback_data->header_builder, field);
}

static int __rrr_http_application_http1_request_send_final_callback (
		struct rrr_http_part *request_part,
		const struct rrr_nullsafe_str *send_body,
		void *arg
) {
	struct rrr_http_application_http1_request_send_callback_data *callback_data = arg;

	(void)(request_part);

	int ret = 0;

	if (rrr_string_builder_length(callback_data->header_builder) > 0) {
		if ((ret = rrr_net_transport_ctx_send_push_const (callback_data->handle, callback_data->header_builder->buf, callback_data->header_builder->wpos)) != 0) {
			RRR_MSG_0("Could not send second part of HTTP request header in __rrr_http_application_http1_request_send_final_callback\n");
			goto out;
		}
	}

	if ((ret = rrr_net_transport_ctx_send_push_const (callback_data->handle, "\r\n", 2)) != 0) {
		RRR_MSG_0("Could not send HTTP header end in __rrr_http_application_http1_request_send_final_callback\n");
		goto out;
	}

	if (rrr_nullsafe_str_len(send_body)) {
		if ((ret = rrr_nullsafe_str_with_raw_do_const (
				send_body,
				__rrr_http_application_http1_send_callback,
				callback_data->handle
		)) != 0) {
			RRR_MSG_0("Could not send HTTP request body in __rrr_http_application_http1_request_send_final_callback\n");
			goto out;
		}
	}
	out:
	return ret;
}

static int __rrr_http_application_http1_request_send (
		RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS
) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) application;

	int ret = 0;

	// DO NOT do any upgrades here, HTTP1 may do this during ticking only.
	// Upgrades here may cause infinite recursion as HTTP2 upgrades in its request_send function.
	*upgraded_app = NULL;

	struct rrr_string_builder header_builder = {0};

	if (http1->active_transaction != NULL) {
		RRR_BUG("BUG: Existing transaction was not clear in  __rrr_http_application_http1_request_send, caller must check with request_send_possible\n");
	}

	__rrr_http_application_http1_transaction_set(http1, transaction);

	pthread_cleanup_push(rrr_string_builder_clear_void, &header_builder);

	if (protocol_version != RRR_HTTP_VERSION_10) {
		if ((ret = rrr_http_part_header_field_push(transaction->request_part, "host", host)) != 0) {
			goto out;
		}
	}

	struct rrr_http_application_http1_request_send_callback_data callback_data = {
		http1,
		handle,
		&header_builder
	};

	if ((ret = rrr_http_transaction_request_prepare_wrapper (
			transaction,
			upgrade_mode,
			protocol_version,
			user_agent,
			__rrr_http_application_http1_request_send_preliminary_callback,
			__rrr_http_application_http1_request_send_make_headers_callback,
			__rrr_http_application_http1_request_send_final_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_application_http1_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
	struct rrr_http_application_http1 *http1 = (struct rrr_http_application_http1 *) app;

	// Async failure callback not implemented for HTTP1
	(void)(failure_callback);
	(void)(failure_callback_arg);

	int ret = RRR_HTTP_OK;

	*upgraded_app = NULL;

	if (rrr_net_transport_ctx_send_waiting_chunk_count(handle) > 0) {
		goto out;
	}

	if (http1->upgrade_active == RRR_HTTP_UPGRADE_MODE_WEBSOCKET) {
		ret = __rrr_http_application_http1_transport_ctx_tick_websocket (
				http1,
				handle,
				read_max_size,
				10,
				15,
				get_response_callback,
				get_response_callback_arg,
				frame_callback,
				frame_callback_arg
		);
	}
	else if (http1->upgrade_active == RRR_HTTP_UPGRADE_MODE_NONE) {
		if (http1->active_transaction != NULL && http1->active_transaction->need_response) {
			if ((ret = rrr_net_transport_ctx_check_alive(handle)) == 0) {
				if ((ret = async_response_get_callback(http1->active_transaction, async_response_get_callback_arg)) == RRR_HTTP_OK) {
					ret = __rrr_http_application_http1_response_send(app, handle, http1->active_transaction);

					__rrr_http_application_http1_transaction_clear(http1);
				}

				ret &= ~(RRR_HTTP_NO_RESULT);
			}
		}
		else {
			struct rrr_http_application_http1_receive_data callback_data = {
					handle,
					http1,
					*received_bytes,
					upgraded_app,
					rules,
					unique_id_generator_callback,
					unique_id_generator_callback_arg,
					upgrade_verify_callback,
					upgrade_verify_callback_arg,
					websocket_callback,
					websocket_callback_arg,
					callback,
					callback_arg
			};

			ret = rrr_net_transport_ctx_read_message (
						handle,
						1,
						4096,
						65535,
						read_max_size,
						0, // No ratelimit interval
						0, // No ratelimit max bytes
						__rrr_http_application_http1_receive_get_target_size,
						&callback_data,
						unique_id_generator_callback == NULL // No generator indicates client
							? __rrr_http_application_http1_response_receive_callback
							: __rrr_http_application_http1_request_receive_callback,
						&callback_data
			);

			*received_bytes = callback_data.received_bytes;
		}
	}
	else {
		RRR_BUG("__rrr_http_application_http1_tick called while active upgrade was not NONE or WEBSOCKET but %i, maybe caller forgot to switch to HTTP2?\n", http1->upgrade_active);
	}

	out:
	return ret;
}

static int __rrr_http_application_http1_need_tick (
		RRR_HTTP_APPLICATION_NEED_TICK_ARGS
) {
	(void)(app);

	/* No need for extra ticking in HTTP1 */

	return 0;
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
	__rrr_http_application_http1_active_transaction_count_get,
	__rrr_http_application_http1_request_send_possible,
	__rrr_http_application_http1_request_send,
	__rrr_http_application_http1_tick,
	__rrr_http_application_http1_need_tick,
	__rrr_http_application_http1_polite_close
};

int rrr_http_application_http1_new (
		struct rrr_http_application **target
) {
	int ret = 0;

	struct rrr_http_application_http1 *result = NULL;

	if ((result = rrr_allocate(sizeof(*result))) == NULL) {
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


