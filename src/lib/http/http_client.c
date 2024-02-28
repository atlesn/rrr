/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>

#include "../log.h"
#include "../allocator.h"

#include "http_client.h"
#include "http_common.h"
#include "http_part.h"
#include "http_util.h"
#include "http_session.h"
#include "http_client_config.h"
#include "http_application.h"
#ifdef RRR_WITH_NGHTTP2
#	include "http_application_http2.h"
#endif
#ifdef RRR_WITH_HTTP3
#	include "http_application_http3.h"
#endif
#include "http_transaction.h"
#include "http_redirect.h"
#include "http_service.h"

#include "../event/event.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"

#define RRR_HTTP_CLIENT_GRAYLIST_PERIOD_SHORT_MS    200
#define RRR_HTTP_CLIENT_GRAYLIST_PERIOD_LONG_MS    1000

#define RRR_HTTP_CLIENT_GRAYLIST_F_SHORT   (1<<0)
#define RRR_HTTP_CLIENT_GRAYLIST_F_LONG    (1<<1)

struct rrr_http_client {
	struct rrr_event_queue *events;

	uint64_t idle_timeout_ms;
	rrr_length send_chunk_count_limit;

	struct rrr_http_rules rules;

	struct rrr_net_transport *transport_keepalive_plain;
	struct rrr_net_transport *transport_keepalive_tls;
	struct rrr_net_transport *transport_keepalive_quic;

	struct rrr_http_redirect_collection redirects;
	struct rrr_http_service_collection alt_svc;

	struct rrr_http_client_callbacks callbacks;
};

int rrr_http_client_new (
		struct rrr_http_client **target,
		struct rrr_event_queue *events,
		uint64_t idle_timeout_ms,
		rrr_length send_chunk_count_limit,
		const struct rrr_http_client_callbacks *callbacks
) {
	int ret = 0;

	struct rrr_http_client *client = rrr_allocate(sizeof(*client));

	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(client, '\0', sizeof(*client));

	client->events = events;
	client->idle_timeout_ms = idle_timeout_ms;
	client->callbacks = *callbacks;
	client->send_chunk_count_limit = send_chunk_count_limit;

	*target = client;

	goto out;
//	out_free:
//		free(client);
	out:
		return ret;
}

void rrr_http_client_destroy (
		struct rrr_http_client *client
) {
	if (client->transport_keepalive_plain) {
		rrr_net_transport_destroy(client->transport_keepalive_plain);
	}
	if (client->transport_keepalive_tls) {
		rrr_net_transport_destroy(client->transport_keepalive_tls);
	}
	if (client->transport_keepalive_quic) {
		rrr_net_transport_destroy(client->transport_keepalive_quic);
	}
	rrr_http_redirect_collection_clear(&client->redirects);
	rrr_http_service_collection_clear(&client->alt_svc);
	rrr_free(client);
}

void rrr_http_client_set_response_max_size (
		struct rrr_http_client *client,
		rrr_biglength set
) {
	client->rules.client_response_max_size = set;
}

static int __rrr_http_client_active_transaction_count_get_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	uint64_t *result_accumulator = arg;

	if (RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle) != NULL) {
		*result_accumulator += rrr_http_session_transport_ctx_active_transaction_count_get_and_maintain(handle);
	}

	return 0;
}

uint64_t rrr_http_client_active_transaction_count_get (
		const struct rrr_http_client *http_client
) {
	uint64_t result_accumulator = 0;

	if (http_client->transport_keepalive_plain != NULL) {
		rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_plain,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_active_transaction_count_get_callback,
				&result_accumulator
		);
	}

	if (http_client->transport_keepalive_tls != NULL) {
		rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_tls,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_active_transaction_count_get_callback,
				&result_accumulator
		);
	}

	if (http_client->transport_keepalive_quic != NULL) {
		rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_quic,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_active_transaction_count_get_callback,
				&result_accumulator
		);
	}

	return result_accumulator + (unsigned long) RRR_LL_COUNT(&http_client->redirects);;
}

static int __rrr_http_client_websocket_response_available_notify_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	(void)(arg);
	rrr_http_session_transport_ctx_websocket_response_available_notify(handle);
	return 0;
}

void rrr_http_client_websocket_response_available_notify (
		struct rrr_http_client *http_client
) {
	if (http_client->transport_keepalive_plain != NULL) {
		rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_plain,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_websocket_response_available_notify_callback,
				NULL
		);
	}

	if (http_client->transport_keepalive_tls != NULL) {
		rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_tls,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_websocket_response_available_notify_callback,
				NULL
		);
	}

	if (http_client->transport_keepalive_quic != NULL) {
		rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_quic,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				__rrr_http_client_websocket_response_available_notify_callback,
				NULL
		);
	}
}

static void __rrr_http_client_dbl_ptr_free_if_not_null (void *arg) {
	void *ptr = *((void **) arg);
	RRR_FREE_IF_NOT_NULL(ptr);
}

static void __rrr_http_client_uri_dbl_ptr_destroy_if_not_null (void *arg) {
	struct rrr_http_uri *uri = *((void **) arg);
	if (uri != NULL) {
		rrr_http_util_uri_destroy(uri);
	}
}

static void __rrr_http_client_alt_svc_clear (void *arg) {
	struct rrr_http_service_collection *alt_svc = arg;
	rrr_http_service_collection_clear(alt_svc);
}

static int __rrr_http_client_request_data_strings_reset (
		struct rrr_http_client_request_data *data,
		const char *server,
		const char *endpoint,
		const char *user_agent
) {
	int ret = 0;

	if (server != NULL) {
		RRR_FREE_IF_NOT_NULL(data->server);
		if ((data->server = rrr_strdup(server)) == NULL) {
			RRR_MSG_0("Could not allocate memory for server in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if (endpoint != NULL) {
		RRR_FREE_IF_NOT_NULL(data->endpoint);
		if ((data->endpoint = rrr_strdup(endpoint)) == NULL) {
			RRR_MSG_0("Could not allocate memory for endpoint in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if (user_agent != NULL) {
		RRR_FREE_IF_NOT_NULL(data->user_agent);
		if ((data->user_agent = rrr_strdup(user_agent)) == NULL) {
			RRR_MSG_0("Could not allocate memory for user_agent in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_request_data (
		struct rrr_http_client_request_data *target,
		const struct rrr_http_client_request_data *source
) {
	int ret = 0;

	memcpy(target, source, sizeof(*target));

	// Make sure all string pointers are reset to avoid mayhem
	target->server = NULL;
	target->endpoint = NULL;
	target->user_agent = NULL;

	if ((ret = __rrr_http_client_request_data_strings_reset(target, source->server, source->endpoint, source->user_agent)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset (
		struct rrr_http_client_request_data *data,
		enum rrr_http_transport transport_force,
		enum rrr_http_method method,
		enum rrr_http_body_format body_format,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		int do_plain_http2,
		const char *user_agent
) {
	int ret = 0;

	if ((ret = __rrr_http_client_request_data_strings_reset(data, NULL, NULL, user_agent)) != 0) {
		goto out;
	}

	data->method = method;
	data->body_format = body_format;
	data->upgrade_mode = upgrade_mode;
	data->protocol_version = protocol_version;
	data->transport_force = transport_force;
	data->do_plain_http2 = do_plain_http2;

	if (data->concurrent_connections == 0) {
		data->concurrent_connections = 1;
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_config (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_client_config *config
) {
	int ret = 0;

	if ((ret = __rrr_http_client_request_data_strings_reset(data, config->server, config->endpoint, NULL)) != 0) {
		goto out;
	}

	if (config->concurrent_connections < 1 || config->concurrent_connections > 65535) {
		RRR_BUG("BUG: Concurrent connection parameter out of range in %s\n", __func__);
	}

	data->http_port = rrr_u16_from_biglength_bug_const(config->server_port);
	data->concurrent_connections = rrr_u16_from_biglength_bug_const(config->concurrent_connections);

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_uri (
		struct rrr_http_client_request_data *data,
		const struct rrr_http_uri *uri
) {
	int ret = 0;

	struct rrr_http_uri_flags uri_flags = {0};
	rrr_http_util_uri_flags_get(&uri_flags, uri);

	if (uri_flags.is_http || uri_flags.is_websocket) {
		data->transport_force = (uri_flags.is_tls ? RRR_HTTP_TRANSPORT_HTTPS : RRR_HTTP_TRANSPORT_HTTP);
		data->upgrade_mode = (uri_flags.is_websocket ? RRR_HTTP_UPGRADE_MODE_WEBSOCKET : RRR_HTTP_UPGRADE_MODE_HTTP2);
	}

	if ((ret = __rrr_http_client_request_data_strings_reset(data, uri->host, uri->endpoint, NULL)) != 0) {
		goto out;
	}

	if (uri->port > 0) {
		data->http_port = uri->port;
	}

	out:
	return ret;
}

int rrr_http_client_request_data_reset_from_raw (
		struct rrr_http_client_request_data *data,
		const char *server,
		uint16_t port
) {
	int ret = 0;

	if ((ret = __rrr_http_client_request_data_strings_reset(data, server, NULL, NULL)) != 0) {
		goto out;
	}

	data->http_port = port;

	out:
	return ret;
}

void rrr_http_client_request_data_cleanup (
		struct rrr_http_client_request_data *data
) {
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->endpoint);
	RRR_FREE_IF_NOT_NULL(data->user_agent);
}

void rrr_http_client_request_data_cleanup_void (
		void *data
) {
	rrr_http_client_request_data_cleanup(data);
}

struct rrr_http_client_tick_callback_data {
	struct rrr_http_client *http_client;

	uint64_t bytes_total;
};

static int __rrr_http_client_chunks_iterate_callback (
		RRR_HTTP_PART_ITERATE_CALLBACK_ARGS
) {
	struct rrr_nullsafe_str *chunks_merged = arg;

	(void)(part_data_size);
	(void)(chunk_total);
	(void)(chunk_idx);

	if (chunk_data_size > RRR_LENGTH_MAX) {
		RRR_MSG_0("Chunk too large in HTTP client (%" PRIrrrbl ">%llu)\n",
			chunk_data_size, (unsigned long long) RRR_LENGTH_MAX);
		return RRR_HTTP_SOFT_ERROR;
	}

	return rrr_nullsafe_str_append_raw (
			chunks_merged,
			data_start,
			rrr_length_from_biglength_bug_const(chunk_data_size)
	);
}

uint64_t __rrr_http_client_net_transport_match_number_make (
		uint16_t port,
		uint16_t index,
		enum rrr_http_application_type application_type
) {
	assert(application_type <= 0xff && application_type >= 0 && "Application type out of bounds");

	return (uint64_t) (((uint64_t) application_type << 32) | ((uint64_t) port << 16 ) | index);
}

uint64_t __rrr_http_client_net_transport_match_number_mask_away_index (
		uint64_t number
) {
	return number & 0xffffffffffff0000;
}

struct rrr_http_client_receive_match_data_callback_data {
	struct rrr_http_transaction *transaction;
	struct rrr_http_service_collection *alt_svc;
};

static int __rrr_http_client_receive_match_data_callback (
		const char *string,
		uint64_t number,
		void *arg
) {
	struct rrr_http_client_receive_match_data_callback_data *callback_data = arg;

	int ret = 0;

	if ((ret = rrr_http_transaction_response_alt_svc_get (
			callback_data->alt_svc,
			callback_data->transaction,
			string,
			__rrr_http_client_net_transport_match_number_mask_away_index(number)
	) != 0)) {
		RRR_MSG_0("Error while iterating alt-svc headers in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_client_receive_alt_svc_get (
		struct rrr_http_service_collection *alt_svc,
		struct rrr_net_transport_handle *handle,
		struct rrr_http_transaction *transaction
) {
	struct rrr_http_client_receive_match_data_callback_data callback_data = {
		transaction,
		alt_svc
	};

	return rrr_net_transport_ctx_with_match_data_do (
			handle,
			__rrr_http_client_receive_match_data_callback,
			&callback_data
	);
}

static int __rrr_http_client_receive_http_part_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_client *http_client = arg;

	(void)(overshoot_bytes);
	(void)(next_application_type);

	int ret = RRR_HTTP_OK;

	const struct rrr_http_header_field *location;
	struct rrr_http_part *response_part = transaction->response_part;
	struct rrr_nullsafe_str *data_chunks_merged = NULL;
	struct rrr_nullsafe_str *data_decoded = NULL;

	if ((ret = rrr_nullsafe_str_new_or_replace_raw(&data_chunks_merged, NULL, 0)) != 0) {
		goto out;
	}

	if ((ret = rrr_nullsafe_str_new_or_replace_raw(&data_decoded, NULL, 0)) != 0) {
		goto out;
	}

	const struct rrr_nullsafe_str *data_use = data_chunks_merged;

	// Moved-codes. Maybe this parsing is too permissive.
	if (response_part->response_code >= 300 && response_part->response_code <= 399) {
		location = rrr_http_part_header_field_get(response_part, "location");
		if (location == NULL || !rrr_nullsafe_str_isset(location->value)) {
			RRR_MSG_0("Could not find Location-field in HTTP redirect response %i %s\n",
					response_part->response_code,
					rrr_http_util_iana_response_phrase_from_status_code(response_part->response_code)
			);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value, location->value);
		if ((transaction->remaining_redirects)-- == 0) {
			RRR_MSG_0("HTTP client maximum number of redirects reached after received redirect response with location '%s'\n", value);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		else {
			RRR_DBG_3("HTTP client redirect to '%s'\n", value);
		}

assert(0 && "wrap with handle match data");

		if ((ret = rrr_http_redirect_collection_push (
				&http_client->redirects,
				transaction,
				location->value
		)) != 0) {
			goto out;
		}
		rrr_http_transaction_incref(transaction);

		goto out;
	}

	if ((ret = rrr_http_part_chunks_iterate (
			response_part,
			data_ptr,
			__rrr_http_client_chunks_iterate_callback,
			data_chunks_merged
	) != 0)) {
		RRR_MSG_0("Error while iterating chunks in response in %s\n", __func__);
		goto out;
	}

#ifdef RRR_HTTP_UTIL_WITH_ENCODING
	const struct rrr_http_header_field *encoding = rrr_http_part_header_field_get(response_part, "content-encoding");
	if (encoding != NULL && rrr_nullsafe_str_isset(encoding->value) && rrr_nullsafe_str_len(data_use) > 0) {
		if ((ret = rrr_http_util_decode (
				data_decoded,
				data_use,
				encoding->value
		) != 0)) {
			RRR_MSG_0("Error %i while decoding in response in %s\n", ret, __func__);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		data_use = data_decoded;
	}
#endif

	if ((ret = __rrr_http_client_receive_alt_svc_get (
			&http_client->alt_svc,
			handle,
			transaction
	)) != 0) {
		RRR_MSG_0("Error while getting alt-svc headers in %s\n", __func__);
		goto out;
	}

	ret = http_client->callbacks.final_callback (
			transaction,
			data_use,
			http_client->callbacks.callback_arg
	);

	out:
	rrr_nullsafe_str_destroy_if_not_null(&data_chunks_merged);
	rrr_nullsafe_str_destroy_if_not_null(&data_decoded);
	return ret;
}

static int __rrr_http_client_request_failure_callback (
		RRR_HTTP_SESSION_FAILURE_CALLBACK_ARGS
) {
	struct rrr_http_client *http_client = arg;

	(void)(handle);

	return http_client->callbacks.failure_callback != NULL
		? http_client->callbacks.failure_callback (
				transaction,
				error_msg,
				http_client->callbacks.callback_arg
		)
		: 0
	;
}

static int __rrr_http_client_websocket_get_response_callback (
		RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS
) {
	struct rrr_http_client *http_client = arg;

	*data = NULL;
	*data_len = 0;
	*is_binary = 0;

	return http_client->callbacks.get_response_callback != NULL
		? http_client->callbacks.get_response_callback (
				application_topic,
				data,
				data_len,
				is_binary,
				unique_id,
				http_client->callbacks.callback_arg
		)
		: 0
	;
}

static int __rrr_http_client_websocket_frame_callback (
		RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS
) {
	struct rrr_http_client *http_client = arg;

	return http_client->callbacks.frame_callback != NULL
		? http_client->callbacks.frame_callback (
				application_topic,
				handle,
				payload,
				is_binary,
				unique_id,
				http_client->callbacks.callback_arg
		)
		: 0
	;
}

static int __rrr_http_client_websocket_handshake_callback (
		RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
) {
	(void)(arg);
	(void)(handle);
	(void)(transaction);
	(void)(data_ptr);
	(void)(overshoot_bytes);
	(void)(next_application_type);
	(void)(application_topic);

	int ret = 0;

	RRR_DBG_3("HTTP WebSocket handshake response from server received\n");

	*do_websocket = 1;

	return ret;
}

struct rrr_http_client_redirect_callback_data {
	int (*callback)(RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS);
	void *callback_arg;
};

static int __rrr_http_client_redirect_callback (
		struct rrr_http_transaction *transaction,
		const struct rrr_nullsafe_str *uri_nullsafe,
		void *arg
) {
	struct rrr_http_client_redirect_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_http_uri *uri = NULL;
	char *endpoint_path_tmp = NULL;
	struct rrr_http_service_collection alt_svc = {0};

	pthread_cleanup_push(__rrr_http_client_uri_dbl_ptr_destroy_if_not_null, &uri);
	pthread_cleanup_push(__rrr_http_client_dbl_ptr_free_if_not_null, &endpoint_path_tmp);
	pthread_cleanup_push(__rrr_http_client_alt_svc_clear, &alt_svc);

	if (callback_data->callback == NULL) {
		RRR_MSG_0("HTTP client got a redirect response but no redirect callback is defined\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (rrr_http_util_uri_parse(&uri, uri_nullsafe) != 0) {
		RRR_MSG_0("Could not parse Location from redirect response header\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (uri->endpoint == NULL || *(uri->endpoint) != '/') {
		if ((ret = rrr_http_transaction_endpoint_path_get (&endpoint_path_tmp, transaction)) != 0) {
			goto out;
		}
		if ((ret = rrr_http_util_uri_endpoint_prepend(uri, endpoint_path_tmp)) != 0) {
			goto out;
		}
	}

	assert(0 && "Get alt svc");
/*
	if ((ret = __rrr_http_client_receive_alt_svc_get (
			&alt_svc,
			handle,
			transaction
	)) != 0) {
		RRR_MSG_0("Error while getting alt-svc headers in %s\n", __func__);
		goto out;
	}
*/

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(response_arg, uri_nullsafe);
	RRR_DBG_3("HTTP redirect to '%s' (%s, %s, %s, %u) original endpoint was '%s' transport '%s'\n",
			response_arg,
			(uri->protocol != NULL ? uri->protocol : "-"),
			(uri->host != NULL ? uri->host : "-"),
			(uri->endpoint != NULL ? uri->endpoint : "-"),
			uri->port,
			transaction->endpoint_str,
			RRR_HTTP_TRANSPORT_TO_STR(transaction->transport_code)
	);

	ret = callback_data->callback(transaction, uri, callback_data->callback_arg);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

static int __rrr_http_client_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
) {
	struct rrr_http_client *http_client = arg;

	int ret = 0;

	rrr_biglength received_bytes = 0;

	int again_max = 5;

	enum rrr_http_tick_speed tick_speed;

	again:

	tick_speed = RRR_HTTP_TICK_SPEED_NO_TICK;

	if ((ret = rrr_http_session_transport_ctx_tick_client (
			&received_bytes,
			handle,
			http_client->rules.client_response_max_size
	)) != 0) {
		goto out;
	}

	struct rrr_http_client_redirect_callback_data redirect_callback_data = {
		http_client->callbacks.redirect_callback,
		http_client->callbacks.callback_arg
	};

	if ((ret = rrr_http_redirect_collection_iterate (
			&http_client->redirects,
			__rrr_http_client_redirect_callback,
			&redirect_callback_data
	)) != 0) {
		goto out;
	}

	rrr_http_session_transport_ctx_need_tick(&tick_speed, handle);

	switch (tick_speed) {
		case RRR_HTTP_TICK_SPEED_NO_TICK:
			if (RRR_LL_COUNT(&http_client->redirects) == 0) {
				break;
			}
			/* Fallthrough */
		case RRR_HTTP_TICK_SPEED_FAST:
			if (again_max--) {
				goto again;
			}
			rrr_net_transport_ctx_notify_tick_fast(handle);
			break;
		case RRR_HTTP_TICK_SPEED_SLOW:
			rrr_net_transport_ctx_notify_tick_slow(handle);
			break;
	};

	ret = received_bytes == 0 ? RRR_NET_TRANSPORT_READ_INCOMPLETE : RRR_NET_TRANSPORT_READ_OK;

	out:
	return ret;
}

static int __rrr_http_client_request_send_final_transport_ctx_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_client_request_callback_data *callback_data = arg;
	enum rrr_http_version protocol_version = callback_data->data->protocol_version;
	enum rrr_http_upgrade_mode upgrade_mode = callback_data->data->upgrade_mode;

	int ret = 0;

	char *query_to_free = NULL;
	char *endpoint_to_free = NULL;
	char *endpoint_and_query_to_free = NULL;
	unsigned char invalid_byte = 0;

	struct rrr_http_application *upgraded_app = NULL;
	enum rrr_http_tick_speed tick_speed = RRR_HTTP_TICK_SPEED_NO_TICK;

	// Upgrade to HTTP2 only possibly with GET requests in plain mode or with all request methods in TLS mode
	if ( upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2 &&
	     callback_data->data->method != RRR_HTTP_METHOD_GET &&
	    !rrr_net_transport_ctx_is_tls(handle)
	) {
		upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
	}

	// Usage of HTTP/1.0 causes connection closure after response, don't use while upgrading. The
	// protocol version is ignored when HTTP/2 is used.
	if (upgrade_mode != RRR_HTTP_UPGRADE_MODE_NONE && protocol_version == RRR_HTTP_VERSION_10) {
		protocol_version = RRR_HTTP_VERSION_11;
	}

	if ((ret = rrr_http_session_transport_ctx_client_new_or_clean (
			callback_data->transaction->application_type,
			handle,
			callback_data->data->user_agent,
			__rrr_http_client_websocket_handshake_callback,
			__rrr_http_client_receive_http_part_callback,
			__rrr_http_client_request_failure_callback,
			__rrr_http_client_websocket_get_response_callback,
			__rrr_http_client_websocket_frame_callback,
			callback_data->http_client
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in %s\n", __func__);
		goto out;
	}

	int request_send_is_possible;
	if ((ret = rrr_http_session_transport_ctx_request_send_possible (
			&request_send_is_possible,
			handle
	)) != 0) {
		RRR_MSG_0("Error while checking for request send possible in HTTP session in %s\n", __func__);
		goto out;
	}

	if (!request_send_is_possible) {
		ret = RRR_HTTP_BUSY;
		goto out;
	}

	const char *endpoint_to_use = NULL;

	if (callback_data->query_prepare_callback != NULL) {
		if	((ret = callback_data->query_prepare_callback (
				&endpoint_to_free,
				&query_to_free,
				callback_data->transaction,
				callback_data->callback_arg)
		) != RRR_HTTP_OK) {
			if (ret == RRR_HTTP_SOFT_ERROR) {
				RRR_MSG_3("Note: HTTP query aborted by soft error from query prepare callback in %s\n", __func__);
				ret = 0;
				goto out;
			}
			RRR_MSG_0("Error %i from query prepare callback in %a\n", ret, __func__);
			goto out;
		}
	}

	// Endpoint to use precedence:
	// 1. endpoint from query prepare callback
	// 2. endpoint from configuration
	// 3. default endpoint /

	if (endpoint_to_free == NULL || *(endpoint_to_free) == '\0') {
		if (callback_data->data->endpoint != NULL) {
			endpoint_to_use = callback_data->data->endpoint;
		}
		else {
			RRR_FREE_IF_NOT_NULL(endpoint_to_free);
			if ((endpoint_to_free = rrr_strdup("/")) == NULL) {
				RRR_MSG_0("Could not allocate memory for endpoint in %s\n");
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}
			endpoint_to_use = endpoint_to_free;
		}
	}
	else {
		endpoint_to_use = endpoint_to_free;
	}

	if (rrr_http_util_uri_validate_characters (
			&invalid_byte,
			endpoint_to_use
	) != 0) {
		RRR_MSG_0("Invalid HTTP endpoint '%s', it contains invalid/non-conforming characters. Offending character was '%c'/0x%02x.\n",
			endpoint_to_use, invalid_byte, invalid_byte);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (query_to_free != NULL && *(query_to_free) != '\0') {
		if (strchr(endpoint_to_use, '?') != 0) {
			RRR_MSG_0("HTTP endpoint '%s' already contained a query string, cannot append query '%s' from callback. Request aborted.\n",
					endpoint_to_use, query_to_free);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		if ((ret = rrr_asprintf(&endpoint_and_query_to_free, "%s?%s", endpoint_to_use, query_to_free)) <= 0) {
			RRR_MSG_0("Could not allocate string for endpoint and query in %s return was %i\n", __func__, ret);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}
	else {
		if ((endpoint_and_query_to_free = rrr_strdup(endpoint_to_use)) == NULL) {
			RRR_MSG_0("Could not allocate string for endpoint in %s\n", __func__);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	RRR_DBG_3("HTTP using endpoint: '%s'\n", endpoint_and_query_to_free);

	if ((ret = rrr_http_transaction_endpoint_set (
			callback_data->transaction,
			endpoint_and_query_to_free
	)) != 0) {
		RRR_MSG_0("Could not set HTTP endpoint in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_request_send (
			&upgraded_app,
			handle,
			callback_data->request_header_host,
			callback_data->transaction,
			upgrade_mode,
			protocol_version
	)) != 0) {
		if (ret != RRR_HTTP_BUSY) {
			RRR_MSG_0("Could not send request in %s, return was %i\n", __func__, ret);
		}
		goto out;
	}

	// Happens during TLS downgrade from HTTP2 to HTTP1 when ALPN negotiation fails
	if (upgraded_app != NULL) {
		rrr_http_session_transport_ctx_application_set(&upgraded_app, handle);
	}

	rrr_http_session_transport_ctx_need_tick(&tick_speed, handle);

	switch (tick_speed) {
		case RRR_HTTP_TICK_SPEED_NO_TICK:
			break;
		case RRR_HTTP_TICK_SPEED_FAST:
			rrr_net_transport_ctx_notify_tick_fast(handle);
			break;
		case RRR_HTTP_TICK_SPEED_SLOW:
			rrr_net_transport_ctx_notify_tick_slow(handle);
			break;
	};

	// Make sure connection does not time out just after request has been sent
	rrr_net_transport_ctx_touch(handle);

	goto out;
	out:
		rrr_http_application_destroy_if_not_null(&upgraded_app);
		RRR_FREE_IF_NOT_NULL(endpoint_to_free);
		RRR_FREE_IF_NOT_NULL(endpoint_and_query_to_free);
		RRR_FREE_IF_NOT_NULL(query_to_free);
		return ret;
}

void __rrr_http_client_request_send_connect_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	(void)(sockaddr);
	(void)(socklen);

	int *result = arg;
	*result = RRR_NET_TRANSPORT_CTX_HANDLE(handle);
}

static int __rrr_http_client_request_send_intermediate_connect (
		struct rrr_net_transport *transport_keepalive,
		struct rrr_http_client_request_callback_data *callback_data,
		const char * const server_to_use,
		const uint16_t port_to_use
) {
	int ret = 0;

	int graylist_count;
	int graylist_flags;

	for (uint16_t concurrent_index = 0; concurrent_index < callback_data->data->concurrent_connections; concurrent_index++) {
		// Match number with index used to look up any existing handle in the transport
		const uint64_t match_number = __rrr_http_client_net_transport_match_number_make (
				port_to_use,
				concurrent_index,
				callback_data->transaction->application_type
		);

		/*
		 * LONG and SHORT graylist periodis are added whenever a connection attempt is made for each
		 * given server and service. Only one connection attempt can be made for each target. If a
		 * service is connected but BUSY, another connection is made. This usually only happens for
		 * HTTP1.
		 *
		 * In case of failing connection attempts of main and alternative services, the following
		 * algorithm applies:
		 *
		 * - During LONG timeout for a target, no new connection attempts may be made.
		 * - After the SHORT period has expired (and before LONG timeout has expired), the alt-svc
		 *   selector will not suggest a graylisted service.
		 * - During the SHORT timeout, the alt-svc selector will still suggest the service to allow
		 *   any handshaking to complete.
		 *
		 * The SHORT timeout must be short enough to allow trying multiple alternative services
		 * within a LONG timeout. It should be set to LONG / 5.
		 *
		 * If all of plain, tls and quic modes are active and the latter two are reported by the
		 * server as alternative services, the following timeline describes how connection
		 * attempts for the different services will be made over time if none of them are reachable.
		 * C indicates connection attempt while H indicates handshaking.
		 *
		 *     HTTP1 |                   | SHORT ->| LONG --- --------- --------- -------->|   ...
		 *           |                   | C (H)       (H)       (H)                       |   ...
		 *     HTTP2 |         | SHORT ->| LONG --- --------- --------- -------->| SHORT ->|   ...
		 *           |         | C (H)   |                                       | C           ...
		 *     HTTP3 | SHORT ->| LONG --- --------- --------- -------->| SHORT ->| LONG ---    ...
		 *           | C  H    |                                       | C H H H |             ...
		 *
		 * 1. The highest protocol, HTTP3, is selected first. Since there is no immediate
		 *    feedback for UDP connections, handshaking will continue during the SHORT timeout
		 *    period. After the SHORT timeout, HTTP3 is no longer selected.
		 *
		 * 2. The second highest protocol, HTTP2, is selected. It will either immediately fail
		 *    due to connection refused/timeout or fail during later handshaking. After the
		 *    SHORT timeout, HTTP2 is no longer selected.
		 *
		 * 3. HTTP1 is not an alternative service, and it will be used when neither of HTTP2 and
		 *    HTTP3 are selected. HTTP3 will be used again later when its LONG timeout has passed.
		 *
		 *  HTTP2 may also be implicitly selected in place of HTTP1 if TLS is used and the server
		 *  reports HTTP2 in the ALPN. In both cases, in case of TLS, handshaking will occur until
		 *  another service is selected.
		 */

		// Match number without index used for preventing multiple connection attempts to the same
		// server and for graylisting checks in alt-svc selector.
		const uint64_t match_number_common = __rrr_http_client_net_transport_match_number_make (
				port_to_use,
				0,
				callback_data->transaction->application_type
		);

		rrr_net_transport_handle keepalive_handle = rrr_net_transport_handle_get_by_match (
				transport_keepalive,
				server_to_use,
				match_number
		);

		if (keepalive_handle == 0) {
			rrr_net_transport_graylist_get (
					&graylist_count,
					&graylist_flags,
					transport_keepalive,
					server_to_use,
					match_number_common
			);

			if (graylist_count > 0) {
				RRR_DBG_3("HTTP client not making connection to %s:%" PRIu16 " due to destination being graylisted\n",
						server_to_use, port_to_use);
				ret = RRR_HTTP_BUSY;
				goto next;
			}

			RRR_DBG_3("HTTP client new connection to %s:%" PRIu16 " %" PRIu16 "/%" PRIu16 "\n",
					server_to_use,
					port_to_use,
					concurrent_index + 1,
					callback_data->data->concurrent_connections
			);

			if ((ret = rrr_net_transport_graylist_push (
					transport_keepalive,
					server_to_use,
					match_number_common,
					RRR_HTTP_CLIENT_GRAYLIST_PERIOD_LONG_MS * 1000,
					RRR_HTTP_CLIENT_GRAYLIST_F_LONG
			)) != 0) {
				RRR_MSG_0("Failed to add to graylist in %s\n", __func__);
				goto out;
			}

			if ((ret = rrr_net_transport_graylist_push (
					transport_keepalive,
					server_to_use,
					match_number_common,
					RRR_HTTP_CLIENT_GRAYLIST_PERIOD_SHORT_MS * 1000,
					RRR_HTTP_CLIENT_GRAYLIST_F_SHORT
			)) != 0) {
				RRR_MSG_0("Failed to add to graylist in %s\n", __func__);
				goto out;
			}

			if ((ret = rrr_net_transport_connect (
					transport_keepalive,
					port_to_use,
					server_to_use,
					__rrr_http_client_request_send_connect_callback,
					&keepalive_handle
			)) != 0) {
				goto out;
			}

			if ((ret = rrr_net_transport_handle_match_data_set (
					transport_keepalive,
					keepalive_handle,
					server_to_use,
					match_number
			)) != 0) {
				RRR_MSG_0("Failed to set match data in %s\n", __func__);
				goto out;
			}
		}
		else {
			RRR_DBG_3("HTTP client existing connection to %s:%" PRIu16 " %" PRIu16 "/%" PRIu16 "\n",
					server_to_use,
					port_to_use,
					concurrent_index + 1,
					callback_data->data->concurrent_connections
			);
		}

		if ((ret = rrr_net_transport_handle_check_handshake_complete (
				transport_keepalive,
				keepalive_handle
		)) != RRR_READ_OK) {
			ret = RRR_HTTP_BUSY;
			goto next;
		}

		ret = rrr_net_transport_handle_with_transport_ctx_do (
				transport_keepalive,
				keepalive_handle,
				__rrr_http_client_request_send_final_transport_ctx_callback,
				callback_data
		);

		next:
		if (ret != RRR_HTTP_BUSY) {
			break;
		}
	}

	out:
		return ret;
}

static void __rrr_http_client_alt_svc_select (
		enum rrr_http_transport *transport_to_use,
		enum rrr_http_application_type *application_to_use,
		const char **server_to_use,
		uint16_t *port_to_use,
		struct rrr_http_client *http_client,
		const struct rrr_http_service_collection *alt_svc,
		const enum rrr_http_transport transport_force,
		const int concurrent_max
) {
	enum rrr_http_transport transport_new = *transport_to_use;
	enum rrr_http_application_type application_new = *application_to_use;
	const char *server_new = *server_to_use;
	uint16_t port_new = *port_to_use;
	struct rrr_net_transport *transport_keepalive;
	int graylist_count;
	int graylist_flags;

	RRR_ASSERT(RRR_HTTP_TRANSPORT_QUIC > RRR_HTTP_TRANSPORT_HTTPS && RRR_HTTP_TRANSPORT_HTTPS > RRR_HTTP_TRANSPORT_HTTP,transport_codes_must_be_in_order);
	RRR_ASSERT(RRR_HTTP_APPLICATION_HTTP3 > RRR_HTTP_APPLICATION_HTTP2 && RRR_HTTP_APPLICATION_HTTP2 > RRR_HTTP_APPLICATION_HTTP1,application_codes_must_be_in_order);

	RRR_LL_ITERATE_BEGIN(alt_svc, struct rrr_http_service);
		const char *server_tmp = node->uri.host != NULL && *node->uri.host != '\0' ? node->uri.host : *server_to_use;

		assert(node->uri.transport > RRR_HTTP_TRANSPORT_ANY && node->uri.transport <= RRR_HTTP_TRANSPORT_QUIC);

		if (node->uri.transport == RRR_HTTP_TRANSPORT_HTTP && !(transport_keepalive = http_client->transport_keepalive_plain))
			RRR_LL_ITERATE_NEXT();
		if (node->uri.transport == RRR_HTTP_TRANSPORT_HTTPS && !(transport_keepalive = http_client->transport_keepalive_tls))
			RRR_LL_ITERATE_NEXT();
		if (node->uri.transport == RRR_HTTP_TRANSPORT_QUIC && !(transport_keepalive = http_client->transport_keepalive_quic))
			RRR_LL_ITERATE_NEXT();

		if (transport_force != RRR_HTTP_TRANSPORT_ANY && transport_force != node->uri.transport)
			RRR_LL_ITERATE_NEXT();
		if (node->uri.transport < transport_new || node->uri.application_type < application_new)
			RRR_LL_ITERATE_NEXT();

		if (__rrr_http_client_net_transport_match_number_make(*port_to_use, 0, *application_to_use) != node->match_number)
			RRR_LL_ITERATE_NEXT();
		if (*server_to_use != NULL && node->match_string != NULL && strcmp(*server_to_use, node->match_string) != 0)
			RRR_LL_ITERATE_NEXT();

		rrr_net_transport_graylist_get (
				&graylist_count,
				&graylist_flags,
				transport_keepalive,
				server_tmp,
				__rrr_http_client_net_transport_match_number_make (
						node->uri.port,
						0,
						node->uri.application_type
				)
		);

		// Don't use alternative service if it is LONG graylisted after
		// SHORT graylisting has expired.
		if ( (graylist_flags & RRR_HTTP_CLIENT_GRAYLIST_F_LONG) &&
		    !(graylist_flags & RRR_HTTP_CLIENT_GRAYLIST_F_SHORT)
		) {
			RRR_DBG_3("HTTP alt-svc transport %s application %s server %s port %u is graylisted, not using\n",
				RRR_HTTP_TRANSPORT_TO_STR(node->uri.transport),
				RRR_HTTP_APPLICATION_TO_STR(node->uri.application_type),
				server_tmp,
				node->uri.port
			);
			RRR_LL_ITERATE_NEXT();
		}

		RRR_DBG_3("HTTP selecting alt-svc transport %s and application %s over %s and %s\n",
			RRR_HTTP_TRANSPORT_TO_STR(node->uri.transport),
			RRR_HTTP_APPLICATION_TO_STR(node->uri.application_type),
			RRR_HTTP_TRANSPORT_TO_STR(transport_new),
			RRR_HTTP_APPLICATION_TO_STR(application_new)
		);

		RRR_DBG_3("HTTP selecting alt-svc server %s and port %u over %s and %u\n",
			server_tmp,
			node->uri.port,
			server_new,
			port_new
		);

		transport_new = node->uri.transport;
		application_new = node->uri.application_type;
		server_new = server_tmp;
		port_new = node->uri.port;
	RRR_LL_ITERATE_END();

	if (transport_new == RRR_HTTP_TRANSPORT_HTTP && application_new == RRR_HTTP_APPLICATION_HTTP2) {
		RRR_DBG_3("HTTP using plain HTTP2 for next request\n");
		// TODO : Do something with data->do_plain_http2???

	}

	*transport_to_use = transport_new;
	*application_to_use = application_new;
	*server_to_use = server_new;
	*port_to_use = port_new;
}

#ifdef RRR_WITH_HTTP3
struct rrr_http_client_transport_ctx_stream_open_callback_data {
        void **stream_data;
	void (**stream_data_destroy)(void *stream_data);
	int (**cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS);
	int (**cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS);
	int (**cb_write_confirm)(RRR_NET_TRANSPORT_STREAM_CONFIRM_CALLBACK_ARGS);
	int (**cb_ack_confirm)(RRR_NET_TRANSPORT_STREAM_CONFIRM_CALLBACK_ARGS);
	void **cb_arg;
	int64_t stream_id;
	int flags;
	void *arg_local;
};

static int __rrr_http_client_net_transport_cb_stream_open (
		RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS
) {
	(void)(arg_global);

	return rrr_http_session_transport_ctx_stream_open (
			stream_data,
			stream_data_destroy,
			cb_get_message,
			cb_blocked,
			cb_shutdown_read,
			cb_shutdown_write,
			cb_close,
			cb_write_confirm,
			cb_ack_confirm,
			cb_arg,
			handle,
			stream_id,
			flags,
			arg_local
	);
}
#endif

static int __rrr_http_client_request_send_transport_keepalive_ensure (
		struct rrr_http_client *http_client,
		const struct rrr_net_transport_config *net_transport_config,
		const int ssl_no_cert_verify
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_tmp_plain = {
			NULL,
			NULL,
			NULL,
			NULL,
			RRR_NET_TRANSPORT_PLAIN,
			RRR_NET_TRANSPORT_F_PLAIN
	};

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_HTTP3)
	struct rrr_net_transport_config net_transport_config_tmp_ssl = *net_transport_config;

	int tls_flags = 0;
	if (ssl_no_cert_verify != 0) {
		tls_flags |= RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY;
	}

	const char *alpn_protos = NULL;
	unsigned alpn_protos_length = 0;

#endif

#ifdef RRR_WITH_HTTP3
	if (http_client->transport_keepalive_quic == NULL) {
		net_transport_config_tmp_ssl.transport_type_p = RRR_NET_TRANSPORT_QUIC;
		rrr_http_application_http3_alpn_protos_get(&alpn_protos, &alpn_protos_length);

		// !!! The stream open callback must only be called for local streams
		// and the flag dictating this must be given here.
		//
		// Not giving the flag may cause the callback to be called prior to the
		// HTTP session being created which results in a null pointer access.
		const int flags = tls_flags | RRR_NET_TRANSPORT_F_QUIC_STREAM_OPEN_CB_LOCAL_ONLY;

		if (rrr_net_transport_new (
				&http_client->transport_keepalive_quic,
				&net_transport_config_tmp_ssl,
				"HTTP client",
				flags,
				http_client->events,
				alpn_protos,
				alpn_protos_length,
				http_client->idle_timeout_ms / 4, /* First read timeout */
				http_client->idle_timeout_ms / 2, /* Soft timeout */
				http_client->idle_timeout_ms,     /* Hard timeout */
				http_client->send_chunk_count_limit,
				NULL,
				NULL,
				NULL,
				NULL,
				__rrr_http_client_read_callback,
				http_client,
				__rrr_http_client_net_transport_cb_stream_open,
				NULL
		) != 0) {
			RRR_MSG_0("Could not create QUIC transport in __rrr_http_client_request_send_transport_keepalive_ensure\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}
#endif

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
	if (http_client->transport_keepalive_tls == NULL) {
		net_transport_config_tmp_ssl.transport_type_p = RRR_NET_TRANSPORT_TLS;
#if RRR_WITH_NGHTTP2
		rrr_http_application_http2_alpn_protos_get(&alpn_protos, &alpn_protos_length);
#endif
		if (rrr_net_transport_new (
				&http_client->transport_keepalive_tls,
				&net_transport_config_tmp_ssl,
				"HTTP client",
				tls_flags,
				http_client->events,
				alpn_protos,
				alpn_protos_length,
				0,
				0,
				http_client->idle_timeout_ms,
				http_client->send_chunk_count_limit,
				NULL,
				NULL,
				NULL,
				NULL,
				__rrr_http_client_read_callback,
				http_client,
				NULL,
				NULL
		) != 0) {
			RRR_MSG_0("Could not create TLS transport in %s\n", __func__);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}
#else
	(void)(net_transport_config);
	(void)(ssl_no_cert_verify);
#endif

	if (http_client->transport_keepalive_plain == NULL) {
		if (rrr_net_transport_new (
				&http_client->transport_keepalive_plain,
				&net_transport_config_tmp_plain,
				"HTTP client",
				0,
				http_client->events,
				NULL,
				0,
				0,
				0,
				http_client->idle_timeout_ms,
				http_client->send_chunk_count_limit,
				NULL,
				NULL,
				NULL,
				NULL,
				__rrr_http_client_read_callback,
				http_client,
				NULL,
				NULL
		) != 0) {
			RRR_MSG_0("Could not create plain transport in %s\n", __func__);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_http_client_request_send_intermediate_transport_select (
		struct rrr_http_client_request_callback_data *callback_data,
		enum rrr_http_transport transport_code,
		const char * const server_to_use,
		const uint16_t port_to_use
) {
	struct rrr_http_client *http_client = callback_data->http_client;
	struct rrr_http_transaction *transaction = callback_data->transaction;
	const struct rrr_http_client_request_data *data = callback_data->data;

	int ret = 0;

	struct rrr_net_transport *transport_keepalive_to_use = NULL;

	switch (transport_code) {
		case RRR_HTTP_TRANSPORT_HTTPS: {
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
			transport_keepalive_to_use = http_client->transport_keepalive_tls;
#else
			RRR_MSG_0("Warning: HTTPS was requested but RRR was not compiled with OpenSSL or LibreSSL support, aborting request\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
#endif
		} break;
		case RRR_HTTP_TRANSPORT_QUIC: {
#ifdef RRR_WITH_HTTP3
			transport_keepalive_to_use = http_client->transport_keepalive_quic;
#else
			RRR_MSG_0("Warning: QUIC was requested but RRR was not compiled with HTTP3 support, aborting request\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
#endif
		} break;
		default: {
			if (data->transport_force != RRR_HTTP_TRANSPORT_ANY && data->transport_force != transport_code) {
				// Note that this should not happen after transport changes
				// as a consequence of alt-svc header. The alt-svc select
				// function should check the transport force paramenter
				// and ignore mismatch suggestions.

				RRR_MSG_0("Warning: Transport type %s was forced while %s was attempted (possibly following redirect), aborting request\n",
					RRR_HTTP_TRANSPORT_TO_STR(data->transport_force),
					RRR_HTTP_TRANSPORT_TO_STR(transport_code)
				);

				ret = RRR_HTTP_SOFT_ERROR;

				goto out;
			}

			transport_keepalive_to_use = http_client->transport_keepalive_plain;
			transport_code = RRR_HTTP_TRANSPORT_HTTP;
		} break;
	}

	if (transport_keepalive_to_use == NULL) {
		RRR_MSG_0("No transport found for HTTP transport %s, transport is not supported\n", RRR_HTTP_TRANSPORT_TO_STR(transport_code));
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	transaction->transport_code = transport_code;

	assert(server_to_use != NULL);
	assert(port_to_use > 0);
	assert(transaction->transport_code > 0);
	assert(transaction->method > 0);
	assert(transaction->application_type > 0);

	RRR_DBG_3("HTTP client request using server %s port %u transport %s method '%s' format '%s' application '%s' version '%s' upgrade mode '%s'\n",
			server_to_use,
			port_to_use,
			RRR_HTTP_TRANSPORT_TO_STR(transaction->transport_code),
			RRR_HTTP_METHOD_TO_STR(transaction->method),
			RRR_HTTP_BODY_FORMAT_TO_STR(transaction->request_body_format),
			RRR_HTTP_APPLICATION_TO_STR(transaction->application_type),
			RRR_HTTP_VERSION_TO_STR(data->protocol_version),
			RRR_HTTP_UPGRADE_MODE_TO_STR(data->upgrade_mode)
	);

	if ((ret = __rrr_http_client_request_send_intermediate_connect (
			transport_keepalive_to_use,
			callback_data,
			server_to_use,
			port_to_use
	)) != 0) {
		if (ret == RRR_HTTP_BUSY) {
			RRR_DBG_3("HTTP application temporarily busy during request to server %s port %u transport %s in http client\n",
				server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code));
		}
		else {
			RRR_DBG_2("HTTP request to server %s port %u transport %s failed in http client, return was %i\n",
				server_to_use, port_to_use, RRR_HTTP_TRANSPORT_TO_STR(transport_code), ret);
		}
	}

	out:
	return ret;
}

static int __rrr_http_client_request_send_intermediate_alt_svc_select (
		struct rrr_http_client_request_callback_data *callback_data,
		enum rrr_http_transport transport_code,
		enum rrr_http_application_type application_type,
		const char *server_to_use,
		uint16_t port_to_use
) {
	struct rrr_http_client *http_client = callback_data->http_client;
	struct rrr_http_transaction *transaction = callback_data->transaction;
	const struct rrr_http_client_request_data *data = callback_data->data;

	int ret = 0;

	__rrr_http_client_alt_svc_select (
			&transport_code,
			&application_type,
			&server_to_use,
			&port_to_use,
			http_client,
			&http_client->alt_svc,
			data->transport_force,
			data->concurrent_connections
	);

	transaction->application_type = application_type;

	if ((ret = __rrr_http_client_request_send_intermediate_transport_select (
			callback_data,
			transport_code,
			server_to_use,
			port_to_use
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

// Note that data in the struct may change if there are any redirects
// Note that query prepare callback is not called if raw request data is set
int rrr_http_client_request_send (
		const struct rrr_http_client_request_data *data,
		struct rrr_http_client *http_client,
		const struct rrr_net_transport_config *net_transport_config,
		rrr_biglength remaining_redirects,
		int (*method_prepare_callback)(RRR_HTTP_CLIENT_METHOD_PREPARE_CALLBACK_ARGS),
		int (*connection_prepare_callback)(RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS),
		int (*query_prepare_callback)(RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS),
		void *callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
) {
	int ret = 0;

	struct rrr_http_transaction *transaction = NULL;
	char *server_to_free = NULL;
	char *request_header_host_to_free = NULL;
	uint16_t port_to_use;
	enum rrr_http_transport transport_code;
	const char *server_to_use;
	enum rrr_http_application_type application_type;

	if ((ret = rrr_http_transaction_new (
			&transaction,
			data->method,
			data->body_format,
			remaining_redirects,
			http_client->callbacks.unique_id_generator_callback,
			http_client->callbacks.callback_arg,
			application_data,
			application_data_destroy
	)) != 0) {
		RRR_MSG_0("Could not create HTTP transaction in %s\n", __func__);
		goto out;
	}

#ifdef RRR_HTTP_UTIL_WITH_ENCODING
	if ((ret = rrr_http_transaction_request_accept_encoding_set (
			transaction,
			rrr_http_util_encodings_get()
	)) != 0) {
		RRR_MSG_0("Failed to push accept encofing header in %s\n", __func__);
		goto out;
	}
#endif

	port_to_use = data->http_port;
	transport_code = RRR_HTTP_TRANSPORT_ANY;

	if (data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}
	else if (data->transport_force == RRR_HTTP_TRANSPORT_HTTP) {
		transport_code = RRR_HTTP_TRANSPORT_HTTP;
	}
	else if (data->transport_force == RRR_HTTP_TRANSPORT_QUIC) {
		transport_code = RRR_HTTP_TRANSPORT_QUIC;
	}

	if (port_to_use == 0) {
		if (transport_code == RRR_HTTP_TRANSPORT_HTTPS || transport_code == RRR_HTTP_TRANSPORT_QUIC) {
			port_to_use = 443;
		}
		else {
			port_to_use = 80;
		}
	}

	server_to_use = data->server;

	if (connection_prepare_callback != NULL) {
		if ((ret = connection_prepare_callback(&server_to_free, &port_to_use, callback_arg)) != 0) {
			if (ret == RRR_HTTP_SOFT_ERROR) {
				RRR_DBG_3("Note: HTTP query aborted by soft error from connection prepare callback\n");
				goto out;
			}
			RRR_MSG_0("Error %i from HTTP client connection prepare callback\n", ret);
			goto out;
		}
		if (server_to_free != NULL) {
			server_to_use = server_to_free;
		}
	}

	if (server_to_use == NULL) {
		RRR_BUG("BUG: No server set in %s\n", __func__);
	}

	if (port_to_use == 0) {
		RRR_BUG("BUG: Port was 0 in %s\n", __func__);
	}

	if (transport_code == RRR_HTTP_TRANSPORT_ANY && port_to_use == 443) {
		transport_code = RRR_HTTP_TRANSPORT_HTTPS;
	}

	if (rrr_asprintf(&request_header_host_to_free, "%s:%u", server_to_use, port_to_use) <= 0) {
		RRR_MSG_0("Failed to allocate memory for host header in %s\n", __func__);
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	application_type = (transport_code == RRR_HTTP_TRANSPORT_QUIC
		? RRR_HTTP_APPLICATION_HTTP3
		: RRR_HTTP_APPLICATION_HTTP1
	);

#ifdef RRR_WITH_NGHTTP2
	// If upgrade mode is HTTP2, force HTTP2 application when HTTPS is used
	if (data->upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2 && transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
		application_type = RRR_HTTP_APPLICATION_HTTP2;
	}

	if (data->do_plain_http2 && transport_code != RRR_HTTP_TRANSPORT_HTTPS) {
		application_type = RRR_HTTP_APPLICATION_HTTP2;
	}

	// Must try HTTP2 first because ALPN upgrade is always sent, downgrade to HTTP/1.1 will occur if negotiation fails
	if (data->upgrade_mode == RRR_HTTP_UPGRADE_MODE_NONE && transport_code == RRR_HTTP_TRANSPORT_HTTPS) {
		application_type = RRR_HTTP_APPLICATION_HTTP2;
	}
#endif /* RRR_WITH_NGHTTP2 */

	if (method_prepare_callback != NULL) {
		enum rrr_http_method chosen_method = data->method;
		if ((ret = method_prepare_callback(&chosen_method, callback_arg)) != 0) {
			if (ret != RRR_HTTP_NO_RESULT) {
				goto out;
			}
		}
		else {
			transaction->method = chosen_method;
		}
	}

	if ((ret = __rrr_http_client_request_send_transport_keepalive_ensure (
			http_client,
			net_transport_config,
			data->ssl_no_cert_verify
	)) != 0) {
		goto out;
	}

	struct rrr_http_client_request_callback_data callback_data = {
		.http_client = http_client,
		.query_prepare_callback = query_prepare_callback,
		.callback_arg = callback_arg,
		.data = data,
		.transaction = transaction,
		.request_header_host = request_header_host_to_free
	};

	if ((ret = __rrr_http_client_request_send_intermediate_alt_svc_select (
			&callback_data,
			transport_code,
			application_type,
			server_to_use,
			port_to_use
	)) != 0) {
		goto out;
	}

	out:
	rrr_http_transaction_decref_if_not_null(transaction);
	RRR_FREE_IF_NOT_NULL(server_to_free);
	RRR_FREE_IF_NOT_NULL(request_header_host_to_free);
	return ret;
}

int rrr_http_client_connections_close_if_open (
		struct rrr_http_client *http_client
) {
	int ret = 0;

	if (http_client->transport_keepalive_plain != NULL) {
		ret |= rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_plain,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				rrr_http_session_transport_ctx_close_if_open,
				NULL
		);
	}

	if (http_client->transport_keepalive_tls != NULL) {
		ret |= rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_tls,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				rrr_http_session_transport_ctx_close_if_open,
				NULL
		);
	}

	if (http_client->transport_keepalive_quic != NULL) {
		ret |= rrr_net_transport_iterate_by_mode_and_do (
				http_client->transport_keepalive_quic,
				RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
				rrr_http_session_transport_ctx_close_if_open,
				NULL
		);
	}

	return ret;
}

