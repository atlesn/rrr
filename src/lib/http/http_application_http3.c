/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#include <nghttp3/nghttp3.h>

#include "http_application_http3.h"
#include "http_application_internals.h"

#include "../http3/http3.h"
#include "../allocator.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_ctx.h"

struct rrr_http_application_http3 {
	RRR_HTTP_APPLICATION_HEAD;
	struct nghttp3_conn *conn;
	int initialized;
};

static const char rrr_http_application_http3_alpn_protos[] = {
	     2, 'h', '3'
};

static void __rrr_http_application_http3_alpn_protos_get (
		RRR_HTTP_APPLICATION_ALPN_PROTOS_GET_ARGS
) {
	*target = rrr_http_application_http3_alpn_protos;
	*length = sizeof(rrr_http_application_http3_alpn_protos);
}

void rrr_http_application_http3_alpn_protos_get (
		const char **target,
		unsigned int *length
) {
	__rrr_http_application_http3_alpn_protos_get(target, length);
}

static int __rrr_http_applicaiton_http3_ctrl_streams_bind (
		struct rrr_http_application_http3 *http3,
		int64_t stream_id_ctrl,
		int64_t stream_id_qpack_encode,
		int64_t stream_id_qpack_decode
) {
	int ret = 0;
	int ret_tmp;

	if ((ret_tmp = nghttp3_conn_bind_control_stream(http3->conn, stream_id_ctrl)) != 0) {
		printf("Failed to bind control stream in %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	if ((ret_tmp = nghttp3_conn_bind_qpack_streams(http3->conn, stream_id_qpack_encode, stream_id_qpack_decode)) != 0) {
		printf("Failed to bind qpack streams %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_initialize (
		struct rrr_http_application_http3 *http3,
		struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	RRR_DBG_3("http3 %p initializing\n", http3);

	int64_t stream_id_ctrl = -1;
	int64_t stream_id_qpack_encode = -1;
	int64_t stream_id_qpack_decode = -1;

	if ((ret = rrr_net_transport_ctx_stream_open (
			&stream_id_ctrl,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_stream_open (
			&stream_id_qpack_encode,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_stream_open (
			&stream_id_qpack_decode,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_applicaiton_http3_ctrl_streams_bind (
			http3,
			stream_id_ctrl,
			stream_id_qpack_encode,
			stream_id_qpack_encode
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_net_transport_cb_get_message (
		RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS
) {
    	(void)(stream_id);
    	(void)(data_vector);
    	(void)(data_vector_count);
    	(void)(fin);
    	(void)(arg);

	RRR_BUG("%s\n", __func__);
}

static int __rrr_http_application_http3_net_transport_cb_stream_blocked (
		RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS
) {
    	(void)(stream_id);
    	(void)(is_blocked);
    	(void)(arg);
	RRR_BUG("%s\n", __func__);
}

static int __rrr_http_application_http3_net_transport_cb_stream_ack (
		RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS
) {
    	(void)(stream_id);
    	(void)(bytes);
    	(void)(arg);
	RRR_BUG("%s\n", __func__);
}

static int __rrr_http_application_http3_stream_open (
		RRR_HTTP_APPLICATION_STREAM_OPEN_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) app;

	(void)(handle);
	(void)(stream_id);
	(void)(flags);

	printf("Stream open %li\n", stream_id);

	*cb_get_message = __rrr_http_application_http3_net_transport_cb_get_message;
	*cb_blocked = __rrr_http_application_http3_net_transport_cb_stream_blocked;
	*cb_ack = __rrr_http_application_http3_net_transport_cb_stream_ack;
	*cb_arg = http3;

	return 0;
}

static void  __rrr_http_application_http3_destroy (
		struct rrr_http_application *application
) {
	rrr_free(application);
}

uint64_t __rrr_http_application_http3_active_transaction_count_get_and_maintain (
		struct rrr_http_application *application
) {
}

static int __rrr_http_application_http3_request_send_possible (
		RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS
) {
	(void)(application);
	*is_possible = 0;
	return 0;
}

static int __rrr_http_application_http3_request_send (
		RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS
) {
}

static int __rrr_http_application_http3_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) app;

	int ret = 0;

	if (!http3->initialized) {
		if ((ret = __rrr_http_application_http3_initialize(http3, handle)) != 0) {
			goto out;
		}
		http3->initialized = 1;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_need_tick (
		RRR_HTTP_APPLICATION_NEED_TICK_ARGS
) {
}

static void __rrr_http_application_http3_polite_close (
		RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS
) {
}

static int __rrr_http_application_http3_nghttp3_cb_acked_stream_data (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t datalen,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(datalen);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_stream_close (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(app_error_code);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_recv_data (
		nghttp3_conn *conn,
		int64_t stream_id,
		const uint8_t *data,
		size_t datalen,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(data);
	(void)(datalen);
	(void)(conn_user_data);
	(void)(stream_user_data);

	printf("Data: %.*s\n", (int) datalen, data);

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_deferred_consume (
		nghttp3_conn *conn,
		int64_t stream_id,
		size_t consumed,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(consumed);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_recv_header (
		nghttp3_conn *conn,
		int64_t stream_id,
		int32_t token,
		nghttp3_rcbuf *name,
		nghttp3_rcbuf *value,
		uint8_t flags,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(token);
	(void)(name);
	(void)(value);
	(void)(flags);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_stop_sending (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(app_error_code);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_reset_stream (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(app_error_code);
	(void)(conn_user_data);
	(void)(stream_user_data);

	printf("Reset stream %li\n", stream_id);

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_end_stream (
		nghttp3_conn *conn,
		int64_t stream_id,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(conn_user_data);
	(void)(stream_user_data);

	printf("End stream %li\n", stream_id);

	return 0;
}

static void *__rrr_http_application_http3_cb_malloc (size_t size, void *user_data) {
	(void)(user_data);
	return rrr_allocate(size);
}

static void __rrr_http_application_http3_cb_free (void *ptr, void *user_data) {
	(void)(user_data);
	rrr_free(ptr);
}

static void *__rrr_http_application_http3_cb_calloc (size_t nmemb, size_t size, void *user_data) {
	(void)(user_data);
	return rrr_callocate(nmemb, size);
}

static void *__rrr_http_application_http3_cb_realloc (void *ptr, size_t size, void *user_data) {
	(void)(user_data);
	return rrr_reallocate(ptr, size);
}

static const struct rrr_http_application_constants rrr_http_application_http3_constants = {
	RRR_HTTP_APPLICATION_HTTP3,
	__rrr_http_application_http3_destroy,
	__rrr_http_application_http3_active_transaction_count_get_and_maintain,
	__rrr_http_application_http3_request_send_possible,
	__rrr_http_application_http3_request_send,
	__rrr_http_application_http3_tick,
	__rrr_http_application_http3_need_tick,
	__rrr_http_application_http3_polite_close,
	__rrr_http_application_http3_stream_open
};

static const nghttp3_callbacks rrr_http_application_http3_nghttp3_callbacks = {
	__rrr_http_application_http3_nghttp3_cb_acked_stream_data,
	__rrr_http_application_http3_nghttp3_cb_stream_close,
	__rrr_http_application_http3_nghttp3_cb_recv_data,
	__rrr_http_application_http3_nghttp3_cb_deferred_consume,
	NULL, /* begin_headers */
	__rrr_http_application_http3_nghttp3_cb_recv_header,
	NULL, /* end_headers */
	NULL, /* begin_trailers */
	NULL, /* recv_trailer */
	NULL, /* end_trailers */
	__rrr_http_application_http3_nghttp3_cb_stop_sending,
	__rrr_http_application_http3_nghttp3_cb_end_stream,
	__rrr_http_application_http3_nghttp3_cb_reset_stream,
	NULL, /* shutdown */
};

static const nghttp3_mem rrr_http_application_http3_nghttp3_mem = {
	.malloc = __rrr_http_application_http3_cb_malloc,
	.free= __rrr_http_application_http3_cb_free,
	.calloc = __rrr_http_application_http3_cb_calloc,
	.realloc = __rrr_http_application_http3_cb_realloc
};

int rrr_http_application_http3_new (
		struct rrr_http_application **result,
		int is_server,
		const struct rrr_http_application_callbacks *callbacks
) {
	(void)(is_server);

	int ret = 0;

	struct rrr_http_application_http3 *http3;
	nghttp3_settings settings = {0};

	if ((http3 = rrr_allocate_zero(sizeof(*http3))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	nghttp3_settings_default(&settings);

	if (nghttp3_conn_client_new (
			&http3->conn,
			&rrr_http_application_http3_nghttp3_callbacks,
			&settings,
			&rrr_http_application_http3_nghttp3_mem,
			http3
	) != 0) {
		printf("Failed to create http3 client\n");
		ret = 1;
		goto out;
	}

	http3->constants = &rrr_http_application_http3_constants;
	http3->callbacks = *callbacks;

	*result = (struct rrr_http_application *) http3;

	RRR_DBG_3("http3 %p new %s application\n", http3, is_server ? "server" : "client");

	goto out;
//	out_free:
//		rrr_free(http3);
	out:
		return ret;
}
