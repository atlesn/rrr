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
#include <assert.h>

#include "http_application_http3.h"
#include "http_application_http2_http3_common.h"
#include "http_application_internals.h"
#include "http_transaction.h"
#include "http_util.h"
#include "http_part.h"
#include "http_header_fields.h"

#include "../http3/http3.h"
#include "../allocator.h"
#include "../map.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_ctx.h"
#include "../util/rrr_time.h"

// Enable printf logging in nghttp3 library
//#define RRR_HTTP_APPLICATION_HTTP3_NGHTTP3_DEBUG 1

// TODO : Replace with RTT times to or otherwise per spec
#define RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_PROGRESSION_INTERVAL_US (250 * 1000) /* 250 ms */

enum rrr_http_application_http3_shutdown_state {
	RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NONE                   = 0,
	RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_LOCAL_STREAMS   = 1<<0,
	RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_REMOTE_STREAMS  = 1<<1,
	RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_FINAL                  = 1<<2
};

struct rrr_http_application_http3 {
	RRR_HTTP_APPLICATION_HEAD;
	struct nghttp3_conn *conn;
	int is_server;
	int initialized;
	enum rrr_http_application_http3_shutdown_state shutdown_state;
	uint64_t shutdown_time;
	struct rrr_net_transport *transport;
	rrr_net_transport_handle handle;
	const struct rrr_http_rules *rules;
};

const char rrr_http_application_http3_alpn_protos[] = {
	     2, 'h', '3',
	     5, 'h', '3', '-', '3', '2'
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

static int __rrr_http_application_http3_ctrl_streams_bind (
		struct rrr_http_application_http3 *http3,
		int64_t stream_id_ctrl,
		int64_t stream_id_qpack_encode,
		int64_t stream_id_qpack_decode
) {
	int ret = 0;
	int ret_tmp;

	if ((ret_tmp = nghttp3_conn_bind_control_stream(http3->conn, stream_id_ctrl)) != 0) {
		RRR_MSG_0("Failed to bind control stream in %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	if ((ret_tmp = nghttp3_conn_bind_qpack_streams(http3->conn, stream_id_qpack_encode, stream_id_qpack_decode)) != 0) {
		RRR_MSG_0("Failed to bind qpack streams %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
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

	if ((ret = rrr_net_transport_ctx_stream_open_local (
			&stream_id_ctrl,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL,
			NULL
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_stream_open_local (
			&stream_id_qpack_encode,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL,
			NULL
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_stream_open_local (
			&stream_id_qpack_decode,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL,
			NULL
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_application_http3_ctrl_streams_bind (
			http3,
			stream_id_ctrl,
			stream_id_qpack_encode,
			stream_id_qpack_decode
	)) != 0) {
		goto out;
	}

	http3->transport = RRR_NET_TRANSPORT_CTX_TRANSPORT(handle);
	http3->handle = RRR_NET_TRANSPORT_CTX_HANDLE(handle);

	out:
	return ret;
}

static int __rrr_http_application_http3_map_to_nv (
		nghttp3_nv **result,
		size_t *result_len,
		const struct rrr_map *map
) {
	*result = NULL;
	*result_len = 0;

	int ret = 0;

	rrr_length len;
	nghttp3_nv *nv;

	len = rrr_length_from_slength_bug_const(RRR_MAP_COUNT(map));

	if ((nv = rrr_allocate_zero(sizeof(*nv) * (size_t) len)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	nghttp3_nv *nv_pos = nv;
	RRR_MAP_ITERATE_BEGIN(map);
		nv_pos->name = (uint8_t *) node_tag;
		nv_pos->namelen = strlen(node_tag);
		nv_pos->value = (uint8_t *) node_value;
		nv_pos->valuelen = rrr_length_from_slength_bug_const(value_length);

		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(buf_a, (const char *) nv_pos->name, nv_pos->namelen);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(buf_b, (const char *) nv_pos->value, nv_pos->valuelen);

		RRR_DBG_3("Push HTTP3 header %s=%s\n", buf_a, buf_b);

		nv_pos++;
	RRR_MAP_ITERATE_END();

	*result = nv;
	*result_len = (size_t) len;

	out:
	return ret;
}

struct rrr_http_application_http3_map_add_nullsafe_callback_data {
	struct rrr_map *map;
	const char *tag;
};

static int __rrr_http_application_http3_map_add_nullsafe_callback (const void *str, rrr_nullsafe_len len, void *arg) {
	struct rrr_http_application_http3_map_add_nullsafe_callback_data *callback_data = arg;
	return rrr_map_item_add_new_with_size (
			callback_data->map,
			callback_data->tag,
			str,
			rrr_length_from_biglength_bug_const(len)
	);

}

static int __rrr_http_application_http3_map_add_nullsafe (
		struct rrr_map *map,
		const char *name,
		const struct rrr_nullsafe_str *value
) {
	struct rrr_http_application_http3_map_add_nullsafe_callback_data callback_data = {
		map,
		name
	};

	return rrr_nullsafe_str_with_raw_do_const (
			value,
			__rrr_http_application_http3_map_add_nullsafe_callback, 
			&callback_data
	);
}

static int __rrr_http_application_http3_stream_user_data_ensure (
		struct rrr_http_transaction **transaction,
		struct rrr_http_application_http3 *http3,
		int64_t stream_id,
		void *user_data
) {
	int ret = 0;

	int ret_tmp;

	if (user_data != NULL) {
		goto out;
	}

	if ((ret = rrr_net_transport_handle_stream_data_get (
			&user_data,
			http3->transport,
			http3->handle,
			stream_id
	)) != 0) {
		goto out;
	}

	assert(user_data != NULL);

	if ((ret_tmp = nghttp3_conn_set_stream_user_data (
			http3->conn,
			stream_id,
			user_data
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	*transaction = user_data;
	return ret;
}

#define GET_TRANSACTION()                                          \
    struct rrr_http_transaction *transaction;                      \
    if (__rrr_http_application_http3_stream_user_data_ensure (     \
        &transaction,                                              \
        http3,                                                     \
        stream_id,                                                 \
        stream_user_data                                           \
    ) != 0) { return NGHTTP3_ERR_CALLBACK_FAILURE; }               \
    struct rrr_net_transport *transport = transaction->protocol_ptr;       \
    rrr_net_transport_handle transport_handle = transaction->protocol_int

static int __rrr_http_application_http3_read_data_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	nghttp3_vec *vec = arg;

	if (len > SIZE_MAX) {
		RRR_MSG_0("Data length %" PRIrrr_nullsafe_len " exceeds maximum of %llu in %s\n",
			len, (unsigned long long) SIZE_MAX, __func__);
		return 1;
	}

	vec->base = (uint8_t *) str; // Cast away const OK
	vec->len = rrr_size_from_biglength_bug_const(len);

	return 0;
}

nghttp3_ssize __rrr_http_application_http3_read_data_callback (
		nghttp3_conn *conn,
		int64_t stream_id,
		nghttp3_vec *vec,
		size_t veccnt,
		uint32_t *pflags,
		void *conn_user_data,
		void *stream_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	(void)(conn);
	(void)(veccnt);

	GET_TRANSACTION();

	(void)(transport);
	(void)(transport_handle);

	*pflags = NGHTTP3_DATA_FLAG_EOF;

	int ret_tmp;

	if (rrr_nullsafe_str_len(transaction->send_body) == 0) {
		return 0;
	}

	assert(veccnt > 0);

	if ((ret_tmp = rrr_nullsafe_str_with_raw_do_const (
			transaction->send_body,
			__rrr_http_application_http3_read_data_nullsafe_callback,
			vec
	)) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 1;
}

struct rrr_http_application_http3_request_send_prepare_callback_data {
	struct rrr_http_application_http3 *http3;
	struct rrr_map *headers;
	struct rrr_net_transport_handle *handle;
	int64_t stream_id;
};

static int __rrr_http_application_http3_header_fields_submit_callback (
		struct rrr_http_header_field *field,
		void *arg
) {
	struct rrr_http_application_http3_request_send_prepare_callback_data *callback_data = arg;

	int ret = 0;

	if (!rrr_nullsafe_str_isset(field->name) || !rrr_nullsafe_str_isset(field->value)) {
		RRR_BUG("BUG: Name or value was NULL in %s\n", __func__);
	}
	if (RRR_LL_COUNT(&field->fields) > 0) {
		RRR_BUG("BUG: Subvalues were present in %s, this is not supported\n", __func__);
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name, field->name);

	if ((ret = __rrr_http_application_http3_map_add_nullsafe (callback_data->headers, name, field->value)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct rrr_http_application_http3_response_submit_callback_data {
	struct rrr_http_application_http3 *http3;
	struct rrr_map *headers;
	int64_t stream_id;
};

static int __rrr_http_application_http3_response_submit_final_callback (
		struct rrr_http_transaction *transaction,
		void *arg
) {
	struct rrr_http_application_http3_response_submit_callback_data *callback_data = arg;

	(void)(transaction);

	int ret = 0;

	int ret_tmp;
	nghttp3_nv *nv;
	size_t nv_len;

	static const struct nghttp3_data_reader data_reader = {
		__rrr_http_application_http3_read_data_callback
	};

	if ((ret = __rrr_http_application_http3_map_to_nv (&nv, &nv_len, callback_data->headers)) != 0) {
		goto out;
	}

	if ((ret_tmp = nghttp3_conn_submit_response (
			callback_data->http3->conn,
			callback_data->stream_id,
			nv,
			nv_len,
			&data_reader
	)) != 0) {
		RRR_MSG_0("Failed to submit HTTP3 response: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	rrr_free(nv);
	return ret;
}

static int __rrr_http_application_http3_response_submit_response_code_callback (
		unsigned int response_code,
		enum rrr_http_version protocol_version,
		void *arg
) {
	struct rrr_http_application_http3_response_submit_callback_data *callback_data = arg;

	(void)(protocol_version);

	int ret = 0;

	if (response_code > 999) {
		RRR_BUG("BUG: Invalid response code %u to %s\n", response_code, __func__);
	}

	char tmp[8];
	sprintf(tmp, "%u", response_code);

	if ((ret = rrr_map_item_add_new (callback_data->headers, ":status", tmp)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_response_submit (
		struct rrr_http_application_http3 *http3,
		struct rrr_http_transaction *transaction,
		int64_t stream_id
) {
	int ret = 0;

	struct rrr_map headers = {0};

	if (http3->callbacks.response_postprocess_callback != NULL && (ret = http3->callbacks.response_postprocess_callback (
			transaction,
			http3->callbacks.callback_arg
	)) != 0) {
		goto out;
	}

	struct rrr_http_application_http3_response_submit_callback_data callback_data = {
		http3,
		&headers,
		stream_id
	};

	RRR_DBG_3("HTTP3 response submit status %i send data length %" PRIrrr_nullsafe_len "\n",
			transaction->response_part->response_code,
			rrr_nullsafe_str_len(transaction->send_body));

	if ((ret = rrr_http_transaction_response_prepare_wrapper (
			transaction,
			__rrr_http_application_http3_header_fields_submit_callback,
			__rrr_http_application_http3_response_submit_response_code_callback,
			__rrr_http_application_http3_response_submit_final_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	rrr_net_transport_handle_notify_read(http3->transport, http3->handle);

	out:
	rrr_map_clear(&headers);
	return ret;
}

static int __rrr_http_application_http3_stream_read_end_respone_submit_callback (
		struct rrr_http_application *application,
		struct rrr_http_transaction *transaction,
		int64_t stream_id,
		void *arg
) {
	(void)(arg);

	return __rrr_http_application_http3_response_submit (
			(struct rrr_http_application_http3 *) application,
			transaction,
			stream_id
	);
}

struct rrr_http_application_http3_stream_read_end_callback_data {
		struct rrr_http_application_http3 *http3;
		struct rrr_http_transaction *transaction;
		struct rrr_net_transport_handle *handle;
		int64_t stream_id;
};

static int __rrr_http_application_http3_stream_read_end_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_http_application_http3_stream_read_end_callback_data *callback_data = arg;

	assert(callback_data->http3->rules != NULL); /* Must be set in tick function */

	return rrr_http_application_http2_http3_common_stream_read_end (
			(struct rrr_http_application *) callback_data->http3,
			callback_data->http3->is_server,
			callback_data->handle,
			callback_data->transaction,
			callback_data->stream_id,
			NULL,
			callback_data->http3->rules,
			str,
			len,
			__rrr_http_application_http3_stream_read_end_respone_submit_callback,
			NULL
	);
}

static int __rrr_http_application_http3_transport_ctx_stream_read_end (
		struct rrr_http_application_http3 *http3,
		struct rrr_http_transaction *transaction,
		struct rrr_net_transport_handle *handle,
		int64_t stream_id
) {
	struct rrr_http_application_http3_stream_read_end_callback_data callback_data = {
		http3,
		transaction,
		handle,
		stream_id
	};

	return rrr_nullsafe_str_with_raw_do_const (
			transaction->read_body,
			__rrr_http_application_http3_stream_read_end_nullsafe_callback,
			&callback_data
	);
}

static int __rrr_http_application_http3_stream_read_end_transport_ctx_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_application_http3_stream_read_end_callback_data *callback_data = arg;

	return __rrr_http_application_http3_transport_ctx_stream_read_end (
			callback_data->http3,
			callback_data->transaction,
			handle,
			callback_data->stream_id
	);
}

static int __rrr_http_application_http3_stream_read_end (
		struct rrr_http_application_http3 *http3,
		struct rrr_http_transaction *transaction,
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle,
		int64_t stream_id
) {
	struct rrr_http_application_http3_stream_read_end_callback_data callback_data = {
		http3,
		transaction,
		NULL,
		stream_id
	};

	return rrr_net_transport_handle_with_transport_ctx_do (
			transport,
			handle,
			__rrr_http_application_http3_stream_read_end_transport_ctx_callback,
			&callback_data
	);
}

static int __rrr_http_application_http3_net_transport_cb_get_message (
		RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS
) {
	struct rrr_http_application_http3 *http3 = arg;

	(void)(stream_id_suggestion);

	int ret = 0;

	ssize_t ret_tmp;

	if ((ret_tmp = nghttp3_conn_writev_stream (
			http3->conn,
			stream_id,
			fin,
			(nghttp3_vec *) data_vector,
			*data_vector_count
	)) < 0) {
		RRR_MSG_0("Failed to get http3 data in %s: %s\n", __func__, nghttp3_strerror((int) ret_tmp));
		ret = 1;
		goto out;
	}

	*data_vector_count = (size_t) ret_tmp;

	out:
	return ret;
}

static int __rrr_http_application_http3_net_transport_cb_stream_blocked (
		RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) arg;

	int ret_tmp;

	if (is_blocked) {
		nghttp3_conn_block_stream (http3->conn, stream_id);
	}
	else if ((ret_tmp = nghttp3_conn_unblock_stream(http3->conn, stream_id)) != 0) {
		RRR_MSG_0("Error from nghttp3 while unblocking in %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		return 1;
	}
	
	return 0;
}

static int __rrr_http_application_http3_net_transport_cb_stream_shutdown_read (
		RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) arg;

	RRR_DBG_3("HTTP3 shutdown read for stream %li from net transport\n", stream_id);

	int ret_tmp;
	if ((ret_tmp = nghttp3_conn_shutdown_stream_read (
			http3->conn,
			stream_id
	)) != 0) {
		RRR_MSG_0("Error from nghttp3 during read shutdown in %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		return 1;
	}

	return 0;
}

static int __rrr_http_application_http3_net_transport_cb_stream_shutdown_write (
		RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) arg;

	RRR_DBG_3("HTTP3 shutdown write for stream %li from net transport\n", stream_id);

	nghttp3_conn_shutdown_stream_write (
			http3->conn,
			stream_id
	);

	return 0;
}

static int __rrr_http_application_http3_net_transport_cb_stream_close (
		RRR_NET_TRANSPORT_STREAM_CLOSE_CALLBACK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) arg;

	int ret_tmp;
	if ((ret_tmp = nghttp3_conn_close_stream (
			http3->conn,
			stream_id,
			application_error_reason
	)) != 0) {
		RRR_MSG_0("Error from nghttp3 during stream close in %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		return 1;
	}

	return 0;
}

static int __rrr_http_application_http3_net_transport_cb_stream_ack (
		RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) arg;

	int ret = 0;

	int ret_tmp;

	if ((ret_tmp = nghttp3_conn_add_ack_offset (
			http3->conn,
			stream_id,
			bytes
	)) != 0) {
		RRR_MSG_0("Error from nghttp3 in %s: %s\n", __func__, nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_stream_open (
		RRR_HTTP_APPLICATION_STREAM_OPEN_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) app;

	int ret = 0;

	struct rrr_http_transaction *transaction_tmp = NULL;

	if (flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL &&
	    http3->shutdown_state & RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_LOCAL_STREAMS
	) {
		RRR_DBG_3("HTTP3 stream open %li in %s (local): Local streams are not allowed as connection is in shutdown\n",
			stream_id, __func__);
		ret = RRR_HTTP_BUSY;
		goto out;
	}

	if (!(flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL) &&
	    http3->shutdown_state & RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_REMOTE_STREAMS
	) {
		RRR_DBG_3("HTTP3 stream open %li in %s (remote): Remote streams are not allowed as connection is in shutdown\n",
			stream_id, __func__);
		ret = RRR_HTTP_BUSY;
		goto out;
	}

	RRR_DBG_3("HTTP3 stream open %li in %s is server %i is local %i is bidi %i\n",
		stream_id,
		__func__,
		http3->is_server,
		(flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL) != 0,
		(flags & RRR_NET_TRANSPORT_STREAM_F_BIDI) != 0);

	if (!(flags & RRR_NET_TRANSPORT_STREAM_F_BIDI) && !(flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL)) {
		RRR_BUG("BUG: Remote unidirectional stream encountered in %s\n", __func__);
	}

	if (http3->is_server) {
		if (flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL) {
			assert(!(flags & RRR_NET_TRANSPORT_STREAM_F_BIDI));
			*stream_data = NULL;
			*stream_data_destroy = NULL;
		}
		else {
			assert(stream_open_callback_arg_local == NULL);

			if (rrr_http_transaction_new (
					&transaction_tmp,
					0,
					0,
					0,
					http3->callbacks.unique_id_generator_callback,
					http3->callbacks.callback_arg,
					NULL,
					NULL
			) != 0) {
				RRR_MSG_0("Could not create transaction in %s\n", __func__);
				return NGHTTP3_ERR_CALLBACK_FAILURE;
			}

			rrr_http_transaction_protocol_data_set (
					transaction_tmp,
					rrr_net_transport_ctx_get_transport(handle),
					rrr_net_transport_ctx_get_handle(handle)
			);

			*stream_data = transaction_tmp;
			*stream_data_destroy = rrr_http_transaction_decref_if_not_null_void;
			rrr_http_transaction_incref(transaction_tmp);
		}
	}
	else {
		if ((flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL) != RRR_NET_TRANSPORT_STREAM_F_LOCAL &&
		    (flags & RRR_NET_TRANSPORT_STREAM_F_BIDI) != RRR_NET_TRANSPORT_STREAM_F_BIDI
		) {
			RRR_DBG_3("http3 remote server opened a bidirectional stream, and this client cannot handle this situation. Closing connection.\n");
			rrr_net_transport_handle_ptr_close_with_reason (
					handle,
					RRR_NET_TRANSPORT_CLOSE_REASON_APPLICATION_ERROR,
					NGHTTP3_H3_STREAM_CREATION_ERROR,
					"This client cannot handle bidirectional streams opened by the server"
			);
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		struct rrr_http_transaction *transaction = stream_open_callback_arg_local;

		if (transaction != NULL) {
			assert(flags & RRR_NET_TRANSPORT_STREAM_F_BIDI);
			*stream_data = transaction;
			*stream_data_destroy = rrr_http_transaction_decref_if_not_null_void;
			rrr_http_transaction_incref(transaction);
		}
		else {
			assert(!(flags & RRR_NET_TRANSPORT_STREAM_F_BIDI));
			*stream_data = NULL;
			*stream_data_destroy = NULL;
		}
	}

	*cb_get_message = __rrr_http_application_http3_net_transport_cb_get_message;
	*cb_blocked = __rrr_http_application_http3_net_transport_cb_stream_blocked;
	*cb_shutdown_read = __rrr_http_application_http3_net_transport_cb_stream_shutdown_read;
	*cb_shutdown_write = __rrr_http_application_http3_net_transport_cb_stream_shutdown_write;
	*cb_close = __rrr_http_application_http3_net_transport_cb_stream_close;
	*cb_ack = __rrr_http_application_http3_net_transport_cb_stream_ack;
	*cb_arg = http3;

	out:
	rrr_http_transaction_decref_if_not_null(transaction_tmp);
	return ret;
}

static void  __rrr_http_application_http3_destroy (
		struct rrr_http_application *application
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) application;

	nghttp3_conn_del(http3->conn);
	rrr_free(http3);
}

uint64_t __rrr_http_application_http3_active_transaction_count_get_and_maintain (
		RRR_HTTP_APPLICATION_TRANSACTION_COUNT_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) application;

	(void)(http3);

	uint64_t count = rrr_net_transport_ctx_stream_count(handle);

	// Subtrack QPACK streams
	return count < 6 ? 0 : count - 6;
}

static int __rrr_http_application_http3_request_send_possible (
		RRR_HTTP_APPLICATION_REQUEST_SEND_POSSIBLE_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) application;

	*is_possible = http3->initialized && !(http3->shutdown_state & RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_LOCAL_STREAMS);

	return 0;
}

static int __rrr_http_application_http3_request_send_preliminary_callback (
		enum rrr_http_method method,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		struct rrr_http_part *request_part,
		const struct rrr_nullsafe_str *request,
		void *arg
) {
	struct rrr_http_application_http3_request_send_prepare_callback_data *callback_data = arg;

	(void)(upgrade_mode);
	(void)(protocol_version);
	(void)(request_part);

	int ret = 0;

	if ((ret = rrr_map_item_add_new (callback_data->headers, ":method", RRR_HTTP_METHOD_TO_STR_CONFORMING(method))) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_application_http3_map_add_nullsafe (callback_data->headers, ":path", request)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_request_send_final_callback (
		struct rrr_http_transaction *transaction,
		void *arg
) {
	struct rrr_http_application_http3_request_send_prepare_callback_data *callback_data = arg;
	struct rrr_http_application_http3 *http3 = callback_data->http3;

	(void)(transaction);

	int ret = 0;

	int ret_tmp;
	nghttp3_nv *nv;
	size_t nv_len;

	static const struct nghttp3_data_reader data_reader = {
		__rrr_http_application_http3_read_data_callback
	};

	if ((ret = __rrr_http_application_http3_map_to_nv (&nv, &nv_len, callback_data->headers)) != 0) {
		goto out;
	}

	if ((ret_tmp = nghttp3_conn_submit_request (
			http3->conn,
			callback_data->stream_id,
			nv,
			nv_len,
			&data_reader,
			NULL
	)) != 0) {
		RRR_MSG_0("Failed to submit HTTP3 request: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	rrr_http_transaction_protocol_data_set (
			transaction,
			rrr_net_transport_ctx_get_transport(callback_data->handle),
			rrr_net_transport_ctx_get_handle(callback_data->handle)
	);

	out:
	rrr_free(nv);
	return ret;
}

static int __rrr_http_application_http3_request_send (
		RRR_HTTP_APPLICATION_REQUEST_SEND_ARGS
) {
	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) application;

	*upgraded_app = NULL;

	int ret = 0;

	int64_t stream_id;
	struct rrr_map headers = {0};

	RRR_DBG_3("HTTP3 request submit method %s send data length %" PRIrrr_nullsafe_len "\n",
			RRR_HTTP_METHOD_TO_STR_CONFORMING(transaction->method),
			rrr_nullsafe_str_len(transaction->send_body));

	if ((ret = rrr_net_transport_ctx_stream_open_local (
			&stream_id,
			handle,
			RRR_NET_TRANSPORT_STREAM_F_LOCAL_BIDI,
			transaction
	)) != 0) {
		goto out;
	}

	struct rrr_http_application_http3_request_send_prepare_callback_data callback_data = {
		http3,
		&headers,
		handle,
		stream_id
	};

	if ((ret = rrr_map_item_add_new (&headers, ":authority", host)) != 0) {
		goto out;
	}

	if ((ret = rrr_map_item_add_new (&headers, ":scheme", "https")) != 0) {
		goto out;
	}

	if ((ret = rrr_http_transaction_request_prepare_wrapper (
			transaction,
			upgrade_mode,
			protocol_version,
			user_agent,
			__rrr_http_application_http3_request_send_preliminary_callback,
			__rrr_http_application_http3_header_fields_submit_callback,
			__rrr_http_application_http3_request_send_final_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	rrr_net_transport_ctx_notify_read(handle);

	out:
	rrr_map_clear(&headers);
	return ret;
}

static int __rrr_http_application_http3_transport_ctx_read_stream_callback (
		RRR_NET_TRANSPORT_READ_STREAM_CALLBACK_ARGS
) {
 	struct rrr_http_application_http3 *http3 = arg;

	int ret = 0;

	ssize_t consumed;

	if ((consumed = nghttp3_conn_read_stream (
			http3->conn,
			stream_id,
			(const uint8_t *) buf,
			buflen,
			fin
	)) < 0) {
		RRR_MSG_0("Failed while delivering data to nghttp3 in %s: %s\n",
			__func__, nghttp3_strerror((int) consumed));
		ret = 1;
		goto out;
	}

	if (consumed > 0 && (ret = rrr_net_transport_ctx_stream_consume (
			handle,
			stream_id,
			(size_t) consumed
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_transport_ctx_read_stream (
		uint64_t *bytes_read,
    		struct rrr_http_application_http3 *http3,
		struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	if ((ret = rrr_net_transport_handle_ptr_read_stream (
			bytes_read,
			handle,
			__rrr_http_application_http3_transport_ctx_read_stream_callback,
			http3
	)) != 0) {
		goto out;
	}

	out:
	return ret & ~(RRR_NET_TRANSPORT_READ_INCOMPLETE);
}

static void __rrr_http_application_http3_polite_close (
		RRR_HTTP_APPLICATION_POLITE_CLOSE_ARGS
) {
	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) app;

	RRR_DBG_3("HTTP3 sumbit polite close\n");

	if (nghttp3_conn_submit_shutdown_notice (http3->conn) != 0) {
		RRR_MSG_0("Warning: Failed to submit HTTP3 shutdown notice\n");
		return;
	}

	http3->shutdown_state |= RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_LOCAL_STREAMS;
	http3->shutdown_time = rrr_time_get_64();

	rrr_net_transport_ctx_notify_read (handle);
}

static int __rrr_http_application_http3_nghttp3_cb_stream_acked_data (
		nghttp3_conn *conn,
		int64_t stream_id,
                uint64_t datalen,
		void *conn_user_data,
		void *stream_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	(void)(conn);

	GET_TRANSACTION();

	(void)(transport);
	(void)(transport_handle);

	transaction->send_body_pos += datalen;

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_stream_close (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
    	struct rrr_http_application_http3 *http3 = conn_user_data;

	(void)(conn);

	GET_TRANSACTION();

	(void)(transport);
	(void)(transport_handle);

	RRR_DBG_3("HTTP3 close %li reason %" PRIu64 "\n", stream_id, app_error_code);

	rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_STREAM_CLOSE);

	if (app_error_code != 0) {
		rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_STREAM_ERROR);
	}

	rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_END|RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_END);

	if (__rrr_http_application_http3_stream_read_end (
			http3,
			transaction,
			transport,
			transport_handle,
			stream_id
	) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (http3->is_server) {
		// Free up memory immediately instead of waiting until next tick
		return rrr_net_transport_handle_stream_data_clear (
				http3->transport,
				http3->handle,
				stream_id
		);
	}

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
    	struct rrr_http_application_http3 *http3 = conn_user_data;

	GET_TRANSACTION();

	(void)(http3);
	(void)(conn);

	if (!rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_HEADERS_END)) {
		RRR_DBG_3("Unexpected data received before headers end was set in %s\n", __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_END)) {
		RRR_DBG_3("Unexpected data received after data end was already set in %s\n", __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (rrr_nullsafe_str_new_or_append_raw(&transaction->read_body, data, datalen) != 0) {
		RRR_MSG_0("Failed to store %llu bytes of data in %s\n", (unsigned long long) datalen, __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (rrr_net_transport_handle_stream_consume (
			transport,
			transport_handle,
			stream_id,
			datalen
	) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

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
	RRR_BUG("%s\n", __func__);
}

static int __rrr_http_application_http3_nghttp3_cb_begin_headers (
		nghttp3_conn *conn,
		int64_t stream_id,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(conn_user_data);
	(void)(stream_user_data);

	RRR_DBG_3("HTTP3 begin headers %li\n", stream_id);

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
	struct rrr_http_application_http3 *http3 = conn_user_data;

	GET_TRANSACTION();

	(void)(conn);
	(void)(token);
	(void)(flags);
	(void)(transport);
	(void)(transport_handle);

	struct rrr_http_part *part = http3->is_server
		? transaction->request_part
		: transaction->response_part
	;
	nghttp3_vec name_vec = nghttp3_rcbuf_get_buf(name);
	nghttp3_vec value_vec = nghttp3_rcbuf_get_buf(value);

	if (rrr_http_transaction_stream_flags_has(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_HEADERS_END)) {
		RRR_DBG_3("Unexpected header field received after headers end was already set in %s\n", __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (part->parse_complete) {
		RRR_DBG_3("Unexpected header field received after parsing of part was complete in %s\n", __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (name_vec.len > RRR_LENGTH_MAX) {
		RRR_DBG_3("Name length exceeded maximum in %s\n", __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (value_vec.len > RRR_LENGTH_MAX) {
		RRR_DBG_3("Value length exceeded maximum in %s\n", __func__);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	if (rrr_http_part_header_field_parse_value_raw (
			part,
			(const char *) name_vec.base,
			rrr_length_from_biglength_bug_const(name_vec.len),
			(const char *) value_vec.base,
			rrr_length_from_biglength_bug_const(value_vec.len)
	) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(buf_a, (const char *) name_vec.base, name_vec.len);
	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(buf_b, (const char *) value_vec.base, value_vec.len);

	RRR_DBG_3("Received HTTP3 header %s=%s\n", buf_a, buf_b);

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_end_headers (
		nghttp3_conn *conn,
		int64_t stream_id,
		int fin,
		void *conn_user_data,
		void *stream_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	GET_TRANSACTION();

	(void)(conn);
	(void)(transport);
	(void)(transport_handle);

	RRR_DBG_3("HTTP3 headers complete on stream %li\n", stream_id);

	rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_HEADERS_END);

	if (transaction->read_body != NULL)
		rrr_nullsafe_str_clear(transaction->read_body);

	if (fin) {
		rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_END);

		RRR_DBG_3("HTTP3 reading complete after headers on stream %li.\n", stream_id);
	}

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_stop_sending (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	/* nghttp3 no longer wishes to receive data, stop reading */

	GET_TRANSACTION();

	(void)(conn);

	RRR_DBG_3("HTTP3 issue shutdown read on stream %li\n", stream_id);

	if (rrr_net_transport_handle_stream_shutdown_read (
			transport,
			transport_handle,
			stream_id,
			app_error_code
	) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_reset_stream (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	/* nghttp3 wishes to issue stream reset */

	GET_TRANSACTION();

	(void)(conn);

	RRR_DBG_3("HTTP3 issue reset on stream %li\n", stream_id);

	if (rrr_net_transport_handle_stream_shutdown_write (
			transport,
			transport_handle,
			stream_id,
			app_error_code
	) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_shutdown (
		nghttp3_conn *conn,
		int64_t stream_id,
		void *conn_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	(void)(conn);

	if (http3->shutdown_time)
		return 0;

	if (stream_id == NGHTTP3_SHUTDOWN_NOTICE_STREAM_ID ||
	    stream_id == NGHTTP3_SHUTDOWN_NOTICE_PUSH_ID
	) {
		RRR_DBG_3("HTTP3 shutdown from remote\n");
	}
	else {
		RRR_DBG_3("HTTP3 shutdown. Stream IDs from us greater than or equal to %li will not be processed by remote.\n", stream_id);
	}

	http3->shutdown_state |= RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_LOCAL_STREAMS;
	http3->shutdown_time = rrr_time_get_64();

	return 0;
}

static int __rrr_http_application_http3_nghttp3_cb_end_stream (
		nghttp3_conn *conn,
		int64_t stream_id,
		void *conn_user_data,
		void *stream_user_data
) {
	struct rrr_http_application_http3 *http3 = conn_user_data;

	GET_TRANSACTION();

	(void)(conn);

	RRR_DBG_3("HTTP3 end stream %li, reading complete.\n", stream_id);

	rrr_http_transaction_stream_flags_add(transaction, RRR_HTTP_DATA_RECEIVE_FLAG_IS_DATA_END);

	if (__rrr_http_application_http3_stream_read_end (
			http3,
			transaction,
			transport,
			transport_handle,
			stream_id
	) != 0) {
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

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

struct rrr_http_application_http3_tick_get_async_response_stream_callback_data {
	struct rrr_http_application_http3 *http3;
	unsigned int response_needed_count;
};

static int __rrr_http_application_http3_tick_get_async_response_stream_callback (
		int64_t stream_id,
		void *stream_data,
		void *arg
) {
	struct rrr_http_transaction *transaction = stream_data;
	struct rrr_http_application_http3_tick_get_async_response_stream_callback_data *callback_data = arg;
	struct rrr_http_application_http3 *http3 = callback_data->http3;

	int ret = 0;

	if (transaction == NULL || !transaction->need_response) {
		goto out;
	}

	callback_data->response_needed_count++;

	if ((ret = http3->callbacks.async_response_get_callback(transaction, http3->callbacks.callback_arg)) != 0) {
		ret &= ~(RRR_HTTP_NO_RESULT);
		goto out;
	}

	transaction->need_response = 0;

	if ((ret = __rrr_http_application_http3_response_submit (
			http3,
			transaction,
			stream_id
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_tick_process_shutdown (
		struct rrr_http_application_http3 *http3
) {
	int ret = 0;

	uint64_t diff = rrr_time_get_64() - http3->shutdown_time;

	// In case of delays, always check both 1x and 2x timeout

	if ( (diff > RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_PROGRESSION_INTERVAL_US * 1) &&
	    !(http3->shutdown_state & RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_REMOTE_STREAMS)
	) {
		RRR_DBG_3("HTTP3 first shutdown progression interval reached, blocking new remote streams.\n");

		http3->shutdown_state |= RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_NO_NEW_REMOTE_STREAMS;
	}

	if (diff > RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_PROGRESSION_INTERVAL_US * 2) {
		if (!(http3->shutdown_state & RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_FINAL)) {
			RRR_DBG_3("HTTP3 second shutdown progression interval reached, shutting down.\n");

			if (nghttp3_conn_shutdown (http3->conn) != 0) {
				RRR_MSG_0("Failed to shutdown http3 in %s\n", __func__);
				ret = RRR_HTTP_HARD_ERROR;
				goto out;
			}

			http3->shutdown_state |= RRR_HTTP_APPLICATION_HTTP3_SHUTDOWN_STATE_FINAL;
		}
		else if (http3->is_server) {
			if (nghttp3_conn_is_drained(http3->conn)) {
				RRR_DBG_3("HTTP3 server all streams are drained after shutdown, closing connection.\n");
				ret = RRR_HTTP_DONE;
				goto out;
			}
			else {
				RRR_DBG_3("HTTP3 server waiting for all streams to drain before shutdown.\n");
			}
		}
		else {
			RRR_DBG_3("HTTP3 client closing connection.\n");
			ret = RRR_HTTP_DONE;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_http_application_http3_tick (
		RRR_HTTP_APPLICATION_TICK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) app;

	(void)(upgraded_app);
	(void)(read_max_size);

	*received_bytes = 0;

	int ret = 0;

	if (!http3->initialized) {
		if ((ret = __rrr_http_application_http3_initialize(http3, handle)) != 0) {
			goto out;
		}
		http3->initialized = 1;
	}

	if (http3->shutdown_time != 0) {
		if ((ret = __rrr_http_application_http3_tick_process_shutdown(http3)) != 0) {
			goto out;
		}
		rrr_net_transport_ctx_notify_read_timed(handle, 50 * 1000 /* 50 ms */);
	}

	http3->rules = rules;

	{
		struct rrr_http_application_http3_tick_get_async_response_stream_callback_data callback_data = {
			http3,
			0
		};
		if ((ret = rrr_net_transport_ctx_streams_iterate (
				handle,
				__rrr_http_application_http3_tick_get_async_response_stream_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
		if (callback_data.response_needed_count > 0) {
			RRR_DBG_3("HTTP3 notify read due to responses needed\n");
			rrr_net_transport_ctx_notify_read(handle);
		}
	}

	uint64_t bytes_read = 0;
	if ((ret =  __rrr_http_application_http3_transport_ctx_read_stream (
			&bytes_read,
			http3,
			handle
	)) != 0) {
		goto out;
	}

	*received_bytes = bytes_read;

	out:
	return ret;
}

static int __rrr_http_application_http3_need_tick (
		RRR_HTTP_APPLICATION_NEED_TICK_ARGS
) {
    	struct rrr_http_application_http3 *http3 = (struct rrr_http_application_http3 *) app;
	return !http3->initialized;
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
	__rrr_http_application_http3_nghttp3_cb_stream_acked_data,
	__rrr_http_application_http3_nghttp3_cb_stream_close,
	__rrr_http_application_http3_nghttp3_cb_recv_data,
	__rrr_http_application_http3_nghttp3_cb_deferred_consume,
	__rrr_http_application_http3_nghttp3_cb_begin_headers,
	__rrr_http_application_http3_nghttp3_cb_recv_header,
	__rrr_http_application_http3_nghttp3_cb_end_headers,
	NULL, /* begin_trailers */
	NULL, /* recv_trailer */
	NULL, /* end_trailers */
	__rrr_http_application_http3_nghttp3_cb_stop_sending,
	__rrr_http_application_http3_nghttp3_cb_end_stream,
	__rrr_http_application_http3_nghttp3_cb_reset_stream,
	__rrr_http_application_http3_nghttp3_cb_shutdown,
	NULL, /* recv_settings */
};

static const nghttp3_mem rrr_http_application_http3_nghttp3_mem = {
	.malloc = __rrr_http_application_http3_cb_malloc,
	.free= __rrr_http_application_http3_cb_free,
	.calloc = __rrr_http_application_http3_cb_calloc,
	.realloc = __rrr_http_application_http3_cb_realloc
};

static void __rrr_http_application_http3_vprintf (const char *format, va_list args) {
	vprintf(format, args);
}

int rrr_http_application_http3_new (
		struct rrr_http_application **result,
		int is_server,
		const struct rrr_http_application_callbacks *callbacks
) {
	int ret = 0;

	struct rrr_http_application_http3 *http3;
	nghttp3_settings settings = {0};

	if ((http3 = rrr_allocate_zero(sizeof(*http3))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	nghttp3_settings_default(&settings);

	if (is_server) {
		if (nghttp3_conn_server_new (
				&http3->conn,
				&rrr_http_application_http3_nghttp3_callbacks,
				&settings,
				&rrr_http_application_http3_nghttp3_mem,
				http3
		) != 0) {
			RRR_MSG_0("Failed to create http3 client in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}
	else {
		if (nghttp3_conn_client_new (
				&http3->conn,
				&rrr_http_application_http3_nghttp3_callbacks,
				&settings,
				&rrr_http_application_http3_nghttp3_mem,
				http3
		) != 0) {
			RRR_MSG_0("Failed to create http3 client in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

#ifdef RRR_HTTP_APPLICATION_HTTP3_NGHTTP3_DEBUG
	nghttp3_set_debug_vprintf_callback(__rrr_http_application_http3_vprintf);
#else
	(void)(__rrr_http_application_http3_vprintf);
#endif

	http3->constants = &rrr_http_application_http3_constants;
	http3->callbacks = *callbacks;
	http3->is_server = is_server;

	*result = (struct rrr_http_application *) http3;

	RRR_DBG_3("http3 %p new %s application\n", http3, is_server ? "server" : "client");

	goto out;
//	out_free:
//		rrr_free(http3);
	out:
		return ret;
}
