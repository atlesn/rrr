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

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include <openssl/err.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <assert.h>

#include "../log.h"
#include "../allocator.h"

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_quic.h"
#include "net_transport_tls_common.h"
#include "net_transport_openssl_common.h"
#include "net_transport_common.h"

#include "../allocator.h"
#include "../rrr_openssl.h"
#include "../rrr_strerror.h"
#include "../random.h"
#include "../ip/ip_util.h"
#include "../ip/ip_accept_data.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"

#define RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH 18
#define RRR_NET_TRANSPORT_QUIC_KEEPALIVE_S 10
#define RRR_NET_TRANSPORT_QUIC_CIPHERS \
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define RRR_NET_TRANSPORT_QUIC_GROUPS \
    "P-256:X25519:P-384:P-521"

// Enable printf logging in ngtcp2 library
//#define RRR_NET_TRANSPORT_QUIC_NGTCP2_DEBUG 1

struct rrr_net_transport_quic_recv_buf {
	rrr_biglength rpos;
	struct rrr_nullsafe_str *str;
};

struct rrr_net_transport_quic_stream {
	RRR_LL_NODE(struct rrr_net_transport_quic_stream);
	int64_t stream_id;
	int flags;
	struct rrr_net_transport_quic_recv_buf recv_buf;
	int (*cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS);
	int (*cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS);
	int (*cb_ack)(RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS);
	void *cb_arg;
};

struct rrr_net_transport_quic_stream_collection {
	RRR_LL_HEAD(struct rrr_net_transport_quic_stream);
};

struct rrr_net_transport_quic_path {
	struct sockaddr_storage addr_remote;
	socklen_t addr_remote_len;
	struct sockaddr_storage addr_local;
	socklen_t addr_local_len;
};

enum rrr_net_transport_quic_migration_mode {
	RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_NONE,
	RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_LOCAL_REBIND,
	RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_IMMEDIATE,
	RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_VALIDATION
};

struct rrr_net_transport_quic_ctx {
	SSL *ssl;

	struct rrr_net_transport_tls *transport_tls;

	rrr_net_transport_handle connected_handle;
	int fd;

	int initial_received;

	ngtcp2_conn *conn;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_path path;
	ngtcp2_connection_close_error last_error;

	struct rrr_net_transport_quic_stream_collection streams;
	struct rrr_net_transport_quic_path path_active;
	struct rrr_net_transport_quic_path path_migration;
	enum rrr_net_transport_quic_migration_mode path_migration_mode;

	char *alpn_selected_proto;
};

struct rrr_net_transport_quic_handle_data {
	// Used by server listen handle and client handle
	struct rrr_net_transport_tls_data *tls_data;

	// Used by server connected handle and client handle
	struct rrr_net_transport_quic_ctx *ctx;
};

void rrr_net_transport_quic_path_to_ngtcp2_path (
		ngtcp2_path *target,
		const struct rrr_net_transport_quic_path *source
) {
	target->local.addr = (ngtcp2_sockaddr *) &source->addr_local;
	target->local.addrlen = source->addr_local_len;
	target->remote.addr = (ngtcp2_sockaddr *) &source->addr_remote;
	target->remote.addrlen = source->addr_remote_len;
	target->user_data = NULL;
}

static void *__rrr_net_transport_quic_cb_malloc (size_t size, void *user_data) {
	(void)(user_data);
	return rrr_allocate(size);
}

static void __rrr_net_transport_quic_cb_free (void *ptr, void *user_data) {
	(void)(user_data);
	rrr_free(ptr);
}

static void *__rrr_net_transport_quic_cb_calloc (size_t nmemb, size_t size, void *user_data) {
	(void)(user_data);
	return rrr_callocate(nmemb, size);
}

static void *__rrr_net_transport_quic_cb_realloc (void *ptr, size_t size, void *user_data) {
	(void)(user_data);
	return rrr_reallocate(ptr, size);
}

static const ngtcp2_mem rrr_net_transport_quic_ngtcp2_mem = {
	.malloc = __rrr_net_transport_quic_cb_malloc,
	.free= __rrr_net_transport_quic_cb_free,
	.calloc = __rrr_net_transport_quic_cb_calloc,
	.realloc = __rrr_net_transport_quic_cb_realloc
};

static ngtcp2_conn *__rrr_net_transport_quic_cb_get_conn (
		ngtcp2_crypto_conn_ref *conn_ref
) {
	struct rrr_net_transport_quic_ctx *ctx = conn_ref->user_data;
	return ctx->conn;
}

static void __rrr_net_transport_quic_connection_id_to_ngtcp2_cid (
		ngtcp2_cid *target,
		const struct rrr_net_transport_connection_id *source
) {
	assert(sizeof(target->data) >= sizeof(source->data) && sizeof(target->data) >= source->length);
	memcpy(target->data, source->data, source->length);
	target->datalen = source->length;
}

static void __rrr_net_transport_quic_ngtcp2_cid_to_connection_id (
		struct rrr_net_transport_connection_id *target,
		const ngtcp2_cid *source
) {
	assert(sizeof(target->data) >= sizeof(source->data) && sizeof(target->data) >= source->datalen);
	memcpy(target->data, source->data, source->datalen);
	target->length = source->datalen;
}

static void __rrr_net_transport_quic_ctx_post_connect_patch (
		struct rrr_net_transport_quic_ctx *ctx,
		rrr_net_transport_handle handle
) {
	ctx->connected_handle = handle;
}

static void __rrr_net_transport_quic_stream_destroy (
		struct rrr_net_transport_quic_stream *stream
) {
	rrr_nullsafe_str_destroy_if_not_null(&stream->recv_buf.str);
	rrr_free(stream);
}

static int __rrr_net_transport_quic_stream_new (
		struct rrr_net_transport_quic_stream **target,
		int64_t stream_id,
		int flags
) {
	int ret = 0;

	struct rrr_net_transport_quic_stream *stream = NULL;

	*target = NULL;

	if ((stream = rrr_allocate_zero (sizeof (*stream))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	stream->stream_id = stream_id;
	stream->flags = flags;
	*target = stream;

	out:
	return ret;
}

static int __rrr_net_transport_quic_ctx_stream_open (
		struct rrr_net_transport_quic_ctx *ctx,
		int64_t stream_id,
		int flags
) {
	struct rrr_net_transport_tls *transport = ctx->transport_tls;
	const char *local = flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL ? "local" : "remote";
	const char *bidi = flags & RRR_NET_TRANSPORT_STREAM_F_BIDI ? "bidi" : "uni";

	int ret = 0;

	struct rrr_net_transport_quic_stream *stream = NULL;

	RRR_DBG_7("net transport quic h %i new %s %s stream %" PRIi64 "\n",
		ctx->connected_handle, local, bidi, stream_id);

	if ((ret = __rrr_net_transport_quic_stream_new (
			&stream,
			stream_id,
			flags
	)) != 0) {
		goto out;
	}

	if (transport->stream_open_callback (
			&stream->cb_get_message,
			&stream->cb_blocked,
			&stream->cb_ack,
			&stream->cb_arg,
			ctx->connected_handle,
			stream->stream_id,
			stream->flags,
			transport->stream_open_callback_arg
	) != 0) {
		ret = 1;
		goto out_destroy;
	}

	RRR_LL_PUSH(&ctx->streams, stream);

	goto out;
	out_destroy:
		__rrr_net_transport_quic_stream_destroy(stream);
	out:
		return ret;
}

static void __rrr_net_transport_quic_ctx_stream_close (
		struct rrr_net_transport_quic_ctx *ctx,
		int64_t stream_id
) {
	RRR_LL_ITERATE_BEGIN(&ctx->streams, struct rrr_net_transport_quic_stream);
		if (node->stream_id == stream_id) {
			// Stream must be closed by read loop after all data
			// is delivered to application.
			node->flags |= RRR_NET_TRANSPORT_STREAM_F_CLOSING;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();
}

static int __rrr_net_transport_quic_ctx_stream_recv (
		struct rrr_net_transport_quic_ctx *ctx,
		int64_t stream_id,
		const uint8_t *buf,
		size_t buflen
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&ctx->streams, struct rrr_net_transport_quic_stream);
		if (node->stream_id == stream_id) {
			ret = rrr_nullsafe_str_new_or_append_raw(&node->recv_buf.str, buf, buflen);
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static void __rrr_net_transport_quic_ctx_destroy (
		struct rrr_net_transport_quic_ctx *ctx
) {
	SSL_free(ctx->ssl);
	ngtcp2_conn_del(ctx->conn);
	RRR_LL_DESTROY(&ctx->streams, struct rrr_net_transport_quic_stream, __rrr_net_transport_quic_stream_destroy(node));
	rrr_free(ctx);
}

static int __rrr_net_transport_quic_handle_data_new (
		struct rrr_net_transport_quic_handle_data **result
) {
	struct rrr_net_transport_quic_handle_data *handle_data;

	if ((handle_data = rrr_allocate_zero(sizeof(*handle_data))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		return 1;
	}

	*result = handle_data;

	return 0;
}

static void __rrr_net_transport_quic_handle_data_destroy (
		struct rrr_net_transport_quic_handle_data *handle_data
) {
	if (handle_data->tls_data)
		rrr_net_transport_openssl_common_ssl_data_destroy(handle_data->tls_data);
	if (handle_data->ctx)
		__rrr_net_transport_quic_ctx_destroy(handle_data->ctx);
	rrr_free(handle_data);
}

static int __rrr_net_transport_quic_ngtcp2_cb_client_initial (ngtcp2_conn *conn, void *user_data) {
	int ret = ngtcp2_crypto_client_initial_cb(conn, user_data);
	printf("Initial %i\n", ret);
	return ret;
}

static int __rrr_net_transport_quic_ngtcp2_cb_handshake_complete (ngtcp2_conn *conn, void *user_data) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	RRR_DBG_7("net transport quic fd %i h %i handshake complete\n", ctx->fd, ctx->connected_handle);

	ngtcp2_conn_set_keep_alive_timeout(conn, (ngtcp2_duration) RRR_NET_TRANSPORT_QUIC_KEEPALIVE_S * 1000 * 1000 * 1000);

	// Add any token ngtcp2_crypto_generate_regular_token, ngtcp2_conn_submit_new_token here
	// NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN

	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_receive_stream_data (
		ngtcp2_conn *conn,
		uint32_t flags,
		int64_t stream_id,
		uint64_t offset,
		const uint8_t *buf,
		size_t buflen,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(offset);
	(void)(stream_user_data);

	if (__rrr_net_transport_quic_ctx_stream_recv(ctx, stream_id, buf, buflen) != 0) {
		RRR_MSG_0("net transport quic fd %i h %i failed to store received stream data (%llu bytes)\n",
			ctx->fd, ctx->connected_handle, (long long unsigned) buflen);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	RRR_DBG_7("net transport quic fd %i h %i stream id %" PRIi64 " recv %llu fin %i\n",
		ctx->fd, ctx->connected_handle, stream_id, (unsigned long long) buflen, (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);

	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, buflen);
	ngtcp2_conn_extend_max_offset(conn, buflen);

	rrr_net_transport_handle_notify_read((struct rrr_net_transport *) ctx->transport_tls, ctx->connected_handle);

	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_stream_open (
		ngtcp2_conn *conn,
		int64_t stream_id,
		void *user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);

	if (__rrr_net_transport_quic_ctx_stream_open (
			ctx,
			stream_id,
			ngtcp2_is_bidi_stream(stream_id) ? RRR_NET_TRANSPORT_STREAM_F_BIDI : 0
	) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_acked_stream_data_offset (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t offset,
		uint64_t datalen,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);
	(void)(stream_user_data);

	RRR_DBG_7("net transport quic fd %i h %i remote ACK stream %" PRIi64 " offset %" PRIu64 " length %" PRIu64 "\n",
		ctx->fd, ctx->connected_handle, stream_id, offset, datalen);

	// nghttp3_conn_add_ack_offset(m stream_id, datalen);
	// NGTCP2_ERR_CALLBACK_FAILURE / ngtcp2_conection_close_error_set_application_error
	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_stream_close (
		ngtcp2_conn *conn,
		uint32_t flags,
		int64_t stream_id,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);
	(void)(app_error_code);
	(void)(stream_user_data);

	if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
		// app_error_close = NGHTTP3_H3_NO_ERROR;
	}

	RRR_DBG_7("net transport quic fd %i h %i close stream %" PRIi64 " (after data is delivered to application)\n",
		ctx->fd, ctx->connected_handle, stream_id);

	__rrr_net_transport_quic_ctx_stream_close(ctx, stream_id);

	return 0;
}

static void __rrr_net_transport_quic_ngtcp2_cb_random (
		uint8_t *dest,
		size_t destlen,
		const ngtcp2_rand_ctx *rand_ctx
) {
	(void)(rand_ctx);
	rrr_random_bytes(dest, destlen);
}

static int __rrr_net_transport_quic_ngtcp2_cb_get_new_connection_id (
		ngtcp2_conn *conn,
		ngtcp2_cid *cid,
		uint8_t *token,
		size_t cidlen,
		void *user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	// We rely on a fixed length when decoding short header packets. ngtcp2
	// library is expected to request a cidlen with the same value as the
	// first cid generated when the connection was initially accepted.
	assert(cidlen == RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH);

	(void)(conn);

	int ret = NGTCP2_ERR_CALLBACK_FAILURE;

	struct rrr_net_transport_connection_id cid_;

	assert(ctx->connected_handle > 0);

	for (int max = 500; max > 0; max--) {
		cid->datalen = cidlen;
		rrr_random_bytes(&cid->data, cidlen);
		rrr_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

		__rrr_net_transport_quic_ngtcp2_cid_to_connection_id(&cid_, cid);

		int ret_tmp;
		if ((ret_tmp = rrr_net_transport_handle_cid_push (
				(struct rrr_net_transport *) ctx->transport_tls,
				ctx->connected_handle,
				&cid_
		)) == 0) {
			char buf[64];
			rrr_net_transport_connection_id_to_str(buf, sizeof(buf), &cid_);
			RRR_DBG_7("net transport quic fd %i h %i new cid %s\n",
				ctx->fd, ctx->connected_handle, buf);

			ret = 0;

			break;
		}
		else {
			if (ret_tmp == RRR_NET_TRANSPORT_READ_BUSY) {
				// OK, try again with another CID
			}
			else {
				RRR_MSG_0("Error while pushing cid to handle in %s\n", __func__);
				break;
			}
		}
	}

	if (ret != 0) {
		RRR_MSG_0("Failed to generate unique cid in %s after multiple attempts\n", __func__);
	}

	return ret;
}

static int __rrr_net_transport_quic_ngtcp2_cb_remove_connection_id (
		ngtcp2_conn *conn,
		const ngtcp2_cid *cid,
		void *user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);

	assert(ctx->connected_handle > 0);

	struct rrr_net_transport_connection_id cid_;
	__rrr_net_transport_quic_ngtcp2_cid_to_connection_id(&cid_, cid);

	{
		char buf[64];
		rrr_net_transport_connection_id_to_str(buf, sizeof(buf), &cid_);
		RRR_DBG_7("net transport quic fd %i h %i remove cid %s\n",
			ctx->fd, ctx->connected_handle, buf);
	}

	rrr_net_transport_handle_cid_remove ((struct rrr_net_transport *) ctx->transport_tls, ctx->connected_handle, &cid_);

	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_stream_reset (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t final_size,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	RRR_DBG_7("net transport quic fd %i h %i stream %" PRIi64 " reset final size %" PRIu64 "\n",
		ctx->fd, ctx->connected_handle, stream_id, final_size);

	// NGTCP2_ERR_CALLBACK_FAILURE - nghttp3_conn_shutdown_stream_read
	
	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_extend_max_stream_data (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t max_data,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);
	(void)(stream_user_data);

	RRR_DBG_7("net transport quic fd %i h %i stream %" PRIi64 " extend max stream data size %" PRIu64 "\n",
		ctx->fd, ctx->connected_handle, stream_id, max_data);

	RRR_LL_ITERATE_BEGIN(&ctx->streams, struct rrr_net_transport_quic_stream);
		if (stream_id == node->stream_id) {
			if (node->cb_blocked != NULL && node->cb_blocked(stream_id, 0, node->cb_arg) != 0) {
				// ngtcp2_connection_close_error_set_application_error();
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
		}
	RRR_LL_ITERATE_END();

	return 0;
}

static int __rrr_net_transport_quic_ngtcp2_cb_stream_stop_sending (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);
	(void)(app_error_code);
	(void)(stream_user_data);

	RRR_DBG_7("net transport quic fd %i h %i stream %" PRIi64 " stop sending\n",
		ctx->fd, ctx->connected_handle, stream_id);

	// NGTCP2_ERR_CALLBACK_FAILURE - nghttp3_conn_shutdown_stream_read

	return 0;
}

static void __rrr_net_transport_quic_cb_printf (
		void *user_data,
		const char *format,
		...
) {
	(void)(user_data);
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}

static int __rrr_net_transport_quic_ctx_new (
		struct rrr_net_transport_quic_ctx **target,
    		struct rrr_net_transport_connection_id_pair *connection_ids_new,
		struct rrr_net_transport_tls *transport_tls,
		struct rrr_net_transport_tls_data *server_tls,
		struct rrr_net_transport_tls_data *client_tls,
		int fd,
    		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const uint32_t client_chosen_version,
		const char *remote_hostname,
		const struct sockaddr *addr_remote,
		socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		socklen_t addr_local_len
) {
	int ret = 0;

	*target = NULL;

	int ret_tmp;
	struct rrr_net_transport_quic_ctx *ctx = NULL;
	ngtcp2_cid scid, dcid;
	ngtcp2_settings settings;
	ngtcp2_transport_params transport_params;

	char buf_remote_addr[128];
	char buf_local_addr[128];

	if ((ctx = rrr_allocate_zero(sizeof(*ctx))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	assert(sizeof(ctx->path_active.addr_remote) >= addr_remote_len);
	memcpy(&ctx->path_active.addr_remote, addr_remote, addr_remote_len);
	ctx->path_active.addr_remote_len = addr_remote_len;

	assert(sizeof(ctx->path_active.addr_local) >= addr_local_len);
	memcpy(&ctx->path_active.addr_local, addr_local, addr_local_len);
	ctx->path_active.addr_local_len = addr_local_len;

	ctx->transport_tls = transport_tls;
	ctx->fd = fd;

	const ngtcp2_path path = {
		.local = {
			(struct sockaddr *) &ctx->path_active.addr_local,
			ctx->path_active.addr_local_len
		},
		.remote = {
			(struct sockaddr *) &ctx->path_active.addr_remote,
			ctx->path_active.addr_remote_len
		},
		.user_data = NULL
	};

	// For debug messages
	rrr_ip_to_str(buf_remote_addr, sizeof(buf_remote_addr), (const struct sockaddr *) path.remote.addr, path.remote.addrlen);
	rrr_ip_to_str(buf_local_addr, sizeof(buf_local_addr), (const struct sockaddr *) path.local.addr, path.local.addrlen);

	// New source connection ID is randomly generated
	rrr_random_bytes(&scid.data, RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH);
	scid.datalen = RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH;

	// Set ngtcp2 settings
	ngtcp2_settings_default(&settings);

#ifdef RRR_NET_TRANSPORT_QUIC_NGTCP2_DEBUG
	settings.log_printf = __rrr_net_transport_quic_cb_printf;
#else
	(void)(__rrr_net_transport_quic_cb_printf);
#endif

	// Set ngtcp2 transport parameters
	ngtcp2_transport_params_default(&transport_params);
	transport_params.initial_max_stream_data_bidi_local = 128 * 1024;
	transport_params.initial_max_stream_data_bidi_remote = 128 * 1024;
	transport_params.initial_max_stream_data_uni = 128 * 1024;
	transport_params.initial_max_data = 1024 * 1024;
	transport_params.initial_max_streams_bidi = 100;
	transport_params.initial_max_streams_uni = 3;

	if (rrr_time_get_64_nano(&settings.initial_ts, NGTCP2_SECONDS) != 0) {
		goto out_free;
	}

	if (server_tls) {
		RRR_DBG_7("net transport quic fd %i new server ctx src %s\n",
				fd, buf_remote_addr);

		// Store new and original connection ID as expected future destination from client
		__rrr_net_transport_quic_ngtcp2_cid_to_connection_id(&connection_ids_new->a, &scid);
		connection_ids_new->b = connection_ids->dst;

		// New destination connection ID is source connection ID from client
		__rrr_net_transport_quic_connection_id_to_ngtcp2_cid(&dcid, &connection_ids->src);

		// TODO : handle retry
		__rrr_net_transport_quic_connection_id_to_ngtcp2_cid(&transport_params.original_dcid, &connection_ids->dst);

		static const ngtcp2_callbacks callbacks = {
			NULL, /* client_initial */
			ngtcp2_crypto_recv_client_initial_cb,
			ngtcp2_crypto_recv_crypto_data_cb,
			__rrr_net_transport_quic_ngtcp2_cb_handshake_complete,
			NULL, /* recv_version_negotiation */
			ngtcp2_crypto_encrypt_cb,
			ngtcp2_crypto_decrypt_cb,
			ngtcp2_crypto_hp_mask_cb,
			__rrr_net_transport_quic_ngtcp2_cb_receive_stream_data,
			__rrr_net_transport_quic_ngtcp2_cb_acked_stream_data_offset,
			__rrr_net_transport_quic_ngtcp2_cb_stream_open,
			__rrr_net_transport_quic_ngtcp2_cb_stream_close,
			NULL, /* recv_stateless_reset */
			NULL, /* recv_retry */
			NULL, /* extend_max_local_streams_uni */
			NULL, /* extend_max_local_streams_uni */
			__rrr_net_transport_quic_ngtcp2_cb_random,
			__rrr_net_transport_quic_ngtcp2_cb_get_new_connection_id,
			__rrr_net_transport_quic_ngtcp2_cb_remove_connection_id,
			ngtcp2_crypto_update_key_cb,
			NULL, /* path_validation */
			NULL, /* select_preferred_addr */
			__rrr_net_transport_quic_ngtcp2_cb_stream_reset,
			NULL, /* extend_max_remote_streams_bidi */
			NULL, /* extend_max_remote_streams_uni */
			__rrr_net_transport_quic_ngtcp2_cb_extend_max_stream_data,
			NULL, /* dcid_status */
			NULL, /* handshake_confirmed */
			NULL, /* recv_new_token */
			ngtcp2_crypto_delete_crypto_aead_ctx_cb,
			ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
			NULL, /* recv_datagram */
			NULL, /* ack_datagram */
			NULL, /* lost_datagram */
			ngtcp2_crypto_get_path_challenge_data_cb,
			__rrr_net_transport_quic_ngtcp2_cb_stream_stop_sending,
			ngtcp2_crypto_version_negotiation_cb,
			NULL, /* recv_rx_key */
			NULL  /* recv_tx_key */
		};

		if ((ret_tmp = ngtcp2_conn_server_new (
				&ctx->conn,
				&dcid,
				&scid,
				&path,
				client_chosen_version,
				&callbacks,
				&settings,
				&transport_params,
				&rrr_net_transport_quic_ngtcp2_mem,
				ctx
		)) != 0) {
			RRR_MSG_0("Could not create server ngtcp2 connection in %s: %s\n",
				__func__, ngtcp2_strerror(ret_tmp));
			ret = 1;
			goto out_free;
		}

		if ((ctx->ssl = SSL_dup(server_tls->ssl)) == NULL) {
			RRR_SSL_ERR("Could not allocate SSL in QUIC");
			ret = 1;
			goto out_destroy_conn;
		}

		SSL_set_accept_state(ctx->ssl);
	}
	else {
		// New destination connection ID is randomly generated
		rrr_random_bytes(&dcid.data, RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH);
		dcid.datalen = RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH;

		// Store new source connection ID as expected future destination from server
		__rrr_net_transport_quic_ngtcp2_cid_to_connection_id(&connection_ids_new->a, &scid);

		// Second CID slot not used
		connection_ids_new->b.length = 0;

		RRR_DBG_7("net transport quic fd %i new client ctx src %s dst %s\n",
				fd, buf_local_addr, buf_remote_addr);

		static const ngtcp2_callbacks callbacks = {
			__rrr_net_transport_quic_ngtcp2_cb_client_initial,
			NULL, /* recv_client_initial */
			ngtcp2_crypto_recv_crypto_data_cb,
			__rrr_net_transport_quic_ngtcp2_cb_handshake_complete,
			NULL, /* recv_version_negotiation */
			ngtcp2_crypto_encrypt_cb,
			ngtcp2_crypto_decrypt_cb,
			ngtcp2_crypto_hp_mask_cb,
			__rrr_net_transport_quic_ngtcp2_cb_receive_stream_data,
			__rrr_net_transport_quic_ngtcp2_cb_acked_stream_data_offset,
			__rrr_net_transport_quic_ngtcp2_cb_stream_open,
			__rrr_net_transport_quic_ngtcp2_cb_stream_close,
			NULL, /* recv_stateless_reset */
			ngtcp2_crypto_recv_retry_cb,
			NULL, /* extend_max_local_streams_bidi */
			NULL, /* extend_max_local_streams_uni */
			__rrr_net_transport_quic_ngtcp2_cb_random,
			__rrr_net_transport_quic_ngtcp2_cb_get_new_connection_id,
			__rrr_net_transport_quic_ngtcp2_cb_remove_connection_id,
			ngtcp2_crypto_update_key_cb,
			NULL, /* path_validation */
			NULL, /* select_preferred_addr */
			__rrr_net_transport_quic_ngtcp2_cb_stream_reset,
			NULL, /* extend_max_remote_streams_bidi */
			NULL, /* extend_max_remote_streams_uni */
			__rrr_net_transport_quic_ngtcp2_cb_extend_max_stream_data,
			NULL, /* dcid_status */
			NULL, /* handshake_confirmed */
			NULL, /* recv_new_token */
			ngtcp2_crypto_delete_crypto_aead_ctx_cb,
			ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
			NULL, /* recv_datagram */
			NULL, /* ack_datagram */
			NULL, /* lost_datagram */
			ngtcp2_crypto_get_path_challenge_data_cb,
			__rrr_net_transport_quic_ngtcp2_cb_stream_stop_sending,
			ngtcp2_crypto_version_negotiation_cb,
			NULL, /* recv_rx_key */
			NULL  /* recv_tx_key */
		};

		if ((ret_tmp = ngtcp2_conn_client_new (
				&ctx->conn,
				&dcid,
				&scid,
				&path,
				client_chosen_version,
				&callbacks,
				&settings,
				&transport_params,
				&rrr_net_transport_quic_ngtcp2_mem,
				ctx
		)) != 0) {
			RRR_MSG_0("Could not create client ngtcp2 connection in %s: %s\n",
				__func__, ngtcp2_strerror(ret_tmp));
			ret = 1;
			goto out_free;
		}

		ctx->ssl = client_tls->ssl;

		SSL_up_ref(ctx->ssl);
		SSL_set_connect_state(ctx->ssl);
		SSL_set_tlsext_host_name(ctx->ssl, remote_hostname);
	}

	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->ssl);
	ngtcp2_connection_close_error_default(&ctx->last_error);

	ctx->conn_ref.user_data = ctx;
	ctx->conn_ref.get_conn = __rrr_net_transport_quic_cb_get_conn;

	// Additional parameters must be set by __rrr_net_transport_quic_ctx_post_connect_patch
	// after the transport handle is known.

	SSL_set_app_data(ctx->ssl, &ctx->conn_ref);

	*target = ctx;

	goto out;
	out_destroy_conn:
		ngtcp2_conn_del(ctx->conn);
	out_free:
		rrr_free(ctx);
	out:
		return ret;
}

static int __rrr_net_transport_quic_ctx_new_server (
		struct rrr_net_transport_quic_ctx **target,
    		struct rrr_net_transport_connection_id_pair *connection_ids_new,
		struct rrr_net_transport_handle *server_handle,
    		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const uint32_t client_chosen_version,
		const struct sockaddr *addr_remote,
		socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		socklen_t addr_local_len
) {
	return __rrr_net_transport_quic_ctx_new (
			target,
			connection_ids_new,
			(struct rrr_net_transport_tls *) server_handle->transport,
			((struct rrr_net_transport_quic_handle_data *) server_handle->submodule_private_ptr)->tls_data,
			NULL,
			server_handle->submodule_fd,
			connection_ids,
			client_chosen_version,
			NULL,
			addr_remote,
			addr_remote_len,
			addr_local,
			addr_local_len
	);
}

static int __rrr_net_transport_quic_ctx_new_client (
		struct rrr_net_transport_quic_ctx **target,
    		struct rrr_net_transport_connection_id_pair *connection_ids_new,
		struct rrr_net_transport_tls *transport_tls,
		struct rrr_net_transport_tls_data *tls_data,
		int fd,
    		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const char *hostname,
		const struct sockaddr *addr_remote,
		socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		socklen_t addr_local_len
) {
	return __rrr_net_transport_quic_ctx_new (
			target,
			connection_ids_new,
			transport_tls,
			NULL,
			tls_data,
			fd,
			connection_ids,
			1, /* Quic version 1 */
			hostname,
			addr_remote,
			addr_remote_len,
			addr_local,
			addr_local_len
	);
}

static int __rrr_net_transport_quic_tls_data_new (
		struct rrr_net_transport_tls_data **result,
		struct rrr_net_transport_tls *tls,
		const struct rrr_ip_data *ip_data,
		const SSL_METHOD *tls_method
) {
	int ret = 0;

	struct rrr_net_transport_tls_data *tls_data = NULL;

	if ((tls_data = rrr_net_transport_openssl_common_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (rrr_net_transport_openssl_common_new_ctx (
			&tls_data->ctx,
			tls_method,
			tls->flags,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path,
			&tls->alpn
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in QUIC");
		ret = 1;
		goto out_destroy;
	}

	SSL_CTX *ctx = tls_data->ctx;

	if (ngtcp2_crypto_openssl_configure_server_context(ctx) != 0) {
		RRR_MSG_0("Failed to configure SSL CTX to ngtcp2 in %s\n", __func__);
		ret = 1;
		goto out_destroy;
	}

	if (SSL_CTX_set_ciphersuites(ctx, RRR_NET_TRANSPORT_QUIC_CIPHERS) != 1) {
		RRR_MSG_0("Failed to set SSL ciphersuites in %s\n", __func__);
		ret = 1;
		goto out_destroy;
	}

	if (SSL_CTX_set1_groups_list(ctx, RRR_NET_TRANSPORT_QUIC_GROUPS) != 1) {
		RRR_MSG_0("Failed to set SSL groups in %s\n", __func__);
		ret = 1;
		goto out_destroy;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	// The created SSL object is only used as a template and
	// is copied using SSL_dup as new connections are created.
	if ((tls_data->ssl = SSL_new(ctx)) == NULL) {
		RRR_SSL_ERR("Could create SSL in QUIC");
		ret = 1;
		goto out_destroy;
	}

	SSL_set_quic_use_legacy_codepoint(tls_data->ssl, 0);

	SSL_set_alpn_protos (
			tls_data->ssl,
			(const uint8_t *) tls->alpn.protos,
			(unsigned int) tls->alpn.length
	);

	SSL_set_quic_transport_version(tls_data->ssl, TLSEXT_TYPE_quic_transport_parameters);

	tls_data->ip_data = *ip_data;

	*result = tls_data;

	goto out;
	out_destroy:
		rrr_net_transport_openssl_common_ssl_data_destroy(tls_data);
	out:
		return ret;
}

struct rrr_net_transport_quic_bind_and_listen_callback_data {
	const struct rrr_ip_data *ip_data;
	struct rrr_net_transport_tls *tls;
};

static int __rrr_net_transport_quic_bind_and_listen_callback (RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS) {
	struct rrr_net_transport_quic_bind_and_listen_callback_data *callback_data = arg;
	struct rrr_net_transport_tls *tls = callback_data->tls;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	struct rrr_net_transport_quic_handle_data *handle_data = NULL;

	if ((ret = __rrr_net_transport_quic_handle_data_new (&handle_data)) != 0) {
		goto out;
	}

	if ((ret = __rrr_net_transport_quic_tls_data_new (
			&handle_data->tls_data,
			tls,
			callback_data->ip_data,
			tls->ssl_server_method
	)) != 0) {
		goto out_destroy_handle;
	}

	RRR_DBG_7("net transport quic fd %i bind and listen port %u\n",
		callback_data->ip_data->fd, callback_data->ip_data->port);

	*submodule_private_ptr = handle_data;
	*submodule_fd = callback_data->ip_data->fd;

	goto out;
	out_destroy_handle:
		__rrr_net_transport_quic_handle_data_destroy(handle_data);
	out:
		return ret;
}

static int __rrr_net_transport_quic_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
	int ret = 0;

	struct rrr_ip_data ip_data = {0};
	struct rrr_net_transport_tls *transport_tls = (struct rrr_net_transport_tls *) transport;

	ip_data.port = port;

	if ((ret = rrr_ip_network_start_udp (&ip_data, do_ipv6)) != 0) {
		goto out;
	}

	if ((ret = rrr_ip_setsockopts (&ip_data, RRR_IP_SOCKOPT_RECV_TOS|RRR_IP_SOCKOPT_RECV_PKTINFO)) != 0) {
		goto out;
	}

	struct rrr_net_transport_quic_bind_and_listen_callback_data callback_data = {
		&ip_data,
		transport_tls
	};

	rrr_net_transport_handle new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
			NULL,
			NULL,
			__rrr_net_transport_quic_bind_and_listen_callback,
			&callback_data
	)) != 0) {
		goto out_destroy_ip;
	}

	RRR_DBG_7("net transport quic fd %i h %i listening on port %u IPv%s\n",
		ip_data.fd, new_handle, port, do_ipv6 ? "6" : "4");

	ret = callback(transport, new_handle, callback_final, callback_final_arg, callback_arg);

	goto out;
	out_destroy_ip:
		rrr_ip_close(&ip_data);
	out:
		return ret;
}

static int __rrr_net_transport_quic_send_packet (
		evutil_socket_t fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const uint8_t *data,
		size_t data_size
) {
	ssize_t bytes_written = 0;

	RRR_DBG_7("net transport quic fd %i transmit %llu bytes\n",
		fd, (unsigned long long) data_size);

	do {
		bytes_written = sendto(fd, data, data_size, 0, addr, addr_len);
	} while (bytes_written < 0 && errno == EINTR);

	if (bytes_written < 0) {
		RRR_MSG_0("net transport quic fd %i error while sending: %s\n", fd, rrr_strerror(errno));
		return 1;
	}

	if ((size_t) bytes_written < data_size) {
		RRR_MSG_0("net transport quic fd %i all bytes not written in %s\n", fd, __func__);
		return 1;
	}

	return 0;
}

static int __rrr_net_transport_quic_send_version_negotiation (
		struct rrr_net_transport_handle *handle
) {
	RRR_BUG("Version negotiation not implemented\n");
	(void)(handle);
	// ngtcp2_pkt_write_version_negotiation
	return 1;
}

static int __rrr_net_transport_quic_decode (
		RRR_NET_TRANSPORT_DECODE_ARGS
) {
	struct rrr_net_transport_quic_handle_data *handle_data = listen_handle->submodule_private_ptr;
	struct rrr_net_transport_tls_data *tls_data = handle_data->tls_data;

	int ret = 0;

	assert(tls_data->ip_data.port != 0);

	if ((ret = rrr_ip_recvmsg(datagram, &tls_data->ip_data, buf, buf_size)) != 0) {
		goto out;
	}

	RRR_DBG_7("net transport quic fd %i decode datagram %llu bytes\n",
		listen_handle->submodule_fd, (unsigned long long) datagram->msg_len);

	uint32_t version;
	const uint8_t *dcid, *scid;
	size_t dcidlen, scidlen;

	int ret_tmp = ngtcp2_pkt_decode_version_cid (
			&version,
			&dcid,
			&dcidlen,
			&scid,
			&scidlen,
			datagram->msg_iov.iov_base,
			datagram->msg_len,
			RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH
	);

	// Return INCOMPLETE for invalid packets or if there is nothing
	// more to do.

	if (ret_tmp < 0) {
		if (ret_tmp == NGTCP2_ERR_INVALID_ARGUMENT) {
			RRR_DBG_7("net transport quic fd %i failed to decode QUIC packet of size %llu\n",
					listen_handle->submodule_fd, (long long unsigned) datagram->msg_len);
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
			goto out;
		}
		else if (ret_tmp == NGTCP2_ERR_VERSION_NEGOTIATION) {
			if ((ret = __rrr_net_transport_quic_send_version_negotiation (
				listen_handle
			)) != 0) {
				goto out;
			}
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
			goto out;
		}

		RRR_MSG_0("Error while decoding QUIC packet: %s\n", ngtcp2_strerror(ret_tmp));
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	if (dcidlen > connection_ids->dst.length) {
		RRR_DBG_7("net transport quic fd %i dcid too long in received QUIC packet (%llu>%llu)\n",
				listen_handle->submodule_fd, (long long unsigned) dcidlen, (long long unsigned) connection_ids->dst.length);
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
		goto out;
	}

	if (scidlen > connection_ids->src.length) {
		RRR_DBG_7("net transport quic fd %i scid too long in received QUIC packet (%llu>%llu)\n",
				listen_handle->submodule_fd, (long long unsigned) scidlen, (long long unsigned) connection_ids->src.length);
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
		goto out;
	}

	// Add any stateless address validation here

	memcpy(connection_ids->dst.data, dcid, dcidlen);
	connection_ids->dst.length = dcidlen;

	memcpy(connection_ids->src.data, scid, scidlen);
	connection_ids->src.length = scidlen;

	out:
	return ret;
}

struct rrr_net_transport_quic_accept_callback_data {
	struct rrr_net_transport_handle *listen_handle;
	uint32_t client_chosen_version;
	struct rrr_net_transport_connection_id_pair connection_ids_new;
};

static int __rrr_net_transport_quic_accept_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_quic_accept_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_net_transport_quic_handle_data *handle_data = NULL;

	if ((ret = __rrr_net_transport_quic_handle_data_new (&handle_data)) != 0) {
		goto out;
	}

	if ((ret = __rrr_net_transport_quic_ctx_new_server (
			&handle_data->ctx,
			&callback_data->connection_ids_new,
			callback_data->listen_handle,
			connection_ids,
			callback_data->client_chosen_version,
			(const struct sockaddr *) &datagram->addr_remote,
			datagram->addr_remote_len,
			(const struct sockaddr *) &datagram->addr_local,
			datagram->addr_local_len
	)) != 0) {
		goto out_destroy_handle;
	}

	{
		char buf_addr_remote[128];
		char buf_addr_local[128];
		char buf_scid[sizeof(connection_ids->src.data) * 2 + 1];
		char buf_dcid[sizeof(connection_ids->src.data) * 2 + 1];

		rrr_ip_to_str(buf_addr_remote, sizeof(buf_addr_remote), (const struct sockaddr *) &handle_data->ctx->path_active.addr_remote, handle_data->ctx->path_active.addr_remote_len);
		rrr_ip_to_str(buf_addr_local, sizeof(buf_addr_local), (const struct sockaddr *) &handle_data->ctx->path_active.addr_local, handle_data->ctx->path_active.addr_local_len);
		rrr_net_transport_connection_id_to_str(buf_scid, sizeof(buf_scid), &connection_ids->src);
		rrr_net_transport_connection_id_to_str(buf_dcid, sizeof(buf_dcid), &connection_ids->dst);

		RRR_DBG_7("net transport quic fd %i accepted connection from %s to %s scid %s dcid %s\n",
				callback_data->listen_handle->submodule_fd, buf_addr_remote, buf_addr_local, buf_scid, buf_dcid);
	}

	*submodule_private_ptr = handle_data;
	*submodule_fd = -1; // Set to disable polling on events for this handle

	goto out;
	out_destroy_handle:
		__rrr_net_transport_quic_handle_data_destroy(handle_data);
	out:
		return ret;
}

int __rrr_net_transport_quic_pre_destroy (
		RRR_NET_TRANSPORT_PRE_DESTROY_ARGS
) {
	struct rrr_net_transport_quic_handle_data *handle_data = submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	if (!ctx) {
		goto out;
	}

	if (!ctx->initial_received) {
		// Wait for first packet to be handled
		return RRR_NET_TRANSPORT_READ_READ_EOF;
	}

	(void)(application_private_ptr);

	const char msg[] = "Connection rejected, try again.";
	ngtcp2_connection_close_error cerr = {0};
	ngtcp2_path_storage path_storage;
	ngtcp2_pkt_info pi = {0};
	uint8_t pb[1200];
	uint64_t timestamp = 0;

	ngtcp2_connection_close_error_set_transport_error(&cerr, handle->submodule_close_reason, (const uint8_t *) msg, strlen(msg));
	ngtcp2_path_storage_zero(&path_storage);

	if (rrr_time_get_64_nano(&timestamp, NGTCP2_SECONDS) != 0) {
		RRR_MSG_0("Warning: Failed to produce timestamp in %s\n", __func__);
		goto out;
	}

	ssize_t bytes = ngtcp2_conn_write_connection_close (
			ctx->conn,
			&path_storage.path,
			&pi,
			pb,
			sizeof(pb),
			&cerr,
			timestamp
	);

	if (bytes == 0 || bytes == NGTCP2_ERR_INVALID_STATE) {
		// No data to send or ignore error
		goto out;
	}
	else if (bytes < 0) {
		RRR_MSG_0("Warning: Failed to make connection close packet in %s: %s\n", __func__, ngtcp2_strerror((int) bytes));
		goto out;
	}

	{
		char addrbuf[128];
		rrr_ip_to_str(addrbuf, sizeof(addrbuf), (const struct sockaddr *) path_storage.path.remote.addr, path_storage.path.remote.addrlen);
		RRR_DBG_7("net transport quic fd %i h %i tx connection close %lli bytes to %s\n",
			ctx->fd, handle->handle, (long long int) bytes, addrbuf);
	}

	if (__rrr_net_transport_quic_send_packet (
				ctx->fd,
				(const struct sockaddr *) path_storage.path.remote.addr,
				path_storage.path.remote.addrlen,
				(const uint8_t *) pb,
				(size_t) bytes
	) != 0) {
		RRR_MSG_0("Warning: Failed to send connection close packet in %s\n", __func__);
		goto out;
	}

	out:
	// OK now to destroy connection (any errors ignored)
	return 0;
}

static void __rrr_net_transport_quic_connection_close (
		struct rrr_net_transport_handle *listen_handle,
		rrr_net_transport_handle handle,
		const uint32_t close_reason
) {
	// This will override any pre destroy set by application
	rrr_net_transport_handle_close_with_reason (
			listen_handle->transport,
			handle,
			close_reason,
			__rrr_net_transport_quic_pre_destroy
	);
}

struct rrr_net_transport_quic_connect_callback_data {
	struct rrr_net_transport_tls *tls;
	const char *hostname;
	const struct sockaddr *remote_addr;
	const socklen_t remote_addr_len;
	const struct sockaddr *local_addr;
	const socklen_t local_addr_len;
	const struct rrr_ip_data *ip_data;
	struct rrr_net_transport_connection_id_pair connection_ids_new;
};

static int __rrr_net_transport_quic_connect_callback (RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS) {
	struct rrr_net_transport_quic_connect_callback_data *callback_data = arg;

	(void)(datagram);

	int ret = 0;

	struct rrr_net_transport_quic_handle_data *handle_data = NULL;

	if ((ret = __rrr_net_transport_quic_handle_data_new (&handle_data)) != 0) {
		goto out;
	}

	if ((ret = __rrr_net_transport_quic_tls_data_new (
			&handle_data->tls_data,
			callback_data->tls,
			callback_data->ip_data,
			callback_data->tls->ssl_client_method
	)) != 0) {
		goto out_destroy_handle;
	}

	if ((ret = __rrr_net_transport_quic_ctx_new_client (
			&handle_data->ctx,
			&callback_data->connection_ids_new,
			callback_data->tls,
			handle_data->tls_data,
			callback_data->ip_data->fd,
			connection_ids,
			callback_data->hostname,
			(const struct sockaddr *) callback_data->remote_addr,
			callback_data->remote_addr_len,
			(const struct sockaddr *) callback_data->local_addr,
			callback_data->local_addr_len
	)) != 0) {
		goto out_destroy_handle;
	}

	SSL_set_connect_state(handle_data->ctx->ssl);

	{
		char buf_addr_remote[128];
		char buf_addr_local[128];

		rrr_ip_to_str(buf_addr_remote, sizeof(buf_addr_remote), (const struct sockaddr *) &handle_data->ctx->path_active.addr_remote, handle_data->ctx->path_active.addr_remote_len);
		rrr_ip_to_str(buf_addr_local, sizeof(buf_addr_local), (const struct sockaddr *) &handle_data->ctx->path_active.addr_local, handle_data->ctx->path_active.addr_local_len);

		RRR_DBG_7("net transport quic fd %i connect from %s to %s\n",
				callback_data->ip_data->fd, buf_addr_local, buf_addr_remote);
	}

	*submodule_private_ptr = handle_data;
	*submodule_fd = callback_data->ip_data->fd;

	goto out;
	out_destroy_handle:
		__rrr_net_transport_quic_handle_data_destroy(handle_data);
	out:
		return ret;
}

#define RRR_NET_TRANSPORT_QUIC_CONNECT_COMPLETE RRR_READ_PERFORMED

struct rrr_net_transport_quic_connect_resolve_callback_data {
	struct rrr_net_transport_tls *tls;
	int attempt;
	struct rrr_ip_data ip_data;
	rrr_net_transport_handle new_handle;
	struct sockaddr *addr;
	socklen_t *socklen;
};

static int __rrr_net_transport_quic_connect_resolve_callback (
		const char *host,
		uint16_t port,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *arg
) {
	struct rrr_net_transport_quic_connect_resolve_callback_data *callback_data = arg;
	struct rrr_ip_data *ip_data = &callback_data->ip_data;
	struct rrr_net_transport_tls *tls = callback_data->tls;

	int ret = 0;

	char buf[128];
	struct sockaddr_storage remote_addr = {0};
	socklen_t remote_addr_len = sizeof(remote_addr);
	struct sockaddr_storage local_addr = {0};
	socklen_t local_addr_len = sizeof(local_addr);

	callback_data->attempt++;
	memset(ip_data, '\0', sizeof(*ip_data));
	rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);

	if (rrr_socket_graylist_exists(&tls->connect_graylist, addr, addr_len)) {
		RRR_DBG_7("net transport quic connect attempt [%i] not connecting to %s:%u->%s due to graylisting, trying next alternative if any.\n",
			callback_data->attempt, host, port, buf);
		goto out;
	}

	RRR_DBG_7("net transport quic connect attempt [%i] to %s:%u->%s.\n",
		callback_data->attempt, host, port, buf);

	ip_data->port = 0;

	if (addr->sa_family == AF_INET) {
		if ((ret = rrr_ip_network_start_udp(ip_data, 0)) != 0) {
			goto out;
		}
	}
	else if (addr->sa_family == AF_INET6) {
		if ((ret = rrr_ip_network_start_udp(ip_data, 1)) != 0) {
			goto out;
		}
	}
	else {
		RRR_BUG("Unknown address family %u in %s\n", addr->sa_family, __func__);
	}

	if ((ret = rrr_ip_setsockopts (ip_data, RRR_IP_SOCKOPT_RECV_TOS|RRR_IP_SOCKOPT_RECV_PKTINFO)) != 0) {
		goto out;
	}

	assert(sizeof(remote_addr) >= addr_len);
	memcpy(&remote_addr, addr, addr_len);
	remote_addr_len = addr_len;

	local_addr_len = sizeof(local_addr);
	if (getsockname(ip_data->fd, (struct sockaddr *) &local_addr, &local_addr_len) != 0) {
		RRR_MSG_0("Failed to get local address in %s: %s\n",
			__func__, rrr_strerror(errno));
		ret = 1;
		goto out_close;
	}

	struct rrr_net_transport_quic_connect_callback_data allocate_callback_data = {
		callback_data->tls,
		host,
		(const struct sockaddr *) &remote_addr,
		remote_addr_len,
		(const struct sockaddr *) &local_addr,
		local_addr_len,
		&callback_data->ip_data,
		RRR_NET_TRANSPORT_CONNECTION_ID_PAIR_DEFAULT_INITIALIZER
	};

	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&callback_data->new_handle,
			(struct rrr_net_transport *) callback_data->tls,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			NULL,
			NULL,
			__rrr_net_transport_quic_connect_callback,
			&allocate_callback_data
	)) != 0) {
		RRR_MSG_0("Could not register handle in %s\n", __func__);
		ret = 1;
		goto out_close;
	}

/*	{
		char buf_scid[sizeof(allocate_callback_data.connection_ids_new.src.data) * 2 + 1];
		char buf_dcid[sizeof(allocate_callback_data.connection_ids_new.src.data) * 2 + 1];
		rrr_net_transport_connection_id_to_str(buf_scid, sizeof(buf_scid), &allocate_callback_data.connection_ids_new.src);
		rrr_net_transport_connection_id_to_str(buf_dcid, sizeof(buf_dcid), &allocate_callback_data.connection_ids_new.dst);
		printf("cid a %s cib b %s\n", buf_scid, buf_dcid);
	}*/

	if ((ret = rrr_net_transport_handle_cids_push (
			(struct rrr_net_transport *) callback_data->tls,
			callback_data->new_handle,
			&allocate_callback_data.connection_ids_new
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_BUSY) {
			RRR_DBG_7("net transport quic fd %i h %i cid collision while connecting. Closing connection.\n",
					callback_data->ip_data.fd, callback_data->new_handle
			);
			goto out_close;
		}
		RRR_MSG_0("Error while adding CID to newly created connection in %s\n", __func__);
		goto out;
	}

	assert(*callback_data->socklen >= addr_len);
	memcpy(callback_data->socklen, addr, addr_len);
	*callback_data->socklen = addr_len;

	ret = RRR_NET_TRANSPORT_QUIC_CONNECT_COMPLETE;

	goto out;
	out_close:
		rrr_ip_close(ip_data);
	out:
		return ret;
}

static int __rrr_net_transport_quic_connect (
		RRR_NET_TRANSPORT_CONNECT_ARGS
) {
	struct rrr_net_transport_tls *transport_tls = (struct rrr_net_transport_tls *) transport;

	int ret = 0;

	struct rrr_net_transport_quic_connect_resolve_callback_data callback_data = {
		.tls = transport_tls,
		.addr = addr,
		.socklen = socklen
	};

	if ((ret = rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
			port,
			host,
			__rrr_net_transport_quic_connect_resolve_callback,
			&callback_data
	)) == RRR_NET_TRANSPORT_QUIC_CONNECT_COMPLETE) {
		ret = 0;
	}
	else {
		RRR_MSG_0("net transport quic connection to %s:%u failed\n");
		ret = 1;
		goto out;
	}

	*handle = callback_data.new_handle;

	out:
	return ret;
}

static int __rrr_net_transport_quic_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	int ret = 0;

	int ret_tmp;
	ngtcp2_pkt_hd pkt;
	const uint32_t close_reason = NGTCP2_INTERNAL_ERROR;

	if ((ret_tmp = ngtcp2_accept (&pkt, datagram->msg_iov.iov_base, datagram->msg_len)) < 0) {
		if (ret_tmp == NGTCP2_ERR_RETRY) {
			/* Packet is stored into dest */
			RRR_BUG("SEND RETRY not implemented");
		}
		else {
			/* Packet is not stored into dest */
			RRR_DBG_7("net transport quic fd %i error while accepting QUIC packet: %s. Dropping it.\n",
				listen_handle->submodule_fd, ngtcp2_strerror(ret_tmp));
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
			goto out;
		}
	}

	struct rrr_net_transport_quic_accept_callback_data callback_data = {
		listen_handle,
		pkt.version,
		RRR_NET_TRANSPORT_CONNECTION_ID_PAIR_DEFAULT_INITIALIZER
	};

	if ((ret = rrr_net_transport_handle_allocate_and_add (
			new_handle,
			listen_handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			connection_ids,
			datagram,
			__rrr_net_transport_quic_accept_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in %s return was %i\n", __func__, ret);
		goto out;
	}

	if ((ret = callback (
			listen_handle->transport,
			*new_handle,
			(struct sockaddr *) datagram->msg.msg_name,
			datagram->msg.msg_namelen,
			final_callback,
			final_callback_arg,
			callback_arg
	)) != 0) {
		RRR_DBG_7("net transport quic fd %i h %i cid error from application initializor while accepting QUIC packet: %s. Closing connection.\n",
				listen_handle->submodule_fd, *new_handle, ngtcp2_strerror(ret_tmp));
		goto out_close;
	}

	if ((ret = rrr_net_transport_handle_cids_push (
			listen_handle->transport,
			*new_handle,
			&callback_data.connection_ids_new
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_BUSY) {
			RRR_DBG_7("net transport quic fd %i h %i cid collision while accepting QUIC packet. Closing connection.\n",
					listen_handle->submodule_fd, *new_handle
			);
			goto out_close;
		}
		RRR_MSG_0("Error while adding CID to newly accepted connection in %s\n", __func__);
		goto out;
	}

/*
	Enable to test early close
	if (1) {
		printf("Early close\n");
		goto out_close;
	}
*/

	goto out;
	out_close:
		__rrr_net_transport_quic_connection_close(listen_handle, *new_handle, close_reason);
		ret = 0;
	out:
		return ret;
}

static uint64_t vec_len(const ngtcp2_vec *vec, size_t n) {
	size_t i;
	size_t res = 0;

	for (i = 0; i < n; ++i) {
		res += vec[i].len;
	}

	return res;
}

static int __rrr_net_transport_quic_write (
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		int (*cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS),
		int (*cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS),
		int (*cb_ack)(RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS),
		void *cb_arg
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	char buf[1280];
	ngtcp2_vec data_vector[128] = {0};
	size_t data_vector_count = 0;
	ngtcp2_path_storage path_storage;
	ngtcp2_pkt_info packet_info = {0};
	int fin = 0;
	ngtcp2_ssize bytes_from_src = 0;
	ngtcp2_ssize bytes_to_buf = 0;
	uint64_t timestamp = 0;

	RRR_ASSERT(sizeof(ngtcp2_vec) == sizeof(struct rrr_net_transport_vector),size_of_ngtpc2_vector_is_not_equal_to_size_of_net_transport_vector);
	assert((stream_id == -1 && cb_get_message == NULL) || (stream_id >= 0 && cb_get_message != NULL));

	ngtcp2_path_storage_zero(&path_storage);

	for (;;) {
		if (rrr_time_get_64_nano(&timestamp, NGTCP2_SECONDS) != 0) {
			goto out_failure;
		}

		if (cb_get_message != NULL) {
			data_vector_count = sizeof(data_vector)/sizeof(*data_vector);

			// Note : - Callback MUST set all values when there is no data.
			//          Defaults are stream_id=-1, data_vector_count=0, fin=0.
			//        - Callback MAY otherwise change the stream number as applicable.

			if (cb_get_message (
					&stream_id,
					(struct rrr_net_transport_vector *) data_vector,
					&data_vector_count,
					&fin,
					cb_arg
			) != 0) {
				goto out_failure;
			}

			if (data_vector_count > 0) {
				RRR_DBG_7("net transport quic fd %i h %i write stream id %" PRIi64 " received %llu bytes from downstream in %llu vectors fin %i\n",
						ctx->fd,
						handle->handle,
						stream_id,
						(unsigned long long) vec_len(data_vector, (unsigned long long) data_vector_count),
						(unsigned long long) data_vector_count,
						fin
				);
			}
		}
		else {
			data_vector_count = 0;
		}

		bytes_to_buf = ngtcp2_conn_writev_stream (
				ctx->conn,
				&path_storage.path,
				&packet_info,
				(uint8_t *) buf,
				sizeof(buf),
				&bytes_from_src,
				NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0),
				stream_id,
				data_vector,
				data_vector_count,
				timestamp
		);

		if (bytes_to_buf < 0) {
			if (bytes_to_buf == NGTCP2_ERR_STREAM_DATA_BLOCKED || bytes_to_buf == NGTCP2_ERR_STREAM_SHUT_WR) {
				RRR_DBG_7("net transport quic fd %i h %i stream %" PRIi64 " blocked\n",
					ctx->fd, ctx->connected_handle, stream_id);

				if (cb_blocked != NULL && cb_blocked(stream_id, 1, cb_arg) != 0) {
					// ngtcp2_connection_close_error_set_application_error();
					goto out_failure;
				}
			}
			else if (bytes_to_buf == NGTCP2_ERR_WRITE_MORE) {
				// Must call writev repeatedly until complete.
				assert(bytes_from_src >= 0);

				if (cb_ack != NULL && cb_ack(stream_id, (size_t) bytes_from_src, cb_arg) != 0) {
					// ngtcp2_connection_close_error_set_application_error();
					goto out_failure;
				}
			}
			else {
				RRR_MSG_0("net transport quic fd %i h %i error while writing: %s\n",
					ctx->fd, ctx->connected_handle, ngtcp2_strerror((int) bytes_to_buf));
				goto out_failure;
			}
		}
		else if (bytes_to_buf == 0) {
			break;
		}

		if (bytes_to_buf > 0 && __rrr_net_transport_quic_send_packet (
					ctx->fd,
					(const struct sockaddr *) path_storage.path.remote.addr,
					path_storage.path.remote.addrlen,
					(const uint8_t *) buf,
					(size_t) bytes_to_buf
		) != 0) {
			goto out_failure;
		}
	}

	return 0;

	out_failure:
	return RRR_NET_TRANSPORT_READ_HARD_ERROR;
}

static int __rrr_net_transport_quic_write_no_streams (
		struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	if ((ret = __rrr_net_transport_quic_write (
			handle,
			-1,
			NULL,
			NULL,
			NULL,
			NULL
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_net_transport_quic_write_all_streams (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	if ((ret = __rrr_net_transport_quic_write_no_streams (handle)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&ctx->streams, struct rrr_net_transport_quic_stream);
		if ((ret = __rrr_net_transport_quic_write (
				handle,
				node->stream_id,
				node->cb_get_message,
				node->cb_blocked,
				node->cb_ack,
				node->cb_arg
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_net_transport_quic_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	rrr_nullsafe_len written_size = 0;	

	*bytes_read = 0;
	*stream_id = 0;

	// Write any data from ngtcp2 and fetch stream data from
	// application layer.
	if ((ret = __rrr_net_transport_quic_write_all_streams (handle)) != 0) {
		goto out;
	}

	assert(sizeof(bytes_read) >= sizeof(written_size));

	RRR_LL_ITERATE_BEGIN(&ctx->streams, struct rrr_net_transport_quic_stream);
		rrr_nullsafe_str_copyto_offset (
				&written_size,
				buf,
				buf_size,
				node->recv_buf.str,
				node->recv_buf.rpos
		);
		if (written_size > 0) {
			// Increment read position
			rrr_biglength_add_bug (&node->recv_buf.rpos, written_size);

			// Clear buffer if all data was written to the outbut buffer
			if (rrr_nullsafe_str_len(node->recv_buf.str) == node->recv_buf.rpos) {
				rrr_nullsafe_str_clear(node->recv_buf.str);
				node->recv_buf.rpos = 0;
			}

			// Make downstream call read again in case there is more data
			rrr_net_transport_ctx_notify_read(handle);

			*bytes_read = written_size;
			*stream_id = node->stream_id;

			RRR_DBG_7("net transport quic fd %i h %i read stream id %" PRIi64 " deliver %" PRIrrrbl " bytes to downstream\n",
					ctx->fd, ctx->connected_handle, node->stream_id, written_size);

			goto out;
		}
		if (node->flags & RRR_NET_TRANSPORT_STREAM_F_CLOSING && rrr_nullsafe_str_len(node->recv_buf.str) == 0) {
			RRR_DBG_7("net transport quic fd %i h %i stream id %" PRIi64 " closing now\n",
					ctx->fd, ctx->connected_handle, node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&ctx->streams, 0; __rrr_net_transport_quic_stream_destroy(node));

	ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;

	out:
	return ret;
}

static void __rrr_net_transport_quic_receive_verify_path_report_migration (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	char buf_a[128];
	char buf_b[128];

	const int addr_local_mismatch = (
			ctx->path_active.addr_local_len != ctx->path_migration.addr_local_len ||
			memcmp(&ctx->path_active.addr_local, &ctx->path_migration.addr_local, ctx->path_active.addr_local_len) != 0
	);
	const int addr_remote_mismatch = (
			ctx->path_active.addr_remote_len != ctx->path_migration.addr_remote_len ||
			memcmp(&ctx->path_active.addr_remote, &ctx->path_migration.addr_remote, ctx->path_active.addr_remote_len) != 0
	);

	if (addr_local_mismatch) {
		rrr_ip_to_str(buf_a, sizeof(buf_a), (const struct sockaddr *) &ctx->path_active.addr_local, ctx->path_active.addr_local_len);
		rrr_ip_to_str(buf_b, sizeof(buf_b), (const struct sockaddr *) &ctx->path_migration.addr_local, ctx->path_migration.addr_local_len);
		RRR_DBG_7("net transport quic fd %i h %i local address migration %s->%s\n",
			ctx->fd, handle->handle, buf_a, buf_b);
	}

	if (addr_remote_mismatch) {
		rrr_ip_to_str(buf_a, sizeof(buf_a), (const struct sockaddr *) &ctx->path_active.addr_remote, ctx->path_active.addr_remote_len);
		rrr_ip_to_str(buf_b, sizeof(buf_b), (const struct sockaddr *) &ctx->path_migration.addr_remote, ctx->path_migration.addr_remote_len);
		RRR_DBG_7("net transport quic fd %i h %i remote address migration %s->%s\n",
			ctx->fd, handle->handle, buf_a, buf_b);
	}
}

static int __rrr_net_transport_quic_receive_handle_migration (
		struct rrr_net_transport_handle *handle,
		const struct rrr_socket_datagram *datagram
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	int ret_tmp;
	ngtcp2_path path;
	uint64_t timestamp = 0;

	if (rrr_time_get_64_nano(&timestamp, NGTCP2_SECONDS) != 0) {
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	switch (ctx->path_migration_mode) {
		case RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_NONE:
			// Migration with path validation
			memcpy(&ctx->path_migration.addr_local, &datagram->addr_local, datagram->addr_local_len);
			ctx->path_migration.addr_local_len = datagram->addr_local_len;
			memcpy(&ctx->path_migration.addr_remote, &datagram->addr_remote, datagram->addr_remote_len);
			ctx->path_migration.addr_remote_len = datagram->addr_remote_len;

			__rrr_net_transport_quic_receive_verify_path_report_migration (handle);

			rrr_net_transport_quic_path_to_ngtcp2_path (&path, &ctx->path_migration);
			if ((ret_tmp = ngtcp2_conn_initiate_migration (ctx->conn, &path, timestamp)) != 0) {
				RRR_MSG_0("net transport quic fd %i h %i failed to initiate migration: %s\n",
					ctx->fd, handle->handle, ngtcp2_strerror(ret_tmp));
				ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
				goto out;
			}
			break;
		case RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_LOCAL_REBIND:
			// Rebind (simply set new address)
			__rrr_net_transport_quic_receive_verify_path_report_migration (handle);
			rrr_net_transport_quic_path_to_ngtcp2_path (&path, &ctx->path_migration);
			ngtcp2_conn_set_local_addr(ctx->conn, &path.local);
			break;
		case RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_IMMEDIATE:
			// Immediate migration requested
			__rrr_net_transport_quic_receive_verify_path_report_migration (handle);

			rrr_net_transport_quic_path_to_ngtcp2_path (&path, &ctx->path_migration);
			if ((ret_tmp = ngtcp2_conn_initiate_immediate_migration (ctx->conn, &path, timestamp)) != 0) {
				RRR_MSG_0("net transport quic fd %i h %i failed to initiate immediate migration: %s\n",
					ctx->fd, handle->handle, ngtcp2_strerror(ret_tmp));
				ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
				goto out;
			}
			break;
		case RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_VALIDATION:
			RRR_BUG("Migration mode VALIDATION cannot be set expicitly in %s\n", __func__);
			break;
		default:
			RRR_BUG("Migration mode %i node implemented in %s\n", __func__);
			break;
	};

	ctx->path_active = ctx->path_migration;
	memset(&ctx->path_migration, '\0', sizeof(ctx->path_migration));
	ctx->path_migration_mode = 0;

	out:
	return ret;
}

static int __rrr_net_transport_quic_receive_verify_path (
		struct rrr_net_transport_handle *handle,
		const struct rrr_socket_datagram *datagram
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	char buf_a[128];
	char buf_b[128];

	const int addr_local_mismatch = (
		ctx->path_active.addr_local_len != datagram->addr_local_len ||
		memcmp(&ctx->path_active.addr_local, &datagram->addr_local, ctx->path_active.addr_local_len) != 0
	);
	const int addr_remote_mismatch = (
		ctx->path_active.addr_remote_len != datagram->addr_remote_len ||
		memcmp(&ctx->path_active.addr_remote, &datagram->addr_remote, ctx->path_active.addr_remote_len) != 0
	);
	const int addr_local_is_any = (
		rrr_ip_addr_is_any((const struct sockaddr *) &ctx->path_active.addr_local) &&
		rrr_ip_addr_get_port((const struct sockaddr *) &ctx->path_active.addr_local) == rrr_ip_addr_get_port((const struct sockaddr *) &datagram->addr_local) &&
		ctx->path_active.addr_local_len == datagram->addr_local_len
	);

	if (!ngtcp2_conn_get_handshake_completed(ctx->conn)) {
		if (addr_local_is_any) {
			if (!ctx->path_migration_mode) {
				// The local address may change from all zeros to an actual address during handshake.
				// Initiale migration which will take place after the handshake to store the correct address.
				ctx->path_migration = ctx->path_active;
				assert(ctx->path_migration.addr_local_len == datagram->addr_local_len);
				memcpy(&ctx->path_migration.addr_local, &datagram->addr_local, datagram->addr_local_len);
				ctx->path_migration_mode = RRR_NET_TRANSPORT_QUIC_PATH_MIGRATION_MODE_LOCAL_REBIND;
				RRR_DBG_7("net transport quic fd %i h %i performing local rebind during handshake\n",
					ctx->fd, handle->handle);
			}
			else {
				// Verify that local bound address does not change
				// after migration is requested.
				struct rrr_net_transport_quic_path path_test = ctx->path_active;
				assert(path_test.addr_local_len == datagram->addr_local_len);
				memcpy(&path_test.addr_local, &datagram->addr_local, datagram->addr_local_len);
				if (memcmp(&path_test, &ctx->path_migration, sizeof(path_test)) != 0) {
					rrr_ip_to_str(buf_a, sizeof(buf_a), (const struct sockaddr *) &ctx->path_migration.addr_local, ctx->path_migration.addr_local_len);
					rrr_ip_to_str(buf_b, sizeof(buf_b), (const struct sockaddr *) &path_test.addr_local, path_test.addr_local_len);
					RRR_DBG_7("net transport quic fd %i h %i local address changed during handshake after migration was initiated (%s->%s). Closing.\n",
						ctx->fd, handle->handle, buf_a, buf_b);
					ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
					goto out;
				}
			}
		}
		else if (addr_local_mismatch) {
			rrr_ip_to_str(buf_a, sizeof(buf_a), (const struct sockaddr *) &ctx->path_active.addr_local, ctx->path_active.addr_local_len);
			rrr_ip_to_str(buf_b, sizeof(buf_b), (const struct sockaddr *) &datagram->addr_local, datagram->addr_local_len);
			RRR_DBG_7("net transport quic fd %i h %i local address changed during handshake (%s->%s). Closing.\n",
				ctx->fd, handle->handle, buf_a, buf_b);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}

		// Remote address should not change during handshake
		if (addr_remote_mismatch) {
			rrr_ip_to_str(buf_a, sizeof(buf_a), (const struct sockaddr *) &ctx->path_active.addr_remote, ctx->path_active.addr_remote_len);
			rrr_ip_to_str(buf_b, sizeof(buf_b), (const struct sockaddr *) &datagram->addr_remote, datagram->addr_remote_len);
			RRR_DBG_7("net transport quic fd %i h %i remote address changed during handshake (%s->%s). Closing.\n",
				ctx->fd, handle->handle, buf_a, buf_b);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}

		// No migration or rebind is performed until handshake is complete
		goto out;
	}

	if (addr_local_mismatch || addr_remote_mismatch || ctx->path_migration_mode) {
		if ((ret = __rrr_net_transport_quic_receive_handle_migration(handle, datagram)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_net_transport_quic_receive (
		RRR_NET_TRANSPORT_RECEIVE_ARGS
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	if (ctx->connected_handle == 0) {
		ctx->initial_received = 1;
		__rrr_net_transport_quic_ctx_post_connect_patch(ctx, handle->handle);
	}
	else {
		assert(ctx->connected_handle == handle->handle);
	}

	if ((ret = __rrr_net_transport_quic_receive_verify_path(handle, datagram)) != 0) {
		goto out;
	}

	int ret_tmp;
	const ngtcp2_path path = {
		{
			(struct sockaddr *) &ctx->path_active.addr_local,
			ctx->path_active.addr_local_len
		}, {
			(struct sockaddr *) &ctx->path_active.addr_remote,
			ctx->path_active.addr_remote_len
		},
		NULL
	};
	ngtcp2_pkt_info pi = {.ecn = datagram->tos};
	uint64_t timestamp = 0;

	if (rrr_time_get_64_nano(&timestamp, NGTCP2_SECONDS) != 0) {
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	uint8_t flags = * (uint8_t *) datagram->msg_iov.iov_base;

	RRR_DBG_7("net transport quic fd %i h %i receive datagram size %llu max %llu flags %u\n",
		ctx->fd,
		ctx->connected_handle,
		(unsigned long long) datagram->msg_len,
		(unsigned long long) datagram->msg_iov.iov_len,
		(unsigned long) flags
	);

	if ((ret_tmp = ngtcp2_conn_read_pkt (
			ctx->conn,
			&path,
			&pi,
			datagram->msg_iov.iov_base,
			datagram->msg_len,
			timestamp
	)) != 0) {
		if (ret_tmp == NGTCP2_ERR_DRAINING) {
			RRR_MSG_0("net transport quic fd %i h %i connection closed while reading (now in draining state)\n",
				ctx->fd, ctx->connected_handle);
			ret = RRR_NET_TRANSPORT_READ_READ_EOF;
		}
		else if (ret_tmp == NGTCP2_ERR_CRYPTO) {
			RRR_MSG_0("net transport quic fd %i h %i crypto error while reading\n",
				ctx->fd, ctx->connected_handle);
			ngtcp2_connection_close_error_set_transport_error_tls_alert (
					&ctx->last_error,
					ngtcp2_conn_get_tls_alert(ctx->conn),
					NULL,
					0
			);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		}
		else {
			RRR_MSG_0("net transport quic fd %i h %i transport error while reading packet: %s\n",
				ctx->fd, ctx->connected_handle, ngtcp2_strerror(ret_tmp));
			ngtcp2_connection_close_error_set_transport_error_liberr (
					&ctx->last_error,
					ret_tmp,
					NULL,
					0
			);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		}
		goto out;
	}

	if (handle->close_now) {
		// Don't write anything, wait for connection close to be sent
		RRR_DBG_7("net transport quic fd %i h %i close now set after reading before writing\n",
			ctx->fd, ctx->connected_handle);
		rrr_net_transport_ctx_notify_read (handle);
		goto out;
	}

	// Write any data generated by ngtcp2 or application
	if ((ret = __rrr_net_transport_quic_write_no_streams (handle)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_net_transport_quic_stream_open (
		RRR_NET_TRANSPORT_STREAM_OPEN_ARGS
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	int64_t stream_id = 0;

	assert(flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL);

	int ret_tmp;
	if ((ret_tmp = (flags & RRR_NET_TRANSPORT_STREAM_F_BIDI ? ngtcp2_conn_open_bidi_stream : ngtcp2_conn_open_uni_stream) (
			ctx->conn,
			&stream_id,
			NULL
	)) != 0) {
		if (ret == NGTCP2_ERR_STREAM_ID_BLOCKED) {
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
		}
		else {
			RRR_MSG_0("Failed to allocate stream ID in %s: %s\n", __func__,
				ngtcp2_strerror(ret_tmp));
		}
		goto out;
	}

	if ((ret = __rrr_net_transport_quic_ctx_stream_open (
			ctx,
			stream_id,
			flags
	)) != 0) {
		goto out;
	}

	// Write any data generated by ngtcp2
	if ((ret = __rrr_net_transport_quic_write_all_streams (handle)) != 0) {
		goto out;
	}

	*result = stream_id;

	out:
	return ret;
}

static void __rrr_net_transport_quic_selected_proto_get (
		RRR_NET_TRANSPORT_SELECTED_PROTO_GET_ARGS
) {
	(void)(handle);
	(void)(proto);
}

static int __rrr_net_transport_quic_poll (
		RRR_NET_TRANSPORT_POLL_ARGS
) {
	(void)(handle);
	RRR_BUG("poll not implemented\n");
	return 1;
}

static int __rrr_net_transport_quic_handshake (
		RRR_NET_TRANSPORT_HANDSHAKE_ARGS
) {
	struct rrr_net_transport_quic_handle_data *handle_data = handle->submodule_private_ptr;
	struct rrr_net_transport_quic_ctx *ctx = handle_data->ctx;

	int ret = 0;

	if ((ret = __rrr_net_transport_quic_write_no_streams (handle)) != 0) {
		goto out;
	}

	ret = ngtcp2_conn_get_handshake_completed(ctx->conn)
		? 0
		: RRR_NET_TRANSPORT_READ_INCOMPLETE
	;

	out:
	return ret;
}

static int __rrr_net_transport_quic_is_tls (void) {
	return 1;
}

static int __rrr_net_transport_quic_close (struct rrr_net_transport_handle *handle) {
	__rrr_net_transport_quic_handle_data_destroy(handle->submodule_private_ptr);
	return 0;
}

static void __rrr_net_transport_quic_destroy (
		RRR_NET_TRANSPORT_DESTROY_ARGS
) {
	rrr_openssl_global_unregister_user();

	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;
	rrr_net_transport_tls_common_destroy(tls);
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_quic_destroy,
	__rrr_net_transport_quic_connect,
	__rrr_net_transport_quic_bind_and_listen,
	__rrr_net_transport_quic_decode,
	__rrr_net_transport_quic_accept,
	__rrr_net_transport_quic_close,
	NULL,
	__rrr_net_transport_quic_read,
	__rrr_net_transport_quic_receive,
	__rrr_net_transport_quic_stream_open,
	NULL,
	__rrr_net_transport_quic_poll,
	__rrr_net_transport_quic_handshake,
	__rrr_net_transport_quic_is_tls,
	__rrr_net_transport_quic_selected_proto_get
};

int rrr_net_transport_quic_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length,
		int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS),
		void *stream_open_callback_arg
) {
	if ((rrr_net_transport_tls_common_new (
			target,
			flags,
			certificate_file,
			private_key_file,
			ca_file,
			ca_path,
			alpn_protos,
			alpn_protos_length
	)) != 0) {
		return 1;
	}

	rrr_openssl_global_register_user();

	(*target)->methods = &tls_methods;
	(*target)->ssl_client_method = TLS_client_method();
	(*target)->ssl_server_method = TLS_server_method();
	(*target)->stream_open_callback = stream_open_callback;
	(*target)->stream_open_callback_arg = stream_open_callback_arg;

	return 0;
}
