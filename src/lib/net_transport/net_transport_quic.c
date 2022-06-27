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

#define RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH 18
#define RRR_NET_TRANSPORT_QUIC_KEEPALIVE_S 10
#define RRR_NET_TRANSPORT_QUIC_CIPHERS \
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define RRR_NET_TRANSPORT_QUIC_GROUPS \
    "P-256:X25519:P-384:P-521"

// Enable printf logging in ngtcp2 library
#define RRR_NET_TRANSPORT_QUIC_NGTCP2_DEBUG 1

struct rrr_net_transport_quic_ctx {
	SSL *ssl;

	struct rrr_net_transport_handle *listen_handle;

	ngtcp2_conn *conn;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_path path;
	ngtcp2_connection_close_error last_error;
	ngtcp2_transport_params transport_params;

	struct sockaddr_storage addr_remote;
	socklen_t addr_remote_len;
	struct sockaddr_storage addr_local;
	socklen_t addr_local_len;

	char *alpn_selected_proto;
};

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

static int __rrr_net_transport_quic_ctx_new (
		struct rrr_net_transport_quic_ctx **target,
		struct rrr_net_transport_handle *listen_handle,
    		struct rrr_net_transport_connection_id_pair *connection_ids_new,
    		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const uint32_t client_chosen_version,
		const struct sockaddr *addr_remote,
		socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		socklen_t addr_local_len
) {
	struct rrr_net_transport_tls_data *listen_tls_data = listen_handle->submodule_private_ptr;

	int ret = 0;

	*target = NULL;

	int ret_tmp;
	struct rrr_net_transport_quic_ctx *ctx = NULL;

	if ((ctx = rrr_allocate_zero(sizeof(*ctx))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	assert(sizeof(ctx->addr_remote) >= addr_remote_len);
	memcpy(&ctx->addr_remote, addr_remote, addr_remote_len);
	ctx->addr_remote_len = addr_remote_len;

	assert(sizeof(ctx->addr_local) >= addr_local_len);
	memcpy(&ctx->addr_local, addr_local, addr_local_len);
	ctx->addr_local_len = addr_local_len;

	ctx->listen_handle = listen_handle;

	const ngtcp2_path path = {
		{
			(struct sockaddr *) &ctx->addr_local,
			ctx->addr_local_len
		}, {
			(struct sockaddr *) &ctx->addr_remote,
			ctx->addr_remote_len
		},
		NULL
	};

	{
		char buf_addr[128];
		char buf_scid[sizeof(connection_ids->src.data) * 2 + 1];

		rrr_ip_to_str(buf_addr, sizeof(buf_addr), (const struct sockaddr *) path.remote.addr, path.remote.addrlen);
		rrr_net_transport_connection_id_to_str(buf_scid, sizeof(buf_scid), &connection_ids->src);

		RRR_DBG_7("net transport quic fd %i new ctx src %s scid %s\n",
				listen_handle->submodule_fd, buf_addr, buf_scid);
	}

	ngtcp2_cid scid, dcid;

	// New source connection ID is randomly generated
	assert(sizeof(scid.data) >= NGTCP2_MAX_CIDLEN);
	rrr_random_bytes(&scid.data, NGTCP2_MAX_CIDLEN);
	scid.datalen = NGTCP2_MAX_CIDLEN;

	// Store new and original connection ID as expected future destination from client
	__rrr_net_transport_quic_ngtcp2_cid_to_connection_id(&connection_ids_new->a, &scid);
	connection_ids_new->b = connection_ids->dst;

	// New destination connection ID is source connection ID from client
	__rrr_net_transport_quic_connection_id_to_ngtcp2_cid(&dcid, &connection_ids->src);

	// Copy and modify transport parameters
	ctx->transport_params = listen_tls_data->transport_params;
	// TODO : handle retry
	__rrr_net_transport_quic_connection_id_to_ngtcp2_cid(&ctx->transport_params.original_dcid, &connection_ids->dst);

	if ((ret_tmp = ngtcp2_conn_server_new (
			&ctx->conn,
			&dcid,
			&scid,
			&path,
			client_chosen_version,
			listen_tls_data->callbacks,
			&listen_tls_data->settings,
			&ctx->transport_params,
			&rrr_net_transport_quic_ngtcp2_mem,
			ctx
	)) != 0) {
		RRR_MSG_0("Could not create ngtcp2 connection in %s: %s\n",
			__func__, ngtcp2_strerror(ret_tmp));
		ret = 1;
		goto out_free;
	}

	if ((ctx->ssl = SSL_dup(listen_tls_data->ssl)) == NULL) {
		RRR_SSL_ERR("Could not allocate SSL in QUIC");
		ret = 1;
		goto out_destroy_conn;
	}

	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->ssl);
	ngtcp2_connection_close_error_default(&ctx->last_error);

	ctx->conn_ref.user_data = ctx;
	ctx->conn_ref.get_conn = __rrr_net_transport_quic_cb_get_conn;

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

static void __rrr_net_transport_quic_ctx_destroy (
		struct rrr_net_transport_quic_ctx *ctx
) {
	SSL_free(ctx->ssl);
	ngtcp2_conn_del(ctx->conn);
	rrr_free(ctx);
}

static int __rrr_net_transport_quic_close (struct rrr_net_transport_handle *handle) {
	if (handle->mode == RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		assert(handle->submodule_fd == -1);
		printf("Quic close ctx data %p\n", handle->submodule_private_ptr);
		__rrr_net_transport_quic_ctx_destroy(handle->submodule_private_ptr);
	}
	else if (handle->mode == RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
		assert(handle->submodule_fd > 0);
		printf("Quic close listen data %p\n", handle->submodule_private_ptr);
		rrr_net_transport_openssl_common_ssl_data_destroy (handle->submodule_private_ptr);
	}
	else {
		assert(0);
	}
	return 0;
}

static void __rrr_net_transport_quic_destroy (
		RRR_NET_TRANSPORT_DESTROY_ARGS
) {
	rrr_openssl_global_unregister_user();

	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;
	rrr_net_transport_tls_common_destroy(tls);
}

static int __rrr_net_transport_quic_connect (
		RRR_NET_TRANSPORT_CONNECT_ARGS
) {
	(void)(handle);
	(void)(addr);
	(void)(socklen);
	(void)(transport);
	(void)(port);
	(void)(host);
	printf("Connect\n");
	return 1;
}

static int my_ngtcp2_cb_handshake_complete (ngtcp2_conn *conn, void *user_data) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	printf("Handshake complete\n");

	ngtcp2_conn_set_keep_alive_timeout(conn, (ngtcp2_duration) RRR_NET_TRANSPORT_QUIC_KEEPALIVE_S * 1000 * 1000 * 1000);

	return 0;
}

static int my_ngtcp2_cb_receive_stream_data (
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

	size_t consumed = 0;

	printf("Receive stream data: %llu - %s fin %i\n", (unsigned long long) buflen, buf, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
/*
	if (ctx->cb_deliver_data (
			&consumed,
			stream_id,
			buf,
			buflen,
			(flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0,
			ctx->cb_arg
	) != 0) {
		return 1;
	}
*/
	// NGTCP2_ERR_CALLBACK_FAILURE / ngtcp2_conection_close_error_set_application_error

	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed);
	ngtcp2_conn_extend_max_offset(conn, consumed);

	return 0;
}

static int my_ngtcp2_cb_acked_stream_data_offset (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t offset,
		uint64_t datalen,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(ctx);
	(void)(conn);
	(void)(offset);
	(void)(stream_user_data);

	printf("ACK from remote Stream %lli, %llu bytes \n", (long long int) stream_id, (unsigned long long) datalen);

	// nghttp3_conn_add_ack_offset(m stream_id, datalen);
	// NGTCP2_ERR_CALLBACK_FAILURE / ngtcp2_conection_close_error_set_application_error
	return 0;
}

static int my_ngtcp2_cb_stream_close (
		ngtcp2_conn *conn,
		uint32_t flags,
		int64_t stream_id,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
		// app_error_close = NGHTTP3_H3_NO_ERROR;
	}

	printf("Close stream %li\n", stream_id);

	return 0;
}
/*
static int my_ngtcp2_cb_extend_max_local_streams_bidi (
		ngtcp2_conn *conn,
		uint64_t max_streams,
		void *user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);

	printf("Extend max streams: %llu\n", (unsigned long long) max_streams);

	if (ctx->cb_ready != NULL && ctx->cb_ready(ctx->cb_arg) != 0) {
		return 1;
	}

	// Call only once
	ctx->cb_ready = NULL;
	return 0;
}
*/

static void my_ngtcp2_cb_random (
		uint8_t *dest,
		size_t destlen,
		const ngtcp2_rand_ctx *rand_ctx
) {
	(void)(rand_ctx);
	rrr_random_bytes(dest, destlen);
}

static int my_ngtcp2_cb_get_new_connection_id (
		ngtcp2_conn *conn,
		ngtcp2_cid *cid,
		uint8_t *token,
		size_t cidlen,
		void *user_data
) {
	(void)(conn);
	(void)(user_data);

	cid->datalen = cidlen;
	rrr_random_bytes(&cid->data, cidlen);
	rrr_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

	return 0;
}

static int my_ngtcp2_cb_remove_connection_id (
		ngtcp2_conn *conn,
		const ngtcp2_cid *cid,
		void *user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;


}

static int my_ngtcp2_cb_stream_reset (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t final_size,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(final_size);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	printf("Stream reset\n");

	// NGTCP2_ERR_CALLBACK_FAILURE - nghttp3_conn_shutdown_stream_read
	
	return 0;
}

static int my_ngtcp2_cb_extend_max_stream_data (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t max_data,
		void *user_data,
		void *stream_user_data
) {
	struct rrr_net_transport_quic_ctx *ctx = user_data;

	(void)(conn);
	(void)(max_data);
	(void)(stream_user_data);

	printf("Extend max stream data stream %lli\n", (long long int) stream_id);

//	if (ctx->cb_ready != NULL && ctx->cb_block_stream(stream_id, 0 /* Unblock */, ctx->cb_arg) != 0) {
//		return 1;
//	}

	return 0;
}

/*
static int my_ngtcp2_cb_stream_stop_sending (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	printf("Stop sending\n");

	// NGTCP2_ERR_CALLBACK_FAILURE - nghttp3_conn_shutdown_stream_read

	return 0;
}
*/
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

	struct rrr_net_transport_tls_data *tls_data = NULL;

	if ((tls_data = rrr_net_transport_openssl_common_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (rrr_net_transport_openssl_common_new_ctx (
			&tls_data->ctx,
			tls->ssl_server_method,
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

	SSL_set_accept_state(tls_data->ssl);
	SSL_set_quic_use_legacy_codepoint(tls_data->ssl, 0);

	SSL_set_alpn_protos (
			tls_data->ssl,
			(const uint8_t *) callback_data->tls->alpn.protos,
			(unsigned int) callback_data->tls->alpn.length
	);
	// SSL_set_tlsext_host_name(ssl, name_remote); - Not needed for server?
	SSL_set_quic_transport_version(tls_data->ssl, TLSEXT_TYPE_quic_transport_parameters);

	// Set ngtcp2 settings
	ngtcp2_settings_default(&tls_data->settings);
#ifdef RRR_NET_TRANSPORT_QUIC_NGTCP2_DEBUG
	tls_data->settings.log_printf = __rrr_net_transport_quic_cb_printf;
#else
	(void)(__rrr_net_transport_quic_cb_printf);
#endif

	// Set ngtcp2 transport parameters
	ngtcp2_transport_params_default(&tls_data->transport_params);
	tls_data->transport_params.initial_max_stream_data_bidi_local = 128 * 1024;
	tls_data->transport_params.initial_max_stream_data_bidi_remote = 128 * 1024;
	tls_data->transport_params.initial_max_stream_data_uni = 128 * 1024;
	tls_data->transport_params.initial_max_data = 1024 * 1024;
	tls_data->transport_params.initial_max_streams_bidi = 100;
	tls_data->transport_params.initial_max_streams_uni = 0;

	if (rrr_time_get_64_nano(&tls_data->settings.initial_ts, NGTCP2_SECONDS) != 0) {
		goto out_destroy;
	}

	static const ngtcp2_callbacks callbacks = {
		NULL, /* client_initial */
		ngtcp2_crypto_recv_client_initial_cb,
		ngtcp2_crypto_recv_crypto_data_cb,
		my_ngtcp2_cb_handshake_complete,
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		my_ngtcp2_cb_receive_stream_data,
		my_ngtcp2_cb_acked_stream_data_offset,
		NULL, /* stream_open */
		my_ngtcp2_cb_stream_close,
		NULL, /* recv_stateless_reset */
		NULL, /* recv_retry */
		NULL, /* extend_max_local_streams_bidi */
		NULL, /* extend_max_local_streams_uni */
		my_ngtcp2_cb_random,
		my_ngtcp2_cb_get_new_connection_id,
		my_ngtcp2_cb_remove_connection_id,
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_addr */
		my_ngtcp2_cb_stream_reset,
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		my_ngtcp2_cb_extend_max_stream_data,
		NULL, /* dcid_status */
		NULL, /* handshake_confirmed */
		NULL, /* recv_new_token */
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, /* recv_datagram */
		NULL, /* ack_datagram */
		NULL, /* lost_datagram */
		ngtcp2_crypto_get_path_challenge_data_cb,
		NULL, /* stream_stop_sending */
		ngtcp2_crypto_version_negotiation_cb,
		NULL, /* recv_rx_key */
		NULL  /* recv_tx_key */
	};

	printf("Bind and listen port %u\n", callback_data->ip_data->port);

	tls_data->callbacks = &callbacks;
	tls_data->ip_data = *callback_data->ip_data;

	*submodule_private_ptr = tls_data;
	*submodule_fd = callback_data->ip_data->fd;

	goto out;
	out_destroy:
		rrr_net_transport_openssl_common_ssl_data_destroy(tls_data);
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

	RRR_DBG_7("QUIC started on port %u IPv%s transport handle %p/%i\n", port, do_ipv6 ? "6" : "4", transport, new_handle);

	ret = callback(transport, new_handle, callback_final, callback_final_arg, callback_arg);

	goto out;
	out_destroy_ip:
		rrr_ip_close(&ip_data);
	out:
		return ret;
}
		
static int __rrr_net_transport_quic_send_version_negotiation (
		struct rrr_net_transport_handle *handle
) {
	RRR_BUG("Version negotiation\n");
	(void)(handle);
	// ngtcp2_pkt_write_version_negotiation
	return 1;
}

static int __rrr_net_transport_quic_decode (
		RRR_NET_TRANSPORT_DECODE_ARGS
) {
	struct rrr_net_transport_tls_data *tls_data = listen_handle->submodule_private_ptr;

	printf("Decode local port %u\n", tls_data->ip_data.port);

	int ret = 0;

	if ((ret = rrr_ip_recvmsg(datagram, &tls_data->ip_data, buf, buf_size)) != 0) {
		goto out;
	}

	uint32_t version;
	const uint8_t *dcid, *scid;
	size_t dcidlen, scidlen;

	printf("Decode msg len %lu\n", datagram->msg_len);

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
			RRR_DBG_7("fd %i failed to decode QUIC packet of size %llu\n",
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
		RRR_DBG_7("fd %i dcid too long in received QUIC packet (%llu>%llu)\n",
				listen_handle->submodule_fd, (long long unsigned) dcidlen, (long long unsigned) connection_ids->dst.length);
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
		goto out;
	}

	if (scidlen > connection_ids->src.length) {
		RRR_DBG_7("fd %i scid too long in received QUIC packet (%llu>%llu)\n",
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
};

static int __rrr_net_transport_quic_accept_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_quic_accept_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_net_transport_quic_ctx *ctx = NULL;

	struct rrr_net_transport_connection_id_pair connection_ids_new = {0};
	if ((ret = __rrr_net_transport_quic_ctx_new (
			&ctx,
			callback_data->listen_handle,
			&connection_ids_new,
			connection_ids,
			callback_data->client_chosen_version,
			(const struct sockaddr *) &datagram->addr_remote,
			datagram->addr_remote_len,
			(const struct sockaddr *) &datagram->addr_local,
			datagram->addr_local_len
	)) != 0) {
		goto out;
	}

	assert(connection_ids_new->orig.length > 0);

	SSL_set_accept_state(ctx->ssl);

	{
		char buf_addr_remote[128];
		char buf_addr_local[128];
		char buf_scid[sizeof(connection_ids->src.data) * 2 + 1];

		rrr_ip_to_str(buf_addr_remote, sizeof(buf_addr_remote), (const struct sockaddr *) &ctx->addr_remote, ctx->addr_remote_len);
		rrr_ip_to_str(buf_addr_local, sizeof(buf_addr_local), (const struct sockaddr *) &ctx->addr_local, ctx->addr_local_len);
		rrr_net_transport_connection_id_to_str(buf_scid, sizeof(buf_scid), &connection_ids->src);

		RRR_DBG_7("net transport quic fd %i accepted connection from %s to %s scid %s\n",
				callback_data->listen_handle->submodule_fd, buf_addr_remote, buf_addr_local, buf_scid);
	}

	*submodule_private_ptr = ctx;
	*submodule_fd = -1; // Set to disable polling on events for this handle

	goto out;
	out:
		return ret;
}

static int __rrr_net_transport_quic_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	struct rrr_net_transport_tls_data *listen_ssl_data = listen_handle->submodule_private_ptr;

	int ret = 0;

	int ret_tmp;
	ngtcp2_pkt_hd pkt;

	if ((ret_tmp = ngtcp2_accept (&pkt, datagram->msg_iov.iov_base, datagram->msg_len)) < 0) {
		if (ret_tmp == NGTCP2_ERR_RETRY) {
			/* Packet is stored into dest */
			RRR_BUG("SEND RETRY");
		}
		else {
			/* Packet is not stored into dest */
			RRR_DBG_7("fd %i error while accepting QUIC packet: %s. Dropping it.\n", listen_handle->submodule_fd, ngtcp2_strerror(ret_tmp));
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
			goto out;
		}
	}

	printf("A pkn %li\n", pkt.pkt_num);

	struct rrr_net_transport_quic_accept_callback_data callback_data = {
		listen_handle,
		pkt.version
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

	ret = callback (
			listen_handle->transport,
			*new_handle,
			(struct sockaddr *) datagram->msg.msg_name,
			datagram->msg.msg_namelen,
			final_callback,
			final_callback_arg,
			callback_arg
	);

	out:
	return ret;
}

static int __rrr_net_transport_quic_read_message (
		RRR_NET_TRANSPORT_READ_MESSAGE_ARGS
) {
	(void)(bytes_read);
	(void)(handle);
	(void)(read_step_initial);
	(void)(read_step_max_size);
	(void)(read_max_size);
	(void)(ratelimit_interval_us);
	(void)(ratelimit_max_bytes);
	(void)(get_target_size);
	(void)(get_target_size_arg);
	(void)(get_target_size_error);
	(void)(get_target_size_error_arg);
	(void)(complete_callback);
	(void)(complete_callback_arg);
	printf("Read message\n");
	return 1;
}

static int my_ngtcp2_send_packet (
		evutil_socket_t fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const uint8_t *data,
		size_t data_size
) {
	ssize_t bytes_written = 0;

	printf("Sending %llu bytes\n", (unsigned long long) data_size);

	do {
		bytes_written = sendto(fd, data, data_size, 0, addr, addr_len);
	} while (bytes_written < 0 && errno == EINTR);

	if (bytes_written < 0) {
		printf("Error while sending: %s\n", rrr_strerror(errno));
		return 1;
	}

	if ((size_t) bytes_written < data_size) {
		printf("All bytes not written in %s\n", __func__);
		return 1;
	}

	return 0;
}
/*
int my_ngtcp2_get_message (
		struct my_ngtcp2_ctx *ctx,
		int64_t *stream_id,
		ngtcp2_vec *data_vector,
		size_t *data_vector_count,
		int *fin
) {
	int ret = 0;

	// Get message

	return ret;
}
*/
static uint64_t vec_len(const ngtcp2_vec *vec, size_t n) {
	size_t i;
	size_t res = 0;

	for (i = 0; i < n; ++i) {
		res += vec[i].len;
	}

	return res;
}

static int __rrr_net_transport_quic_write (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_quic_ctx *ctx = handle->submodule_private_ptr;

	char buf[1280];
	ngtcp2_vec data_vector[128] = {0};
	size_t data_vector_count = 0;
	ngtcp2_path_storage path_storage;
	ngtcp2_pkt_info packet_info = {0};
	int fin = 0;
	ngtcp2_ssize bytes_from_src = 0;
	ngtcp2_ssize bytes_to_buf = 0;
	uint64_t timestamp = 0;
	int64_t stream_id = -1;

	ngtcp2_path_storage_zero(&path_storage);

	printf("Write event\n");

	for (;;) {
		if (rrr_time_get_64_nano(&timestamp, NGTCP2_SECONDS) != 0) {
			goto out_failure;
		}

		printf("++ Loop\n");

		data_vector_count = sizeof(data_vector)/sizeof(*data_vector);
/*		if (my_ngtcp2_get_message (
					ctx,
					&stream_id,
					data_vector,
					&data_vector_count,
					&fin
		) != 0) {
			goto out_failure;
		}*/
		data_vector_count = 0;

		printf("Vector count %llu len %llu stream ID %lli fin %i\n",
				(unsigned long long) data_vector_count,
				(unsigned long long) vec_len(data_vector, data_vector_count),
				(long long int) stream_id,
				fin
		);

		if (!fin && stream_id == -1 && data_vector_count == 0) {
			printf("- No data from http3\n");
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

		printf("- Write out: %li, Write in: %li\n", bytes_to_buf, bytes_from_src);

		if (bytes_to_buf < 0) {
			if (bytes_to_buf == NGTCP2_ERR_STREAM_DATA_BLOCKED || bytes_to_buf == NGTCP2_ERR_STREAM_SHUT_WR) {
				printf("- Blocked\n");
		//		if (ctx->cb_block_stream(stream_id, 1 /* Blocked*/, ctx->cb_arg) != 0) {
		//			//		ngtcp2_connection_close_error_set_application_error();
		//			goto out_failure;
		//		}
			}
			else if (bytes_to_buf == NGTCP2_ERR_WRITE_MORE) {
				// Must call writev repeatedly until complete.
				assert(bytes_from_src >= 0);
				printf("- More\n");

		//		if (ctx->cb_ack_data(stream_id, bytes_from_src, ctx->cb_arg) != 0) {
		//			//		ngtcp2_connection_close_error_set_application_error();
		//			goto out_failure;
		//		}
			}
			else {
				printf("Error while writing: %s\n", ngtcp2_strerror((int) bytes_to_buf));
				goto out_failure;
			}
		}
		else if (bytes_to_buf == 0) {
			break;
		}

		if (bytes_to_buf > 0 && my_ngtcp2_send_packet (
					ctx->listen_handle->submodule_fd,
					(const struct sockaddr *) path_storage.path.remote.addr,
					path_storage.path.remote.addrlen,
					(const uint8_t *) buf,
					bytes_to_buf
		) != 0) {
			goto out_failure;
		}
	}

	return 0;

	out_failure:
	return RRR_NET_TRANSPORT_READ_HARD_ERROR;
}

static int __rrr_net_transport_quic_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	(void)(bytes_read);
	(void)(handle);
	(void)(buf);
	(void)(buf_size);

	// printf("Read buf size %lu\n", handle->datagram.size);
	printf("Read\n");

	return __rrr_net_transport_quic_write(handle);
}

static int __rrr_net_transport_quic_receive (
		RRR_NET_TRANSPORT_RECEIVE_ARGS
) {
	struct rrr_net_transport_quic_ctx *ctx = handle->submodule_private_ptr;

	int ret = 0;

	if (!ngtcp2_conn_get_handshake_completed(ctx->conn)) {
		if (ctx->addr_local_len != datagram->addr_local_len || memcmp(&ctx->addr_local, &datagram->addr_local, ctx->addr_local_len) != 0) {
			RRR_DBG_7("net transport quic fd %i h %i local address changed during handshake. Closing.\n",
				handle->submodule_fd, handle->handle);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}
		if (ctx->addr_remote_len != datagram->addr_remote_len || memcmp(&ctx->addr_remote, &datagram->addr_remote, ctx->addr_remote_len) != 0) {
			RRR_DBG_7("net transport quic fd %i h %i remote address changed during handshake. Closing.\n",
				handle->submodule_fd, handle->handle);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
			goto out;
		}
	}
	else {
		memcpy(&ctx->addr_local, &datagram->addr_local, datagram->addr_local_len);
		ctx->addr_local_len = datagram->addr_local_len;

		memcpy(&ctx->addr_remote, &datagram->addr_remote, datagram->addr_remote_len);
		ctx->addr_remote_len = datagram->addr_remote_len;
	}

	int ret_tmp;
	const ngtcp2_path path = {
		{
			(struct sockaddr *) &ctx->addr_local,
			ctx->addr_local_len
		}, {
			(struct sockaddr *) &ctx->addr_remote,
			ctx->addr_remote_len
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
	printf("Receive datagram size %lu max %lu flags %u\n", datagram->msg_len, datagram->msg_iov.iov_len, flags);

	if ((ret_tmp = ngtcp2_conn_read_pkt (
			ctx->conn,
			&path,
			&pi,
			datagram->msg_iov.iov_base,
			datagram->msg_len,
			timestamp
	)) != 0) {
		if (ret_tmp == NGTCP2_ERR_DRAINING) {
			printf("Connection was closed (now in draining state) while reading\n");
			ret = RRR_NET_TRANSPORT_READ_READ_EOF;
		}
		else if (ret_tmp == NGTCP2_ERR_CRYPTO) {
			printf("Crypto error while reading packet: %s\n", ngtcp2_strerror(ret_tmp));
			ngtcp2_connection_close_error_set_transport_error_tls_alert (
					&ctx->last_error,
					ngtcp2_conn_get_tls_alert(ctx->conn),
					NULL,
					0
			);
			ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		}
		else {
			printf("Transport error while reading packet: %s\n", ngtcp2_strerror(ret_tmp));
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

	if ((ret = __rrr_net_transport_quic_write(handle)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_net_transport_quic_send (
		RRR_NET_TRANSPORT_SEND_ARGS
) {
	(void)(bytes_written);
	(void)(handle);
	(void)(data);
	(void)(size);
	printf("Send\n");
	return 1;
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
	printf("Poll\n");
	return 1;
}

static int __rrr_net_transport_quic_handshake (
		RRR_NET_TRANSPORT_HANDSHAKE_ARGS
) {
	(void)(handle);
	return 0;
}

static int __rrr_net_transport_quic_is_tls (void) {
	return 1;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_quic_destroy,
	__rrr_net_transport_quic_connect,
	__rrr_net_transport_quic_bind_and_listen,
	__rrr_net_transport_quic_decode,
	__rrr_net_transport_quic_accept,
	__rrr_net_transport_quic_close,
	__rrr_net_transport_quic_read_message,
	__rrr_net_transport_quic_read,
	__rrr_net_transport_quic_receive,
	__rrr_net_transport_quic_send,
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
		unsigned int alpn_protos_length
) {
	if ((rrr_net_transport_tls_common_new(
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

	return 0;
}
