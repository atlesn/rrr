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

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "../log.h"
#include "../allocator.h"

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_openssl.h"
#include "net_transport_openssl_common.h"
#include "net_transport_tls_common.h"
#include "net_transport_common.h"

#include "../socket/rrr_socket.h"
#include "../rrr_openssl.h"
#include "../rrr_strerror.h"
#include "../read.h"
#include "../read_constants.h"
#include "../ip/ip.h"
#include "../ip/ip_util.h"
#include "../ip/ip_accept_data.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"

struct in6_addr;

static int __rrr_net_transport_openssl_ssl_data_close (struct rrr_net_transport_handle *handle) {
	rrr_net_transport_openssl_common_ssl_data_destroy (handle->submodule_private_ptr);
	return 0;
}

static int __rrr_net_transport_openssl_pre_destroy (
		RRR_NET_TRANSPORT_PRE_DESTROY_ARGS
) {
	(void)(submodule_private_ptr);

	return handle->application_pre_destroy != NULL
		? handle->application_pre_destroy(handle, application_private_ptr)
		: 0
	;
}

static void __rrr_net_transport_openssl_destroy (
		RRR_NET_TRANSPORT_DESTROY_ARGS
) {
	rrr_openssl_global_unregister_user();

	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;
	rrr_net_transport_tls_common_destroy(tls);
}

static void __rrr_net_transport_openssl_dump_enabled_ciphers(SSL *ssl) {
	STACK_OF(SSL_CIPHER) *sk = SSL_get1_supported_ciphers(ssl);

	RRR_MSG_1("== DUMP ENABLED TLS/SSL CIPHERS ===================\n");

	for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);

		const char *name = SSL_CIPHER_get_name(c);
		if (name == NULL) {
			break;
		}

		RRR_MSG_1("%s%s", (i == 0 ? "" : ":"), name);
	}

	RRR_MSG_1("== END DUMP ENABLED TLS/SSL CIPHERS ===============\n");

	sk_SSL_CIPHER_free(sk);
}

struct rrr_net_transport_openssl_connect_callback_data {
	struct rrr_net_transport_tls *tls;
	struct rrr_ip_accept_data *accept_data;
	unsigned int port;
	const char *host;
};

const char *__rrr_net_transport_openssl_ssl_version_to_str (
	long int version
) {
	const char *result = "";
	switch (version) {
#ifdef HAVE_TLS1_3_VERSION
		case TLS1_3_VERSION:
			result = "TLSv1.3";
			break;
#endif
#ifdef HAVE_TLS1_2_VERSION
		case TLS1_2_VERSION:
			result = "TLSv1.2";
			break;
#endif
		case TLS1_1_VERSION:
			result = "TLSv1.1";
			break;
		case TLS1_VERSION:
			result = "TLSv1";
			break;
		case SSL3_VERSION:
			result = "SSLv3";
			break;
		case SSL2_VERSION:
			result = "SSLv2";
			break;
		case 0:
			result = "auto";
			break;
		default:
			result = "unknown";
			break;
	};
	return result;
}

int __rrr_net_transport_openssl_connect_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_openssl_connect_callback_data *callback_data = arg;
	struct rrr_net_transport_tls *tls = callback_data->tls;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	struct rrr_net_transport_tls_data *ssl_data = NULL;
	if ((ssl_data = rrr_net_transport_openssl_common_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_openssl_connect_callback\n");
		ret = 1;
		goto out_final;
	}

	if (rrr_net_transport_openssl_common_new_ctx (
			&ssl_data->o_ctx,
			tls->ssl_client_method,
			tls->flags_tls,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path,
			&tls->alpn
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_openssl_connect_callback");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	if ((ssl_data->web = BIO_new_ssl(ssl_data->o_ctx, 1)) == NULL) {
		RRR_SSL_ERR("Could not get BIO in __rrr_net_transport_openssl_connect_callback");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	SSL *ssl = NULL;
	BIO_get_ssl(ssl_data->web, &ssl);

	if (SSL_set_fd(ssl, callback_data->accept_data->ip_data.fd) != 1) {
		RRR_SSL_ERR("Could not set FD for SSL in __rrr_net_transport_openssl_connect_callback\n");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	if (SSL_set_tlsext_host_name(ssl, callback_data->host) != 1) {
		RRR_SSL_ERR("Could not set TLS hostname");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	if (SSL_set_max_proto_version(ssl, TLS1_3_VERSION) != 1) {
		RRR_SSL_ERR("Could set SSL protocol version");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	// Not used for TLSv1.3
	//const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
	if (SSL_set_cipher_list(ssl, "DEFAULT") != 1) {
		RRR_SSL_ERR("Could not set TLS cipher list");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	if (RRR_DEBUGLEVEL_1) {
		__rrr_net_transport_openssl_dump_enabled_ciphers(ssl);

		long int max_version = SSL_get_max_proto_version(ssl);
		long int min_version = SSL_get_min_proto_version(ssl);

		RRR_MSG_1("SSL max/min protocol verison: %s(%li) >= x <= %s(%li)\n",
			__rrr_net_transport_openssl_ssl_version_to_str(max_version), max_version,
			__rrr_net_transport_openssl_ssl_version_to_str(min_version), min_version
		);
	}

	// Set non-blocking I/O
	BIO_set_nbio(ssl_data->web, 1); // Always returns 1

	SSL_set_connect_state(ssl);

	*submodule_private_ptr = ssl_data;
	*submodule_fd = callback_data->accept_data->ip_data.fd;

	// Set this data, including FD at the end. Caller will try to close the FD
	// upon errors from this function, and we wish to avoid double close() as
	// the FD will attempted to be closed by the destroy function below.
	ssl_data->sockaddr = callback_data->accept_data->addr;
	ssl_data->socklen = callback_data->accept_data->len;
	ssl_data->ip_data = callback_data->accept_data->ip_data;

	goto out_final;
	out_destroy_ssl_data:
		rrr_net_transport_openssl_common_ssl_data_destroy(ssl_data);
	out_final:
		return ret;
}

static int __rrr_net_transport_openssl_connect (
		RRR_NET_TRANSPORT_CONNECT_ARGS
) {
	struct rrr_ip_accept_data *accept_data = NULL;

	if (*socklen < sizeof(accept_data->addr)) {
		RRR_BUG("BUG: socklen too small in __rrr_net_transport_openssl_connect\n");
	}

	*handle = 0;

	int ret = 0;

	if (rrr_ip_network_connect_tcp_ipv4_or_ipv6(&accept_data, port, host) != 0) {
		RRR_DBG_3("Could not create TCP connection to %s:%u for TLS usage\n", host, port);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	struct rrr_net_transport_openssl_connect_callback_data callback_data = {
		(struct rrr_net_transport_tls *) transport,
		accept_data,
		port,
		host
	};

	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			"ossl outbound",
			NULL,
			NULL,
			__rrr_net_transport_openssl_connect_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_openssl_connect return was %i\n", ret);
		ret = 1;
		goto out_destroy_ip;
	}

	memcpy(addr, &accept_data->addr, accept_data->len);
	*socklen = accept_data->len;

	*handle = new_handle;

	goto out;
	out_destroy_ip:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

struct rrr_net_transport_openssl_bind_and_listen_callback_data {
	struct rrr_net_transport_tls *tls;
	uint16_t port;
	int do_ipv6;
};

static int __rrr_net_transport_openssl_bind_and_listen_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_openssl_bind_and_listen_callback_data *callback_data = arg;
	struct rrr_net_transport_tls *tls = callback_data->tls;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	struct rrr_net_transport_tls_data *ssl_data = NULL;

	if ((ssl_data = rrr_net_transport_openssl_common_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_openssl_bind_and_listen_callback\n");
		ret = 1;
		goto out;
	}

	ssl_data->ip_data.port = callback_data->port;

	if (rrr_ip_network_start_tcp (&ssl_data->ip_data, 10, callback_data->do_ipv6) != 0) {
		RRR_DBG_1("Note: Could not start IP listening in __rrr_net_transport_openssl_bind_and_listen_callback\n");
		ret = 1;
		goto out_free_ssl_data;
	}

	if (rrr_net_transport_openssl_common_new_ctx (
			&ssl_data->o_ctx,
			tls->ssl_server_method,
			tls->flags_tls,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path,
			&tls->alpn
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_openssl_bind_and_listen_callback");
		ret = 1;
		goto out_destroy_ip;
	}

	*submodule_private_ptr = ssl_data;
	*submodule_fd = ssl_data->ip_data.fd;

	goto out;
//	out_destroy_ctx:
//		SSL_CTX_free(ssl_data->o_ctx);
	out_destroy_ip:
		rrr_ip_close(&ssl_data->ip_data);
	out_free_ssl_data:
		RRR_FREE_IF_NOT_NULL(ssl_data);
	out:
		return ret;
}

static int __rrr_net_transport_openssl_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	int ret = 0;

	if (tls->certificate_file == NULL || tls->private_key_file == NULL) {
		RRR_MSG_0("Certificate file and/or private key file not set while attempting to start TLS listening server\n");
		ret = 1;
		goto out;
	}

	struct rrr_net_transport_openssl_bind_and_listen_callback_data callback_data = {
		tls,
		port,
		do_ipv6
	};

	rrr_net_transport_handle new_handle;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
			"ossl listen",
			NULL,
			NULL,
			__rrr_net_transport_openssl_bind_and_listen_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	RRR_DBG_7("OpenSSL listening started on port %u transport handle %p/%i\n", port, transport, new_handle);

	ret = callback (
			transport,
			new_handle,
			callback_final,
			callback_final_arg,
			callback_arg
	);

	out:
	return ret;
}

struct rrr_net_transport_openssl_accept_callback_data {
	struct rrr_net_transport_tls *tls;
	struct rrr_ip_accept_data *accept_data;
};

static int __rrr_net_transport_openssl_accept_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_openssl_accept_callback_data *callback_data = arg;
	struct rrr_net_transport_tls *tls = callback_data->tls;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	struct rrr_net_transport_tls_data *ssl_data = NULL;

	if ((ssl_data = rrr_net_transport_openssl_common_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_openssl_accept_callback\n");
		ret = 1;
		goto out;
	}

	if (rrr_net_transport_openssl_common_new_ctx (
			&ssl_data->o_ctx,
			tls->ssl_server_method,
			tls->flags_tls,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path,
			&tls->alpn
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_openssl_accept_callback");
		ret = 1;
		goto out_destroy;
	}

	if ((ssl_data->web = BIO_new_ssl(ssl_data->o_ctx, 0)) == NULL) {
		RRR_SSL_ERR("Could not allocate BIO in __rrr_net_transport_openssl_accept_callback");
		ret = 1;
		goto out_destroy;
	}

	SSL *ssl;
	BIO_get_ssl(ssl_data->web, &ssl);

	if (SSL_set_fd(ssl, callback_data->accept_data->ip_data.fd) != 1) {
		RRR_SSL_ERR("Could not set FD for SSL in __rrr_net_transport_openssl_accept_callback");
		ret = 1;
		goto out_destroy;
	}

	BIO_set_nbio(ssl_data->web, 1);

	SSL_set_accept_state(ssl);

	// Set this data, including FD at the end. Caller will try to close the FD
	// upon errors from this function, and we wish to avoid double close() as
	// the FD will attempted to be closed by the destroy function below.
	ssl_data->sockaddr = callback_data->accept_data->addr;
	ssl_data->socklen = callback_data->accept_data->len;
	ssl_data->ip_data = callback_data->accept_data->ip_data;

	*submodule_private_ptr = ssl_data;
	*submodule_fd = ssl_data->ip_data.fd;

	goto out;
	out_destroy:
		rrr_net_transport_openssl_common_ssl_data_destroy(ssl_data);
	out:
		return ret;
}

int __rrr_net_transport_openssl_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	struct rrr_ip_accept_data *accept_data = NULL;
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) listen_handle->transport;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	struct rrr_net_transport_tls_data *listen_ssl_data = listen_handle->submodule_private_ptr;

	if ((ret = rrr_ip_accept(&accept_data, &listen_ssl_data->ip_data, "net_transport_tls", 0)) != 0) {
		RRR_MSG_0("Error while accepting connection in TLS server\n");
		ret = 1;
		goto out;
	}

	if (accept_data == NULL) {
		goto out;
	}

	struct rrr_net_transport_openssl_accept_callback_data callback_data = {
		tls,
		accept_data
	};

	if ((ret = rrr_net_transport_handle_allocate_and_add (
			new_handle,
			listen_handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			"ossl accept",
			NULL,
			NULL,
			__rrr_net_transport_openssl_accept_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_openssl_accept return was %i\n", ret);
		goto out_destroy_ip;
	}

	{
		char buf[128];
		rrr_ip_to_str(buf, sizeof(buf), (const struct sockaddr *) &accept_data->addr, accept_data->len);
		RRR_DBG_7("OpenSSL accepted connection on port %u from %s transport handle %p/%i\n",
				listen_ssl_data->ip_data.port, buf, listen_handle->transport, new_handle);
	}

	ret = callback (
			listen_handle->transport,
			*new_handle,
			(struct sockaddr *) &accept_data->addr,
			accept_data->len,
			final_callback,
			final_callback_arg,
			callback_arg
	);

	goto out;

	out_destroy_ip:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

static int __rrr_net_transport_openssl_read_raw (
		char *buf,
		rrr_biglength *read_bytes,
		struct rrr_net_transport_tls_data *ssl_data,
		rrr_biglength read_step_max_size
) {
	int ret = RRR_READ_OK;

	if (read_step_max_size > INT_MAX) {
		read_step_max_size = INT_MAX;
	}

	ssize_t result = BIO_read(ssl_data->web, buf, (int) read_step_max_size);
	if (result <= 0) {
		if (BIO_should_retry(ssl_data->web) == 0) {
//			int reason = BIO_get_retry_reason(ssl_data->web);
			RRR_SSL_DBG_3("Error while reading from TLS connection, possible close of connection");
			// Possible close of connection
			ret = RRR_READ_EOF;
			goto out;
		}
		ret = rrr_socket_check_alive((int) BIO_get_fd(ssl_data->web, NULL), 0 /* Not silent */);
		goto out;
	}
	else if (ERR_peek_error() != 0) {
		RRR_SSL_ERR("Error while reading in __rrr_net_transport_openssl_read_raw");
		return RRR_READ_SOFT_ERROR;
	}

	out:
	ERR_clear_error();
	*read_bytes = (result >= 0 ? (rrr_biglength) result : 0);
	return ret;
}

static int __rrr_net_transport_openssl_read_read (
		char *buf,
		rrr_biglength *read_bytes,
		rrr_biglength read_step_max_size,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	struct rrr_net_transport_tls_data *ssl_data = callback_data->handle->submodule_private_ptr;

	return __rrr_net_transport_openssl_read_raw (buf, read_bytes, ssl_data, read_step_max_size);
}

static int __rrr_net_transport_openssl_read_message (
		RRR_NET_TRANSPORT_READ_MESSAGE_ARGS
) {
	int ret = 0;

	*bytes_read = 0;

	struct rrr_net_transport_read_callback_data read_callback_data = {
		handle,
		get_target_size,
		get_target_size_arg,
		get_target_size_error,
		get_target_size_error_arg,
		complete_callback,
		complete_callback_arg
	};

	uint64_t bytes_read_tmp = 0;
	ret = rrr_read_message_using_callbacks (
			&bytes_read_tmp,
			read_step_initial,
			read_step_max_size,
			read_max_size,
			RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			RRR_LL_FIRST(&handle->read_sessions),
			ratelimit_interval_us,
			ratelimit_max_bytes,
			rrr_net_transport_common_read_get_target_size,
			rrr_net_transport_common_read_get_target_size_error_callback,
			rrr_net_transport_common_read_complete_callback,
			__rrr_net_transport_openssl_read_read,
			rrr_net_transport_tls_common_read_get_read_session_with_overshoot,
			rrr_net_transport_tls_common_read_get_read_session,
			rrr_net_transport_tls_common_read_remove_read_session,
			NULL,
			&read_callback_data
	);
	*bytes_read += bytes_read_tmp;

	if ( ret == RRR_NET_TRANSPORT_READ_OK ||
	     ret == RRR_NET_TRANSPORT_READ_RATELIMIT ||
	     ret == RRR_NET_TRANSPORT_READ_READ_EOF ||
	     ret == RRR_NET_TRANSPORT_READ_SOFT_ERROR ||
	     ret == RRR_NET_TRANSPORT_READ_INCOMPLETE
	) {
		// OK, no message printed
	}
	else {
		RRR_MSG_0("Error %i while reading from remote in %s\n", ret, __func__);
	}

	return ret;
}

static int __rrr_net_transport_openssl_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	int ret = RRR_NET_TRANSPORT_READ_OK;

	if (buf_size > SSIZE_MAX) {
		RRR_MSG_0("Buffer size too large in __rrr_net_transport_openssl_read\n");
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	ret = __rrr_net_transport_openssl_read_raw(buf, bytes_read, handle->submodule_private_ptr, buf_size);

	if (ret == RRR_NET_TRANSPORT_READ_OK && *bytes_read == 0) {
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
	}

	out:
	return ret;
}

static int __rrr_net_transport_openssl_send (
		RRR_NET_TRANSPORT_SEND_ARGS
) {
	struct rrr_net_transport_tls_data *ssl_data = handle->submodule_private_ptr;

	*bytes_written = 0;

	if (size > INT_MAX) {
		size = INT_MAX;
	}

	ssize_t bytes_written_tmp;
	if ((bytes_written_tmp = BIO_write(ssl_data->web, data, (int) size)) <= 0) {
		if (BIO_should_retry(ssl_data->web)) {
			return RRR_NET_TRANSPORT_SEND_INCOMPLETE;
		}
		return RRR_NET_TRANSPORT_SEND_HARD_ERROR;
	}
	else {
		*bytes_written = (rrr_biglength) bytes_written_tmp;
	}

	return RRR_NET_TRANSPORT_SEND_OK;
}

static int __rrr_net_transport_openssl_selected_proto_get (
		RRR_NET_TRANSPORT_SELECTED_PROTO_GET_ARGS
) {
	struct rrr_net_transport_tls_data *ssl_data = handle->submodule_private_ptr;

	SSL *ssl = NULL;
	BIO_get_ssl(ssl_data->web, &ssl);

	return rrr_net_transport_openssl_common_alpn_selected_proto_get (proto, ssl);
}

static int __rrr_net_transport_openssl_poll (
		RRR_NET_TRANSPORT_POLL_ARGS
) {
	struct rrr_net_transport_tls_data *ssl_data = handle->submodule_private_ptr;

	int fd = (int) BIO_get_fd(ssl_data->web, NULL);
	if (fd < 0) {
		return RRR_NET_TRANSPORT_READ_SOFT_ERROR;
	}

	if (rrr_socket_check_alive (fd, 0 /* Not silent */) != 0) {
		return RRR_READ_EOF;
	}

	return RRR_READ_OK;
}

static int __rrr_net_transport_openssl_handshake (
		RRR_NET_TRANSPORT_HANDSHAKE_ARGS
) {
	struct rrr_net_transport_tls_data *ssl_data = handle->submodule_private_ptr;

	SSL *ssl;
	BIO_get_ssl(ssl_data->web, &ssl);

	int ret_tmp;
	if ((ret_tmp = SSL_do_handshake(ssl)) != 1) {
		if (BIO_should_retry(ssl_data->web) || SSL_want_read(ssl) || SSL_want_write(ssl)) {
			return RRR_NET_TRANSPORT_SEND_INCOMPLETE;
		}
		if (ret_tmp < 0) {
			RRR_MSG_0("Fatal error during handshake (possible certificate expiration): %i\n", SSL_get_error(ssl, ret_tmp));
			switch (SSL_get_error(ssl, ret_tmp)) {
				case SSL_ERROR_NONE:
					RRR_BUG("Invalid return value SSL_ERROR_NONE in %s\n", __func__);
					break;
				case SSL_ERROR_ZERO_RETURN:
					RRR_MSG_0("SSL_ERROR_ZERO_RETURN while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_READ:
					RRR_MSG_0("SSL_ERROR_WANT_READ while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_WRITE:
					RRR_MSG_0("SSL_ERROR_WANT_WRITE while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_CONNECT:
					RRR_MSG_0("SSL_ERROR_WANT_CONNECT while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_ACCEPT:
					RRR_MSG_0("SSL_ERROR_WANT_ACCEPT while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_X509_LOOKUP:
					RRR_MSG_0("SSL_ERROR_WANT_X509_LOOKUP while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_ASYNC:
					RRR_MSG_0("SSL_ERROR_WANT_ASYNC while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_WANT_ASYNC_JOB:
					RRR_MSG_0("SSL_ERROR_WANT_ASYNC_JOB while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_SYSCALL:
					RRR_MSG_0("SSL_ERROR_SYSCALL while handshaking in OpenSSL\n");
					break;
				case SSL_ERROR_SSL:
					RRR_SSL_ERR("Handshake failure");
					break;
				default:
					RRR_MSG_0("Unknown error during handshake: %i\n", SSL_get_error(ssl, ret_tmp));
					break;
			};
		}
		else {
			RRR_SSL_ERR("Handshake failure");
		}
		return RRR_NET_TRANSPORT_SEND_SOFT_ERROR;
	}

	if (!SSL_is_server(ssl)) {
		// TODO : Hostname verification
#ifdef RRR_HAVE_GET1_PEER_CERTIFICATE
		X509 *cert = SSL_get1_peer_certificate(ssl);
#else
		X509 *cert = SSL_get_peer_certificate(ssl);
#endif
		if (cert != NULL) {
			X509_free(cert);
		}
		else {
			RRR_MSG_0("No certificate received in TLS handshake fd %i\n",
					handle->submodule_fd);
			return RRR_NET_TRANSPORT_SEND_SOFT_ERROR;
		}
	}

	long verify_result = 0;
	if ((verify_result = SSL_get_verify_result(ssl)) != X509_V_OK) {
		RRR_MSG_0("Certificate verification failed for fd %i with reason %li\n",
				handle->submodule_fd, verify_result);
		return RRR_NET_TRANSPORT_SEND_SOFT_ERROR;
	}

	return RRR_NET_TRANSPORT_SEND_OK;
}

static int __rrr_net_transport_openssl_is_tls (void) {
	return 1;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_openssl_destroy,
	__rrr_net_transport_openssl_connect,
	NULL,
	__rrr_net_transport_openssl_bind_and_listen,
	NULL,
	NULL,
	__rrr_net_transport_openssl_accept,
	__rrr_net_transport_openssl_ssl_data_close,
	__rrr_net_transport_openssl_pre_destroy,
	__rrr_net_transport_openssl_read_message,
	__rrr_net_transport_openssl_read,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	__rrr_net_transport_openssl_send,
	__rrr_net_transport_openssl_poll,
	__rrr_net_transport_openssl_handshake,
	__rrr_net_transport_openssl_is_tls,
	__rrr_net_transport_openssl_selected_proto_get
};

int rrr_net_transport_openssl_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
	if ((rrr_net_transport_tls_common_new (
			target,
			flags,
			0,
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
