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

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "net_transport.h"
#include "net_transport_tls.h"

#include "../posix.h"
#include "../log.h"
#include "../socket/rrr_socket.h"
#include "../rrr_openssl.h"
#include "../rrr_strerror.h"
#include "../gnu.h"
#include "../read.h"
#include "../read_constants.h"
#include "../ip.h"
#include "../ip_accept_data.h"
#include "../macro_utils.h"

struct rrr_net_transport_tls_ssl_data {
	SSL_CTX *ctx;
	BIO *web;
	struct rrr_ip_data ip_data;
	struct sockaddr_storage sockaddr;
	socklen_t socklen;
	int handshake_complete;
};
struct in6_addr;
static void __rrr_net_transport_tls_ssl_data_destroy (struct rrr_net_transport_tls_ssl_data *ssl_data) {
	if (ssl_data != NULL) {
/*		if (ssl_data->out != NULL) {
			BIO_free(ssl_data->out);
		}*/
		if (ssl_data->web != NULL) {
			BIO_free_all(ssl_data->web);
		}
		if (ssl_data->ctx != NULL) {
			SSL_CTX_free(ssl_data->ctx);
		}
		if (ssl_data->ip_data.fd != 0) {
			rrr_ip_close(&ssl_data->ip_data);
		}

		free(ssl_data);
	}
}

static int __rrr_net_transport_tls_ssl_data_close (struct rrr_net_transport_handle *handle) {
	__rrr_net_transport_tls_ssl_data_destroy (handle->submodule_private_ptr);

	return 0;
}

static void __rrr_net_transport_tls_destroy (struct rrr_net_transport *transport) {
	// This will call back into our close() function for each handle
	rrr_net_transport_common_cleanup(transport);

	rrr_openssl_global_unregister_user();

	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	RRR_FREE_IF_NOT_NULL(tls->ca_path);
	RRR_FREE_IF_NOT_NULL(tls->ca_file);
	RRR_FREE_IF_NOT_NULL(tls->certificate_file);
	RRR_FREE_IF_NOT_NULL(tls->private_key_file);

	// Do not free here, upstream does that after destroying lock
}

static void __rrr_net_transport_tls_dump_enabled_ciphers(SSL *ssl) {
	STACK_OF(SSL_CIPHER) *sk = SSL_get1_supported_ciphers(ssl);

	RRR_MSG_0("Enabled ciphers: ");

	for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);

		const char *name = SSL_CIPHER_get_name(c);
		if (name == NULL) {
			break;
		}

		RRR_MSG_0("%s%s", (i == 0 ? "" : ":"), name);
	}

	RRR_MSG_0("\n");

	sk_SSL_CIPHER_free(sk);
}

static int __rrr_net_transport_tls_verify_always_ok (X509_STORE_CTX *x509, void *arg) {
	(void)(x509);
	(void)(arg);
	return 1;
}

struct rrr_net_transport_tls_ssl_data *__rrr_net_transport_tls_ssl_data_new (void) {
	struct rrr_net_transport_tls_ssl_data *ssl_data = NULL;

	if ((ssl_data = malloc(sizeof(*ssl_data))) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_ssl_data_new \n");
		return NULL;
	}
	memset (ssl_data, '\0', sizeof(*ssl_data));

	return ssl_data;
}

static int __rrr_net_transport_tls_new_ctx (
		SSL_CTX **target,
		const SSL_METHOD *method,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path
) {
	int ret = 0;

	*target = NULL;

	SSL_CTX *ctx = NULL;

	if (((certificate_file == NULL || *certificate_file == '\0') && (private_key_file != NULL && *private_key_file != '\0')) ||
		((private_key_file == NULL || *private_key_file == '\0') && (certificate_file != NULL && *certificate_file != '\0'))
	) {
		RRR_BUG("BUG: Certificate file and private key file must both be either set or unset in __rrr_net_transport_tls_new_ctx\n");
	}

	if ((ctx = SSL_CTX_new(method)) == NULL) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_tls_new_ctx ");
		ret = 1;
		goto out;
	}

	// NULL callback causes verification failure to cancel further processing
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);

	// Unused flag: SSL_OP_NO_TLSv1_2, we need to support 1.2
	// TODO : Apparently the version restrictions with set_options are deprecated
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);

	unsigned int min_version = TLS1_2_VERSION;
	if ((flags & RRR_NET_TRANSPORT_F_MIN_VERSION_TLS_1_1) != 0) {
		min_version = TLS1_1_VERSION;
	}

	if (SSL_CTX_set_min_proto_version(ctx, min_version) != 1) {
		RRR_SSL_ERR("Could not set minimum protocol version to TLSv1.2");
		ret = 1;
		goto out_destroy;
	}

	if ((ret = rrr_openssl_load_verify_locations(ctx, ca_file, ca_path)) != 0) {
		ret = 1;
		goto out_destroy;
	}

	// Disable verification if required
	if ((flags & RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY) != 0) {
		SSL_CTX_set_cert_verify_callback (ctx, __rrr_net_transport_tls_verify_always_ok, NULL);
	}

	if (certificate_file != NULL && *certificate_file != '\0') {
		RRR_DBG_1("Opening certificate chain file '%s'\n", certificate_file);
		if (SSL_CTX_use_certificate_chain_file(ctx, certificate_file) <= 0) {
			RRR_SSL_ERR("Could not set certificate file while starting TLS");
			ret = 1;
			goto out_destroy;
		}
	}

	if (private_key_file != NULL && *private_key_file != '\0') {
		RRR_DBG_1("Opening private key file '%s', expecting PEM format\n", private_key_file);
		if (SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) <= 0 ) {
			RRR_SSL_ERR("Could not set private key file while starting TLS");
			ret = 1;
			goto out_destroy;
		}

		if (SSL_CTX_check_private_key(ctx) != 1) {
			RRR_SSL_ERR("Error encoutered while checking private key while starting TLS");
			ret = 1;
			goto out_destroy;
		}
	}

	*target = ctx;

	goto out;
	out_destroy:
		SSL_CTX_free(ctx);
	out:
		return ret;
}

struct rrr_net_transport_tls_connect_locked_callback_data {
	struct rrr_net_transport_tls_ssl_data *ssl_data;
	unsigned int port;
	const char *host;
};

static int __rrr_net_transport_tls_connect_locked_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	int ret = 0;

	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) handle->transport;

	struct rrr_net_transport_tls_connect_locked_callback_data *callback_data = arg;
	struct rrr_net_transport_tls_ssl_data *ssl_data = callback_data->ssl_data;

	if (__rrr_net_transport_tls_new_ctx (
			&ssl_data->ctx,
			tls->ssl_client_method,
			tls->flags,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_tls_connect");
		ret = 1;
		goto out;
	}

	if ((ssl_data->web = BIO_new_ssl(ssl_data->ctx, 1)) == NULL) {
		RRR_SSL_ERR("Could not get BIO in __rrr_net_transport_tls_connect");
		ret = 1;
		goto out;
	}

	SSL *ssl = NULL;
	BIO_get_ssl(ssl_data->web, &ssl);

	if (SSL_set_fd(ssl, ssl_data->ip_data.fd) != 1) {
		RRR_SSL_ERR("Could not set FD for SSL in __rrr_net_transport_tls_accept\n");
		ret = 1;
		goto out;
	}

	// Not used for TLSv1.3
	//const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
	//res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);

	if (SSL_set_tlsext_host_name(ssl, callback_data->host) != 1) {
		RRR_SSL_ERR("Could not set TLS hostname");
		ret = 1;
		goto out;
	}

	if (RRR_DEBUGLEVEL_1) {
		__rrr_net_transport_tls_dump_enabled_ciphers(ssl);
	}

	// Set non-blocking I/O
	BIO_set_nbio(ssl_data->web, 1); // Always returns 1

	retry_handshake:
	if (BIO_do_handshake(ssl_data->web) != 1) {
		if (BIO_should_retry(ssl_data->web)) {
			rrr_posix_usleep(1000);
			goto retry_handshake;
		}
		RRR_SSL_ERR("Could not do TLS handshake");
		ret = 1;
		goto out;
	}
	
	ssl_data->handshake_complete = 1;

	X509 *cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		X509_free(cert);
	}
	else {
		RRR_MSG_0("No certificate received in TLS handshake with %s:%u\n",
				callback_data->host, callback_data->port);
		ret = 1;
		goto out;
	}

	long verify_result = 0;
	if ((verify_result = SSL_get_verify_result(ssl)) != X509_V_OK) {
		RRR_MSG_0("Certificate verification failed for %s:%u with reason %li\n",
				callback_data->host, callback_data->port, verify_result);
		ret = 1;
		goto out;
	}

	// TODO : Hostname verification

	out:
	return ret;
}

static int __rrr_net_transport_tls_connect (
		int *handle,
		struct sockaddr *addr,
		socklen_t *socklen,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {
	struct rrr_ip_accept_data *accept_data = NULL;

	if (*socklen < sizeof(accept_data->addr)) {
		RRR_BUG("BUG: socklen too small in __rrr_net_transport_tls_connect\n");
	}

	*handle = 0;

	int ret = 0;

	struct rrr_net_transport_tls_ssl_data *ssl_data = NULL;

	if (rrr_ip_network_connect_tcp_ipv4_or_ipv6(&accept_data, port, host, NULL) != 0) {
		RRR_DBG_1("Could not create TLS connection to %s:%u\n", host, port);
		ret = 1;
		goto out;
	}

	if ((ssl_data = __rrr_net_transport_tls_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_tls_connect\n");
		ret = 1;
		goto out_destroy_ip;
	}

	ssl_data->ip_data = accept_data->ip_data;

	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			ssl_data,
			0
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_tls_connect return was %i\n", ret);
		ret = 1;
		goto out_destroy_ssl_data;
	}

	struct rrr_net_transport_tls_connect_locked_callback_data callback_data = {
			ssl_data,
			port,
			host
	};

	if ((ret = rrr_net_transport_handle_with_transport_ctx_do (
			transport,
			new_handle,
			__rrr_net_transport_tls_connect_locked_callback,
			&callback_data
	)) != 0) {
		goto out_unregister_handle;
	}

	memcpy(addr, &accept_data->addr, accept_data->len);
	*socklen = accept_data->len;

	*handle = new_handle;

	goto out;

	out_unregister_handle:
		// Will also destroy ssl_data (which in turn destroys ip)
		rrr_net_transport_handle_close(transport, new_handle);
		// SSL data is freed when handle is unregistered, don't double-free
		goto out;
	out_destroy_ssl_data:
		__rrr_net_transport_tls_ssl_data_destroy(ssl_data);
		// ssl_data_destroy calls ip_close, skip doing it again
		goto out;
	out_destroy_ip:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

static int __rrr_net_transport_tls_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;
	struct rrr_net_transport_tls_ssl_data *ssl_data = NULL;

	int ret = 0;

	if (tls->certificate_file == NULL || tls->private_key_file == NULL) {
		RRR_MSG_0("Certificate file and/or private key file not set while attempting to start TLS listening server\n");
		ret = 1;
		goto out;
	}

	if ((ssl_data = __rrr_net_transport_tls_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_tls_bind_and_listen\n");
		ret = 1;
		goto out;
	}

	int new_handle;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
			ssl_data,
			0
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_tls_bind_and_listen return was %i\n", ret);
		ret = 1;
		goto out_free_ssl_data;
	}

	// Do all initialization inside memory fence
	memset(ssl_data, '\0', sizeof(*ssl_data));

	ssl_data->ip_data.port = port;

	if (rrr_ip_network_start_tcp_ipv4_and_ipv6 (&ssl_data->ip_data, 10) != 0) {
		RRR_MSG_0("Could not start IP listening in __rrr_net_transport_tls_bind_and_listen\n");
		ret = 1;
		goto out_unregister_handle;
	}

	if (__rrr_net_transport_tls_new_ctx (
			&ssl_data->ctx,
			tls->ssl_server_method,
			tls->flags,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_tls_bind_and_listen");
		ret = 1;
		goto out_destroy_ip;
	}

	ret = callback (
			transport,
			new_handle,
			callback_final,
			callback_final_arg,
			callback_arg
	);

	goto out;
//	out_destroy_ctx:
//		SSL_CTX_free(ssl_data->ctx);
	out_destroy_ip:
		rrr_ip_close(&ssl_data->ip_data);
	out_unregister_handle:
		// Will also destroy ssl_data (which in turn destroys ip)
		// Will unlock and destroy
		rrr_net_transport_handle_close (transport, new_handle);
		// Freed when handle is unregistered, don't double-free
		ssl_data = NULL;
	out_free_ssl_data:
		RRR_FREE_IF_NOT_NULL(ssl_data);
	out:
		return ret;
}

int __rrr_net_transport_tls_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	struct rrr_ip_accept_data *accept_data = NULL;
	struct rrr_net_transport_tls_ssl_data *new_ssl_data = NULL;
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) listen_handle->transport;

	int ret = 0;

	struct rrr_net_transport_tls_ssl_data *listen_ssl_data = listen_handle->submodule_private_ptr;

	if ((ret = rrr_ip_accept(&accept_data, &listen_ssl_data->ip_data, "net_transport_tls", 0)) != 0) {
		RRR_MSG_0("Error while accepting connection in TLS server\n");
		ret = 1;
		goto out;
	}

	if (accept_data == NULL) {
		goto out;
	}

	if ((new_ssl_data = __rrr_net_transport_tls_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_tls_accept\n");
		ret = 1;
		goto out_destroy_ip;
	}

	// Run this before populating SSL data to provide memory fence
	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			listen_handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			new_ssl_data,
			0
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_tls_accept return was %i\n", ret);
		ret = 1;
		goto out_destroy_ssl_data;
	}

	// Do all initialization inside memory fence
	memset (new_ssl_data, '\0', sizeof(*new_ssl_data));

	if (__rrr_net_transport_tls_new_ctx (
			&new_ssl_data->ctx,
			tls->ssl_server_method,
			tls->flags,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_tls_accept\n");
		ret = 1;
		goto out_destroy_ip;
	}

	new_ssl_data->sockaddr = accept_data->addr;
	new_ssl_data->socklen = accept_data->len;
	new_ssl_data->ip_data = accept_data->ip_data;

	if ((new_ssl_data->web = BIO_new_ssl(new_ssl_data->ctx, 0)) == NULL) {
		RRR_SSL_ERR("Could not allocate BIO in __rrr_net_transport_tls_accept\n");
		ret = 1;
		goto out_unregister_handle;
	}

	SSL *ssl;
	BIO_get_ssl(new_ssl_data->web, &ssl);

	if (SSL_set_fd(ssl, new_ssl_data->ip_data.fd) != 1) {
		RRR_SSL_ERR("Could not set FD for SSL in __rrr_net_transport_tls_accept\n");
		ret = 1;
		goto out_unregister_handle;
	}

	BIO_set_nbio(new_ssl_data->web, 1);

	// SSL handshake is done in read function

	ret = callback(
			listen_handle->transport,
			new_handle,
			(struct sockaddr *) &accept_data->addr,
			accept_data->len,
			final_callback,
			final_callback_arg,
			callback_arg
	);

	goto out;
	out_unregister_handle:
		// Will also destroy ssl_data (which in turn destroys ip)
		rrr_net_transport_handle_close(listen_handle->transport, new_handle);
		goto out;
	out_destroy_ssl_data:
		__rrr_net_transport_tls_ssl_data_destroy(new_ssl_data);
		goto out; // ssl_data_cleanup will call rrr_ip_close
	out_destroy_ip:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

static int __rrr_net_transport_tls_read_poll(int read_flags, void *private_arg) {
	(void)(private_arg);
	(void)(read_flags);
	return RRR_READ_OK;
}

static struct rrr_read_session *__rrr_net_transport_tls_read_get_read_session_with_overshoot(void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;

	return rrr_read_session_collection_get_session_with_overshoot (
			&callback_data->handle->read_sessions
	);
}

static struct rrr_read_session *__rrr_net_transport_tls_read_get_read_session(void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	struct rrr_net_transport_tls_ssl_data *ssl_data = callback_data->handle->submodule_private_ptr;

	return rrr_read_session_collection_maintain_and_find_or_create (
			&callback_data->handle->read_sessions,
			(struct sockaddr *) &ssl_data->sockaddr,
			ssl_data->socklen
	);
}

static void __rrr_net_transport_tls_read_remove_read_session(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;

	rrr_read_session_collection_remove_session(&callback_data->handle->read_sessions, read_session);
}

static int __rrr_net_transport_tls_read_get_target_size(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

static int __rrr_net_transport_tls_read_complete_callback(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}

static int __rrr_net_transport_tls_read_read (
		char *buf,
		ssize_t *read_bytes,
		ssize_t read_step_max_size,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	struct rrr_net_transport_tls_ssl_data *ssl_data = callback_data->handle->submodule_private_ptr;

	int ret = RRR_READ_OK;

	ssize_t result = BIO_read(ssl_data->web, buf, read_step_max_size);
	if (result < 0) {
		if (BIO_should_retry(ssl_data->web) == 0) {
//			int reason = BIO_get_retry_reason(ssl_data->web);
			RRR_SSL_ERR("Error while reading from TLS connection");
			// Possible close of connection
			ret = RRR_READ_SOFT_ERROR;
			goto out;
		}
		else {
			// Retry later
			return RRR_READ_INCOMPLETE;
		}
	}
	else if (ERR_peek_error() != 0) {
		RRR_SSL_ERR("Error while reading in __rrr_net_transport_tls_read_read");
		return RRR_READ_SOFT_ERROR;
	}

	out:
	ERR_clear_error();
	*read_bytes = (result >= 0 ? result : 0);
	return ret;
}

static int __rrr_net_transport_tls_read_message (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	int ret = 0;

	*bytes_read = 0;

//	struct rrr_net_transport_tls_ssl_data *ssl_data = handle->submodule_private_ptr;

	// Try only once to avoid blocking on bad clients
/*	while (ssl_data->handshake_complete == 0) {
		if (BIO_do_handshake(ssl_data->web) != 1) {
			if (ERR_peek_last_error() != 0 || BIO_should_retry(ssl_data->web) != 1) {
				RRR_SSL_ERR("Could not do handshake with remote in TLS connection\n");
				ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
				goto out;
			}
			else if (--read_attempts == 0) {
				ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
				goto out;
			}
		}
		else {
			ssl_data->handshake_complete = 1;
		}
	}*/

	struct rrr_net_transport_read_callback_data read_callback_data = {
		handle,
		get_target_size,
		get_target_size_arg,
		complete_callback,
		complete_callback_arg
	};

	while (--read_attempts >= 0) {
		uint64_t bytes_read_tmp = 0;
		ret = rrr_read_message_using_callbacks (
				&bytes_read_tmp,
				read_step_initial,
				read_step_max_size,
				read_max_size,
				read_flags,
				__rrr_net_transport_tls_read_get_target_size,
				__rrr_net_transport_tls_read_complete_callback,
				__rrr_net_transport_tls_read_poll,
				__rrr_net_transport_tls_read_read,
				__rrr_net_transport_tls_read_get_read_session_with_overshoot,
				__rrr_net_transport_tls_read_get_read_session,
				__rrr_net_transport_tls_read_remove_read_session,
				NULL,
				&read_callback_data
		);
		*bytes_read += bytes_read_tmp;

		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			continue;
		}
		else if (ret == RRR_NET_TRANSPORT_READ_OK) {
			break;
		}
		else {
			RRR_MSG_0("Error %i while reading from remote in __rrr_net_transport_tls_read_message\n", ret);
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_net_transport_tls_send (
	uint64_t *sent_bytes,
	struct rrr_net_transport_handle *handle,
	const void *data,
	ssize_t size
) {
	struct rrr_net_transport_tls_ssl_data *ssl_data = handle->submodule_private_ptr;

	*sent_bytes = 0;

	if (BIO_write(ssl_data->web, data, size) <= 0) {
		if (BIO_should_retry(ssl_data->web)) {
			return 0;
		}
		RRR_MSG_0("Write failure in __rrr_net_transport_tls_send\n");
		return 1;
	}
	else {
		*sent_bytes = (size > 0 ? size : 0);
	}

	return 0;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_tls_destroy,
	__rrr_net_transport_tls_connect,
	__rrr_net_transport_tls_bind_and_listen,
	__rrr_net_transport_tls_accept,
	__rrr_net_transport_tls_ssl_data_close,
	__rrr_net_transport_tls_read_message,
	__rrr_net_transport_tls_send
};

#define CHECK_FLAG(flag)				\
	do {if ((flags & flag) != 0) {		\
		flags_checked |= flag;			\
		flags &= ~(flag);				\
	}} while(0)

int rrr_net_transport_tls_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path
) {
	struct rrr_net_transport_tls *result = NULL;

	*target = NULL;

	int ret = 0;

	int flags_checked = 0;
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY);
	CHECK_FLAG(RRR_NET_TRANSPORT_F_MIN_VERSION_TLS_1_1);

	if (flags != 0) {
		RRR_BUG("BUG: Unknown flags %i given to rrr_net_transport_tls_new\n", flags);
	}

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_net_transport_tls_new\n");
		ret = 1;
		goto out;
	}

	rrr_openssl_global_register_user();

	memset(result, '\0', sizeof(*result));

	if (certificate_file != NULL && *certificate_file != '\0') {
		if ((result->certificate_file = strdup(certificate_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for certificate file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (private_key_file != NULL && *private_key_file != '\0') {
		if ((result->private_key_file = strdup(private_key_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for private key file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (ca_file != NULL && *ca_file != '\0') {
		if ((result->ca_file = strdup(ca_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for CA file file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (ca_path != NULL && *ca_path != '\0') {
		if ((result->ca_path = strdup(ca_path)) == NULL) {
			RRR_MSG_0("Could not allocate memory for CA path file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	result->methods = &tls_methods;
	result->ssl_client_method = TLS_client_method();
	result->ssl_server_method = TLS_server_method();
	result->flags = flags_checked;

	*target = result;

	goto out;
	out_free:
		RRR_FREE_IF_NOT_NULL(result->ca_path);
		RRR_FREE_IF_NOT_NULL(result->ca_file);
		RRR_FREE_IF_NOT_NULL(result->certificate_file);
		RRR_FREE_IF_NOT_NULL(result->private_key_file);
		free(result);
	out:
		return ret;
}
