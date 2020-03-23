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
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "../global.h"
#include "net_transport_tls.h"
#include "rrr_openssl.h"
#include "gnu.h"

#define RRR_SSL_ERR(msg)								\
	do {												\
		char buf[256];									\
		ERR_error_string_n(ERR_get_error(), buf, 256); 	\
		RRR_MSG_ERR(msg ": %s\n", buf);					\
	} while(0)

struct rrr_net_transport_tls_ssl_data {
	SSL_CTX *ctx;
	BIO *web;
	struct rrr_net_transport_read_session read_session;
};

static int __rrr_net_transport_tls_close (struct rrr_net_transport *transport, void *private_ptr, int handle) {
	(void)(handle);
	(void)(transport);

	struct rrr_net_transport_tls_ssl_data *ssl_data = private_ptr;

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

		// Cast away const OK
		void *buffer = (void *)  ssl_data->read_session.buffer;
		void *overshoot = (void *)  ssl_data->read_session.overshoot;

		RRR_FREE_IF_NOT_NULL(buffer);
		RRR_FREE_IF_NOT_NULL(overshoot);

		free(ssl_data);
	}

	return 0;
}

static int __rrr_net_transport_tls_handle_destroy_callback (int handle, void *private_ptr, void *arg) {
	return __rrr_net_transport_tls_close ((struct rrr_net_transport *) arg, private_ptr, handle);
}

static void __rrr_net_transport_tls_destroy (struct rrr_net_transport *transport) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	rrr_net_transport_handle_collection_clear(&transport->handles, __rrr_net_transport_tls_handle_destroy_callback, transport);

	free(tls);

	rrr_openssl_global_unregister_user();
}

static int __rrr_net_transport_tls_connect (
		int *handle,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	int ret = 0;
	char *host_and_port = NULL;
	struct rrr_net_transport_tls_ssl_data *ssl_data = NULL;

	*handle = 0;

	if ((ssl_data = malloc(sizeof(*ssl_data))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory for SSL data in __rrr_net_transport_tls_connect\n");
		ret = 1;
		goto out;
	}
	memset (ssl_data, '\0', sizeof(*ssl_data));

	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_collection_allocate_and_add_handle(&new_handle, &transport->handles, ssl_data)) != 0) {
		RRR_MSG_ERR("Could not get handle in __rrr_net_transport_tls_connect\n");
		ret = 1;
		goto out_free_ssl_data;
	}

	if ((ssl_data->ctx = SSL_CTX_new(tls->ssl_method)) == NULL) {
		RRR_SSL_ERR("Could not get SSL CTX in __rrr_net_transport_tls_connect");
		ret = 1;
		goto out_unregister_handle;
	}

	// NULL callback causes verification failure to cancel further processing
	SSL_CTX_set_verify(ssl_data->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ssl_data->ctx, 4);

	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(ssl_data->ctx, flags);

	// TODO : Add user-configurabe cerfificates and paths
	if (SSL_CTX_load_verify_locations(ssl_data->ctx, NULL, "/etc/ssl/certs/") != 1) {
		RRR_SSL_ERR("Could not set certificate verification path\n");
		ret = 1;
		goto out_unregister_handle;
	}

	if ((ssl_data->web = BIO_new_ssl_connect(ssl_data->ctx)) == NULL) {
		RRR_SSL_ERR("Could not get BIO in __rrr_net_transport_tls_connect");
		ret = 1;
		goto out_unregister_handle;
	}

	if (rrr_asprintf(&host_and_port, "%s:%u", host, port) <= 0) {
		RRR_MSG_ERR("Could not create host/port-string in __rrr_net_transport_tls_connect\n");
		ret = 1;
		goto out_unregister_handle;
	}

	if (BIO_set_conn_hostname(ssl_data->web, host_and_port) != 1) {
		RRR_SSL_ERR("Could not set TLS BIO hostname");
		ret = 1;
		goto out_unregister_handle;
	}

	SSL *ssl = NULL;
	BIO_get_ssl(ssl_data->web, &ssl);
	if (ssl == NULL) {
		RRR_SSL_ERR("Could not get SSL pointer from BIO");
		ret = 1;
		goto out_unregister_handle;
	}

	// Not used for TLSv1.3
	//const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
	//res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);

	if (SSL_set_tlsext_host_name(ssl, host) != 1) {
		RRR_SSL_ERR("Could not set TLS hostname");
		ret = 1;
		goto out_unregister_handle;
	}

	if (BIO_do_connect(ssl_data->web) != 1) {
		RRR_SSL_ERR("Could not do TLS connect");
		ret = 1;
		goto out_unregister_handle;
	}

	if (BIO_do_handshake(ssl_data->web) != 1) {
		RRR_SSL_ERR("Could not do TLS handshake");
		ret = 1;
		goto out_unregister_handle;
	}

	X509 *cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		X509_free(cert);
	}
	else {
		RRR_MSG_ERR("No certificate received in TLS handshake with %s\n", host_and_port);
		ret = 1;
		goto out_unregister_handle;
	}

	long verify_result = 0;
	if ((verify_result = SSL_get_verify_result(ssl)) != X509_V_OK) {
		RRR_MSG_ERR("Certificate verification failed for %s with reason %li\n", host_and_port, verify_result);
		ret = 1;
		goto out_unregister_handle;
	}

	// TODO : Hostname verification

	*handle = new_handle;

	goto out;
	out_unregister_handle:
		// This will also clean up any SSL stuff
		rrr_net_transport_handle_collection_handle_remove(
				&transport->handles,
				new_handle,
				__rrr_net_transport_tls_handle_destroy_callback,
				NULL
		);
		ssl_data = NULL; // Freed when handle is unregistered, don't double-free
	out_free_ssl_data:
		RRR_FREE_IF_NOT_NULL(ssl_data);
	out:
		RRR_FREE_IF_NOT_NULL(host_and_port);
		return ret;
}

static int __rrr_net_transport_tls_read_message (
	struct rrr_net_transport *transport,
	int transport_handle,
	ssize_t read_step_initial,
	ssize_t read_step_max_size,
	int (*get_target_size)(struct rrr_net_transport_read_session *read_session, void *arg),
	void *get_target_size_arg,
	int (*complete_callback)(struct rrr_net_transport_read_session *read_session, void *arg),
	void *complete_callback_arg
) {
	struct rrr_net_transport_tls_ssl_data *ssl_data = NULL;
	if ((ssl_data = rrr_net_transport_handle_collection_handle_get_private_ptr(&transport->handles, transport_handle)) == NULL) {
		RRR_MSG_ERR("Handle %i not found in __rrr_net_transport_tls_send\n", transport_handle);
		return 1;
	}

	struct rrr_net_transport_read_session *read_session = &ssl_data->read_session;

	if (read_session->overshoot != NULL) {
		if (read_session->buffer != NULL) {
			RRR_BUG("Both overshoot and buffer was non-NULL in __rrr_net_transport_tls_read_message\n");
		}

		read_session->buffer = read_session->overshoot;
		read_session->buffer_size = read_session->overshoot_size;

		read_session->overshoot = NULL;
		read_session->overshoot_size = 0;
	}

	// Check for allocation or expansion of buffer
	// NOTE : Buffer is always cleaned up when handle is unregistered
	if (read_session->wpos + read_step_max_size > read_session->buffer_size) {
		char *new_buf = realloc((void*) read_session->buffer, read_session->buffer_size + read_step_max_size);
		if (new_buf == NULL) {
			RRR_MSG_ERR("Could not allocate memory in __rrr_net_transport_tls_read_message\n");
			return 1;
		}
		read_session->buffer = new_buf;
		read_session->buffer_size = read_session->buffer_size + read_step_max_size;
	}

	// Cast away const OK, we only want const in the callback functions
	char *buffer = (char *) read_session->buffer;

	int bytes_to_read = read_session->buffer_size - read_session->wpos;

	if (read_session->target_size > 0) {
		bytes_to_read = read_session->target_size - read_session->wpos;
	}
	else if (read_session->wpos == 0) {
		bytes_to_read = read_step_initial;
	}

	ERR_clear_error();

	int result = BIO_read(ssl_data->web, buffer + read_session->wpos, bytes_to_read);
	if (result == 0) {
		if (BIO_should_retry(ssl_data->web) == 0) {
			if (read_session->read_complete_method == RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE) {
				read_session->target_size = read_session->wpos;
			}
			else {
				RRR_MSG_ERR("Connection closed before read completed in __rrr_net_transport_tls_read_message\n");
				return 1;
			}
		}
		else {
			// Retry later
			return 0;
		}
	}
	else if (ERR_peek_error() != 0) {
		RRR_SSL_ERR("Error while reading");
		return 1;
	}

	read_session->wpos += result;

	if (read_session->target_size == 0 && read_session->read_complete_method != RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE) {
		int ret = 0;
		if ((ret = get_target_size(read_session, get_target_size_arg)) != 0) {
			if (ret != RRR_NET_TRANSPORT_READ_INCOMPLETE) {
				RRR_MSG_ERR("Error %i from get_target_size in TLS read\n", ret);
				return 1;
			}
		}
		else if (read_session->read_complete_method == RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE) {
			if (read_session->target_size != 0)  {
				RRR_BUG("BUG: get_target_size set both a target size and RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE\n");
			}
		}
		else if (read_session->read_complete_method == RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH) {
			if (read_session->target_size == 0) {
				RRR_BUG("BUG: get_target_size did not set any target size in __rrr_net_transport_tls_read_message\n");
			}
		}
		else {
			RRR_BUG("BUG: get_target_size returned invalid complete method %i in __rrr_net_transport_tls_read_message\n",
					read_session->read_complete_method);
		}

		if (ret == 0 && read_session->target_size < read_session->wpos) {
			read_session->overshoot_size = read_session->wpos - read_session->target_size;

			if ((read_session->overshoot = malloc(read_session->overshoot_size)) == NULL) {
				RRR_MSG_ERR("Could not allocate memory for overshoot in __rrr_net_transport_tls_read_message\n");
				return 1;
			}

			memcpy((void *) read_session->overshoot, read_session->buffer + read_session->wpos, read_session->overshoot_size);

			read_session->wpos = read_session->target_size;
		}
	}

	if (read_session->wpos == read_session->target_size) {
		int ret = 0;
		if ((ret = complete_callback(read_session, complete_callback_arg)) != 0) {
			RRR_MSG_ERR("Error %i from callback in __rrr_net_transport_tls_read_message\n", ret);
			return 1;
		}

		// Don't clear overshoot here
		void *buffer = (void*) read_session->buffer; // Cast away const OK
		RRR_FREE_IF_NOT_NULL(buffer);
		read_session->buffer = NULL;
		read_session->target_size = 0;
		read_session->wpos = 0;
		read_session->read_complete_method = 0;
		read_session->buffer_size = 0;
	}

	return 0;
}

static int __rrr_net_transport_tls_send (
	struct rrr_net_transport *transport,
	int transport_handle,
	void *data,
	ssize_t size
) {
	struct rrr_net_transport_tls_ssl_data *ssl_data = NULL;
	if ((ssl_data = rrr_net_transport_handle_collection_handle_get_private_ptr(&transport->handles, transport_handle)) == NULL) {
		RRR_MSG_ERR("Handle %i not found in __rrr_net_transport_tls_send\n", transport_handle);
		return 1;
	}

	if (BIO_write(ssl_data->web, data, size) != size) {
		RRR_MSG_ERR("Write failure in __rrr_net_transport_tls_send\n");
		return 1;
	}

	return 0;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_tls_destroy,
	__rrr_net_transport_tls_connect,
	__rrr_net_transport_tls_close,
	__rrr_net_transport_tls_read_message,
	__rrr_net_transport_tls_send
};

int rrr_net_transport_tls_new (struct rrr_net_transport_tls **target) {
	struct rrr_net_transport_tls *result = NULL;

	*target = NULL;

	int ret = 0;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_net_transport_tls_new\n");
		ret = 1;
		goto out;
	}

	rrr_openssl_global_register_user();

	memset(result, '\0', sizeof(*result));

	result->methods = &tls_methods;
	result->ssl_method = TLS_client_method();

	*target = result;

	out:
	return ret;
}
