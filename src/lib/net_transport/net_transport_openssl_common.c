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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>

#include "../allocator.h"

#include "net_transport_openssl_common.h"
#include "net_transport_tls_common.h"

#include "../rrr_openssl.h"

struct rrr_net_transport_tls_data *rrr_net_transport_openssl_common_ssl_data_new (void) {
	struct rrr_net_transport_tls_data *ssl_data = NULL;

	if ((ssl_data = rrr_allocate(sizeof(*ssl_data))) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in %s\n", __func__);
		return NULL;
	}
	memset (ssl_data, '\0', sizeof(*ssl_data));

	return ssl_data;
}

void rrr_net_transport_openssl_common_ssl_data_destroy (struct rrr_net_transport_tls_data *ssl_data) {
	if (ssl_data != NULL) {
		if (ssl_data->web != NULL) {
			assert(ssl_data->ssl == NULL);
			BIO_free_all(ssl_data->web);
		}
		if (ssl_data->ssl != NULL) {
			assert(ssl_data->web == NULL);
			SSL_free(ssl_data->ssl);
		}
		if (ssl_data->ctx != NULL) {
			SSL_CTX_free(ssl_data->ctx);
		}
		if (ssl_data->ip_data.fd != 0) {
			rrr_ip_close(&ssl_data->ip_data);
		}
		RRR_FREE_IF_NOT_NULL(ssl_data->alpn_selected_proto);
		rrr_free(ssl_data);
	}
}

static int __rrr_net_transport_openssl_common_verify_always_ok (X509_STORE_CTX *x509, void *arg) {
	(void)(x509);
	(void)(arg);
	return 1;
}

static int __rrr_net_transport_openssl_common_alpn_select_cb (
		SSL *s,
		const unsigned char **out,
		unsigned char *outlen,
		const unsigned char *in,
		unsigned int inlen,
		void *arg
) {
	struct rrr_net_transport_tls_alpn *alpn = arg;

	(void)(s);

	int ret = SSL_TLSEXT_ERR_NOACK;

	*out = NULL;
	*outlen = 0;

	// -2 for comma and \0
	if (alpn->length > 256 - 2|| inlen > 256 - 2) {
		RRR_MSG_1("Error: Large ALPN proto vectors (%u and %u) in %s\n", alpn->length, inlen, __func__);
		ret = SSL_TLSEXT_ERR_ALERT_FATAL;
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		unsigned char server_protocols_tmp[256];
		unsigned char client_protocols_tmp[256];
		rrr_net_transport_tls_common_alpn_protos_to_str_comma_separated(server_protocols_tmp, sizeof(server_protocols_tmp), (unsigned char *) alpn->protos, alpn->length);
		rrr_net_transport_tls_common_alpn_protos_to_str_comma_separated(client_protocols_tmp, sizeof(client_protocols_tmp), in, inlen);
		RRR_DBG_3("TLS ALPN server protocols: '%s' client protocols: '%s'\n", server_protocols_tmp, client_protocols_tmp);
	}

	if (alpn->length == 0 || inlen == 0) {
		goto out;
	}

	// Strategy : Pick the first protocol from the server list which is also in the client list
	int server_index = 0;
	for (unsigned int i = 0; i < alpn->length;/* increment at loop end */) {
		const char *i_text = alpn->protos + i + 1;
		unsigned char i_text_length = (unsigned char) alpn->protos[i];

		if (i + i_text_length >= alpn->length) {
			RRR_BUG("BUG: Invalid size in self-created ALPN vector in %s\n", __func__);
		}

		for (unsigned int j = 0; j < inlen;/* increment at loop end */) {
			const unsigned char *j_text = in + j + 1;
			unsigned char j_text_length = in[j];

			if (j + j_text_length >= inlen) {
				RRR_MSG_0("Error: Invalid size in vector from input in %s\n", __func__);
				ret = SSL_TLSEXT_ERR_ALERT_FATAL;
				goto out;
			}

			if (i_text_length == j_text_length && memcmp(i_text, j_text, i_text_length) == 0) {
				*out = (const unsigned char *) alpn->protos + i + 1;
				*outlen = i_text_length;
				RRR_DBG_3("TLS ALPN selected protocol at server position %i\n", server_index);
				ret = SSL_TLSEXT_ERR_OK;
				goto out;
			}

			j += (unsigned int) j_text_length + 1;
		}

		server_index++;
		i += (unsigned int) i_text_length + 1;
	}

	RRR_DBG_3("TLS ALPN no protocol selected\n");

	out:
	return ret;
}

// Memory in *alpn must be permanently available during connection lifetime
int rrr_net_transport_openssl_common_new_ctx (
		SSL_CTX **target,
		const SSL_METHOD *method,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		struct rrr_net_transport_tls_alpn *alpn
) {
	int ret = 0;

	*target = NULL;

	SSL_CTX *ctx = NULL;

	if (((certificate_file == NULL || *certificate_file == '\0') && (private_key_file != NULL && *private_key_file != '\0')) ||
		((private_key_file == NULL || *private_key_file == '\0') && (certificate_file != NULL && *certificate_file != '\0'))
	) {
		RRR_BUG("BUG: Certificate file and private key file must both be either set or unset in %s\n", __func__);
	}

	if ((ctx = SSL_CTX_new(method)) == NULL) {
		RRR_SSL_ERR("Could not get SSL CTX");
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
	if ((flags & RRR_NET_TRANSPORT_F_TLS_VERSION_MIN_1_1) != 0) {
		min_version = TLS1_1_VERSION;
	}

	if (SSL_CTX_set_min_proto_version(ctx, (long int) min_version) != 1) {
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
		SSL_CTX_set_cert_verify_callback (ctx, __rrr_net_transport_openssl_common_verify_always_ok, NULL);
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

	if (alpn != NULL && alpn->protos != NULL) {
		// For client
		// Note: Returns 0 on success as opposed to other OpenSSL functions
		if (SSL_CTX_set_alpn_protos(ctx, (unsigned const char *) alpn->protos, alpn->length) != 0) {
			RRR_SSL_ERR("SSL_CTX_set_alpn_protos failed");
			ret = 1;
			goto out_destroy;
		}

		// For server
		SSL_CTX_set_alpn_select_cb(ctx, __rrr_net_transport_openssl_common_alpn_select_cb, alpn);
	}

	*target = ctx;

	goto out;
	out_destroy:
		SSL_CTX_free(ctx);
	out:
		return ret;
}
