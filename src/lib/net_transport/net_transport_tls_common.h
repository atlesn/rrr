/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NET_TRANSPORT_TLS_COMMON_H
#define RRR_NET_TRANSPORT_TLS_COMMON_H

#include "net_transport_struct.h"
#include "net_transport.h"
#include "../ip/ip.h"
#include "../socket/rrr_socket_graylist.h"

#define RRR_NET_TRANSPORT_TLS_COMMON_ALPN_MAX 6

#ifdef RRR_WITH_OPENSSL
#	include <openssl/ssl.h>
#endif

#ifdef RRR_WITH_GNUTLS
#	include <gnutls/gnutls.h>
#endif

struct rrr_read_session;

struct rrr_net_transport_tls_alpn {
	char *protos;
	unsigned int length;
	char alpn_buf[RRR_NET_TRANSPORT_TLS_COMMON_ALPN_MAX][256];
	unsigned int alpn_buf_count;
};

struct rrr_net_transport_tls {
	RRR_NET_TRANSPORT_HEAD(struct rrr_net_transport_tls);

	struct rrr_net_transport_tls_alpn alpn;
	struct rrr_socket_graylist *connect_graylist;

#ifdef RRR_WITH_OPENSSL
	const SSL_METHOD *ssl_client_method;
	const SSL_METHOD *ssl_server_method;
#endif

#ifdef RRR_WITH_LIBRESSL
	struct tls_config *config;
#endif

#ifdef RRR_WITH_GNUTLS
	gnutls_datum_t alpn_datum[RRR_NET_TRANSPORT_TLS_COMMON_ALPN_MAX];
	unsigned int alpn_datum_count;
#endif

	int flags_tls;
	int flags_submodule;

	char *certificate_file;
	char *private_key_file;
	char *ca_file;
	char *ca_path;
};

struct rrr_net_transport_tls_data {
	struct rrr_ip_data ip_data;
	struct sockaddr_storage sockaddr;
	socklen_t socklen;

#ifdef RRR_WITH_OPENSSL
	SSL_CTX *ctx;
	BIO *web;
	SSL *ssl;
#endif

#ifdef RRR_WITH_LIBRESSL
	struct tls *ctx;
#endif

#ifdef RRR_WITH_GNUTLS
	gnutls_certificate_credentials_t x509_cred;
	gnutls_priority_t priority_cache;
	gnutls_datum_t ticket_key;
#endif
};

int rrr_net_transport_tls_common_new (
		struct rrr_net_transport_tls **target,
		int flags_tls,
		int flags_submodule,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
);
int rrr_net_transport_tls_common_destroy (
		struct rrr_net_transport_tls *target
);
struct rrr_read_session *rrr_net_transport_tls_common_read_get_read_session (
		void *private_arg
);
struct rrr_read_session *rrr_net_transport_tls_common_read_get_read_session_with_overshoot (
		void *private_arg
);
void rrr_net_transport_tls_common_read_remove_read_session (
		struct rrr_read_session *read_session,
		void *private_arg
);
void rrr_net_transport_tls_common_alpn_protos_to_str_comma_separated (
		unsigned char *out_buf,
		unsigned int out_size,
		const unsigned char *in,
		unsigned int in_size
);
void rrr_net_transport_tls_common_alpn_populate (
		struct rrr_net_transport_tls_alpn *target,
		const unsigned char *in,
		unsigned int in_size
);

#endif /* RRR_NET_TRANSPORT_TLS_COMMON_H */
