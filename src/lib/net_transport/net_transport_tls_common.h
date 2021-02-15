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

#ifndef RRR_NET_TRANSPORT_TLS_COMMON_H
#define RRR_NET_TRANSPORT_TLS_COMMON_H

#include "net_transport.h"
#include "../ip/ip.h"

#ifdef RRR_WITH_OPENSSL
#	include <openssl/ssl.h>
#endif

struct rrr_read_session;

struct rrr_net_transport_tls_alpn {
	char *protos;
	unsigned int length;
};

struct rrr_net_transport_tls {
	RRR_NET_TRANSPORT_HEAD(struct rrr_net_transport_tls);

#ifdef RRR_WITH_OPENSSL
	const SSL_METHOD *ssl_client_method;
	const SSL_METHOD *ssl_server_method;
#endif

#ifdef RRR_WITH_LIBRESSL
	struct tls_config *config;
#endif

	int flags;
	char *certificate_file;
	char *private_key_file;
	char *ca_file;
	char *ca_path;
	struct rrr_net_transport_tls_alpn alpn;
};

struct rrr_net_transport_tls_data {
	struct rrr_ip_data ip_data;
	struct sockaddr_storage sockaddr;
	socklen_t socklen;

	char *alpn_selected_proto;

#ifdef RRR_WITH_OPENSSL
	SSL_CTX *ctx;
	BIO *web;
#endif

#ifdef RRR_WITH_LIBRESSL
	struct tls *ctx;
#endif

};

int rrr_net_transport_tls_common_new (
		struct rrr_net_transport_tls **target,
		int flags,
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
int rrr_net_transport_tls_common_read_get_target_size (
		struct rrr_read_session *read_session,
		void *private_arg
);
int rrr_net_transport_tls_common_read_complete_callback (
		struct rrr_read_session *read_session,
		void *private_arg
);
void rrr_net_transport_tls_common_alpn_protos_to_str_comma_separated (
		unsigned char *out_buf,
		unsigned int out_size,
		const unsigned char *in,
		unsigned int in_size
);

#endif /* RRR_NET_TRANSPORT_TLS_COMMON_H */
