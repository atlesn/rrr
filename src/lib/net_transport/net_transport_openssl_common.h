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

#ifndef RRR_NET_TRANSPORT_OPENSSL_COMMON_H
#define RRR_NET_TRANSPORT_OPENSSL_COMMON_H

#include <openssl/ssl.h>

struct rrr_net_transport_tls_alpn;
struct rrr_net_transport_tls_data;
struct rrr_ip_data;

struct rrr_net_transport_tls_data *rrr_net_transport_openssl_common_ssl_data_new (void);
void rrr_net_transport_openssl_common_ssl_data_destroy (
		struct rrr_net_transport_tls_data *ssl_data
);
void rrr_net_transport_openssl_common_ssl_data_ip_replace (
		struct rrr_net_transport_tls_data *ssl_data,
		const struct rrr_ip_data *ip_data
);
int rrr_net_transport_openssl_common_alpn_selected_proto_get (
		char **target,
		SSL *ssl
);
int rrr_net_transport_openssl_common_new_ctx (
		SSL_CTX **target,
		const SSL_METHOD *method,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		struct rrr_net_transport_tls_alpn *alpn
);

#endif /* RRR_NET_TRANSPORT_OPENSSL_COMMON_H */
