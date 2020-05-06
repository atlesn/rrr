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

#ifndef RRR_NET_TRANSPORT_TLS_H
#define RRR_NET_TRANSPORT_TLS_H

#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>

#include "net_transport.h"

struct rrr_net_transport_tls {
	RRR_NET_TRANSPORT_HEAD;

	const SSL_METHOD *ssl_client_method;
	const SSL_METHOD *ssl_server_method;
	int flags;
	char *certificate_file;
	char *private_key_file;
};

int rrr_net_transport_tls_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file
);

#endif /* RRR_NET_TRANSPORT_TLS_H */
