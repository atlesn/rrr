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

#ifndef RRR_NET_TRANSPORT_TLS_H
#define RRR_NET_TRANSPORT_TLS_H

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)

#include "net_transport_defines.h"

#ifdef RRR_WITH_LIBRESSL
#	include "net_transport_libressl.h"
#endif
#ifdef RRR_WITH_OPENSSL
#	include "net_transport_openssl.h"
#endif

static inline int rrr_net_transport_tls_new (
		struct rrr_net_transport_tls **target,
		enum rrr_net_transport_subtype subtype,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
	if (flags & RRR_NET_TRANSPORT_F_TLS_NO_ALPN) {
		alpn_protos = NULL;
		alpn_protos_length = 0;
	}

	switch (subtype) {
		case RRR_NET_TRANSPORT_TLS_NONE:
#ifdef RRR_WITH_LIBRESSL
		case RRR_NET_TRANSPORT_TLS_LIBRESSL:
			return rrr_net_transport_libressl_new (
					target,
					flags,
					certificate_file,
					private_key_file,
					ca_file,
					ca_path,
					alpn_protos,
					alpn_protos_length
			);
#endif
#ifdef RRR_WITH_OPENSSL
		case RRR_NET_TRANSPORT_TLS_OPENSSL:
			return rrr_net_transport_openssl_new (
					target,
					flags,
					certificate_file,
					private_key_file,
					ca_file,
					ca_path,
					alpn_protos,
					alpn_protos_length
			);
#endif
		default:
			RRR_BUG("BUG: Unknown subtype %i in %s", subtype, __func__);
			break;
	};
}

#endif /* RRR_WITH_LIBRESSL || RRR_WITH_OPENSSL */

#endif /* RRR_NET_TRANSPORT_TLS_H */
