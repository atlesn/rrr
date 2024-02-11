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

#ifndef RRR_NET_TRANSPORT_DEFINES_H
#define RRR_NET_TRANSPORT_DEFINES_H

#include "../socket/rrr_socket_read.h"
#include "../read_constants.h"

#define RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY              (1<<0)
#define RRR_NET_TRANSPORT_F_TLS_VERSION_MIN_1_1             (1<<1)
#define RRR_NET_TRANSPORT_F_TLS_NO_ALPN                     (1<<2)
#define RRR_NET_TRANSPORT_F_QUIC_STREAM_OPEN_CB_LOCAL_ONLY  (1<<3)

#define RRR_NET_TRANSPORT_STREAM_F_LOCAL               (1<<0)
#define RRR_NET_TRANSPORT_STREAM_F_BIDI                (1<<1)
#define RRR_NET_TRANSPORT_STREAM_F_CLOSING             (1<<2)
#define RRR_NET_TRANSPORT_STREAM_F_BLOCKED             (1<<3)
#define RRR_NET_TRANSPORT_STREAM_F_SHUTDOWN_WRITE      (1<<4)
#define RRR_NET_TRANSPORT_STREAM_F_SHUTDOWN_READ       (1<<5)
#define RRR_NET_TRANSPORT_STREAM_F_LOCAL_BIDI                            \
    (RRR_NET_TRANSPORT_STREAM_F_LOCAL|RRR_NET_TRANSPORT_STREAM_F_BIDI)

#define RRR_NET_TRANSPORT_READ_OK				RRR_READ_OK
#define RRR_NET_TRANSPORT_READ_HARD_ERROR		RRR_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_READ_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_READ_INCOMPLETE		RRR_READ_INCOMPLETE
#define RRR_NET_TRANSPORT_READ_BUSY			RRR_READ_BUSY
#define RRR_NET_TRANSPORT_READ_READ_EOF			RRR_READ_EOF
#define RRR_NET_TRANSPORT_READ_RATELIMIT                RRR_READ_RATELIMIT

#define RRR_NET_TRANSPORT_SEND_OK				RRR_NET_TRANSPORT_READ_OK
#define RRR_NET_TRANSPORT_SEND_HARD_ERROR		RRR_NET_TRANSPORT_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_SEND_SOFT_ERROR		RRR_NET_TRANSPORT_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_SEND_INCOMPLETE		RRR_NET_TRANSPORT_READ_INCOMPLETE

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH	RRR_READ_COMPLETE_METHOD_TARGET_LENGTH
#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE		RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ

enum rrr_net_transport_type {
	RRR_NET_TRANSPORT_NONE     = 0,
	RRR_NET_TRANSPORT_PLAIN    = 1,
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
	RRR_NET_TRANSPORT_TLS      = 2,
#endif
#if defined(RRR_WITH_HTTP3)
	RRR_NET_TRANSPORT_QUIC     = 4
#endif
};

enum rrr_net_transport_type_f {
	RRR_NET_TRANSPORT_F_NONE   = 0,
	RRR_NET_TRANSPORT_F_PLAIN  = 1,
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
	RRR_NET_TRANSPORT_F_TLS    = 2,
#endif
#if defined(RRR_WITH_HTTP3)
	RRR_NET_TRANSPORT_F_QUIC   = 4
#endif
};

#if (defined (RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)) && defined(RRR_WITH_HTTP3)
#  define RRR_NET_TRANSPORT_F_TLSISH (RRR_NET_TRANSPORT_F_TLS|RRR_NET_TRANSPORT_F_QUIC)
#elif defined (RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
#  define RRR_NET_TRANSPORT_F_TLSISH (RRR_NET_TRANSPORT_F_TLS)
#elif defined (RRR_WITH_HTTP3)
#  error "RRR_WITH_HTTP3 defined without RRR_WITH_LIBRESSL or RRR_WITH_OPENSSL"
#endif

enum rrr_net_transport_socket_mode {
	RRR_NET_TRANSPORT_SOCKET_MODE_ANY,
	RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
	RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION
};

enum rrr_net_transport_close_reason {
	RRR_NET_TRANSPORT_CLOSE_REASON_NO_ERROR,
	RRR_NET_TRANSPORT_CLOSE_REASON_INTERNAL_ERROR,
	RRR_NET_TRANSPORT_CLOSE_REASON_CONNECTION_REFUSED,
	RRR_NET_TRANSPORT_CLOSE_REASON_APPLICATION_ERROR
};

#endif /* RRR_NET_TRANSPORT_DEFINES_H */
