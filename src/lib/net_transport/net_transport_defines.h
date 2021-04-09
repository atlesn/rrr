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

#ifndef RRR_NET_TRANSPORT_DEFINES_H
#define RRR_NET_TRANSPORT_DEFINES_H

#include "../socket/rrr_socket_read.h"
#include "../read_constants.h"

#define RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY	(1<<0)
#define RRR_NET_TRANSPORT_F_TLS_VERSION_MIN_1_1	(1<<1)
#define RRR_NET_TRANSPORT_F_TLS_NO_ALPN			(1<<2)

#define RRR_NET_TRANSPORT_READ_OK				RRR_READ_OK
#define RRR_NET_TRANSPORT_READ_HARD_ERROR		RRR_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_READ_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_READ_INCOMPLETE		RRR_READ_INCOMPLETE
#define RRR_NET_TRANSPORT_READ_READ_EOF			RRR_READ_EOF
#define RRR_NET_TRANSPORT_READ_RATELIMIT                RRR_READ_RATELIMIT

#define RRR_NET_TRANSPORT_SEND_OK				RRR_NET_TRANSPORT_READ_OK
#define RRR_NET_TRANSPORT_SEND_HARD_ERROR		RRR_NET_TRANSPORT_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_SEND_SOFT_ERROR		RRR_NET_TRANSPORT_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_SEND_INCOMPLETE		RRR_NET_TRANSPORT_READ_INCOMPLETE

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH	RRR_READ_COMPLETE_METHOD_TARGET_LENGTH
#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE		RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ

enum rrr_net_transport_type {
	RRR_NET_TRANSPORT_BOTH,
	RRR_NET_TRANSPORT_PLAIN,
	RRR_NET_TRANSPORT_TLS
};

enum rrr_net_transport_socket_mode {
	RRR_NET_TRANSPORT_SOCKET_MODE_ANY,
	RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
	RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION
};

#endif /* RRR_NET_TRANSPORT_DEFINES_H */
