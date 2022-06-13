/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NET_TRANSPORT_QUIC_H
#define RRR_NET_TRANSPORT_QUIC_H

#include "net_transport_tls_common.h"

struct rrr_net_transport_tls;
typedef struct rrr_net_transport_quic_vec rrr_net_transport_quic_vec;

typedef int (*rrr_net_transport_quic_cb_ready)(void *arg);
typedef int (*rrr_net_transport_quic_cb_get_data)(int64_t *stream_id, rrr_net_transport_quic_vec *vec, size_t *vec_count, int *fin, void *arg);
typedef int (*rrr_net_transport_quic_cb_ack_data)(int64_t stream_id, size_t bytes, void *arg);
typedef int (*rrr_net_transport_quic_cb_deliver_data)(size_t *consumed, int64_t stream_id, const uint8_t *buf, size_t buflen, int fin, void *arg);
typedef int (*rrr_net_transport_quic_cb_block_stream)(int64_t stream_id, int blocked, void *arg);

struct rrr_net_transport_quic_callbacks {
	rrr_net_transport_quic_cb_ready cb_ready;
	rrr_net_transport_quic_cb_get_data cb_get_data;
	rrr_net_transport_quic_cb_ack_data cb_ack_data;
	rrr_net_transport_quic_cb_deliver_data cb_deliver_data;
	rrr_net_transport_quic_cb_block_stream cb_block_stream;
};

int rrr_net_transport_quic_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
);

#endif /* RRR_NET_TRANSPORT_QUIC_H */
