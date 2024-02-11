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

#ifndef RRR_NET_TRANSPORT_CONNECTION_ID_H
#define RRR_NET_TRANSPORT_CONNECTION_ID_H

#include <stdint.h>

#include "../util/linked_list.h"

#define RRR_NET_TRANSPORT_CONNECTION_ID_MAX 20

struct rrr_net_transport_connection_id {
	RRR_LL_NODE(struct rrr_net_transport_connection_id);
	uint8_t data[RRR_NET_TRANSPORT_CONNECTION_ID_MAX];
	size_t length;
};

struct rrr_net_transport_connection_id_collection {
	RRR_LL_HEAD(struct rrr_net_transport_connection_id);
};

struct rrr_net_transport_connection_id_pair {
	union {
		struct rrr_net_transport_connection_id a;
		struct rrr_net_transport_connection_id src;
	};
	union {
		struct rrr_net_transport_connection_id b;
		struct rrr_net_transport_connection_id dst;
	};
};

#define RRR_NET_TRANSPORT_CONNECTION_ID_DEFAULT_INITIALIZER \
    {.length = RRR_NET_TRANSPORT_CONNECTION_ID_MAX}

#define RRR_NET_TRANSPORT_CONNECTION_ID_PAIR_DEFAULT_INITIALIZER \
    {.a = RRR_NET_TRANSPORT_CONNECTION_ID_DEFAULT_INITIALIZER,.b = RRR_NET_TRANSPORT_CONNECTION_ID_DEFAULT_INITIALIZER}

void rrr_net_transport_connection_id_to_str (
		char *buf,
		size_t buf_len,
		const struct rrr_net_transport_connection_id *id
);
void rrr_net_transport_connection_id_collection_clear (
		struct rrr_net_transport_connection_id_collection *collection
);
int rrr_net_transport_connection_id_collection_has (
		const struct rrr_net_transport_connection_id_collection *collection,
		const struct rrr_net_transport_connection_id *cid
);
void rrr_net_transport_connection_id_collection_remove (
		struct rrr_net_transport_connection_id_collection *collection,
		const struct rrr_net_transport_connection_id *cid
);
int rrr_net_transport_connection_id_collection_push (
		struct rrr_net_transport_connection_id_collection *collection,
		const struct rrr_net_transport_connection_id *cid
);

#endif /* RRR_NET_TRANSPORT_CONNECTION_ID_H */
