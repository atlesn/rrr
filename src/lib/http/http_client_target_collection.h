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

#ifndef RRR_HTTP_TARGET_COLLECTION_H
#define RRR_HTTP_TARGET_COLLECTION_H

#include <stdint.h>

#include "../util/linked_list.h"

struct rrr_net_transport;

struct rrr_http_client_target {
	RRR_LL_NODE(struct rrr_http_client_target);
	char *server;
	uint16_t port;
	int keepalive_handle;
	uint64_t last_used;
};

struct rrr_http_client_target_collection {
	RRR_LL_HEAD(struct rrr_http_client_target);
};

void rrr_http_client_target_destroy_and_close (
		struct rrr_http_client_target *target,
		struct rrr_net_transport *transport_or_null
);
int rrr_http_client_target_new (
		struct rrr_http_client_target **target,
		const char *server,
		uint16_t port
);
void rrr_http_client_target_collection_clear (
		struct rrr_http_client_target_collection *collection,
		struct rrr_net_transport *transport_or_null
);
struct rrr_http_client_target *rrr_http_client_target_find_or_new (
		struct rrr_http_client_target_collection *collection,
		const char *server,
		uint16_t port
);
void rrr_http_client_target_collection_remove (
		struct rrr_http_client_target_collection *collection,
		int keepalive_handle,
		struct rrr_net_transport *transport_or_null
);

#endif /* RRR_HTTP_TARGET_COLLECTION_H */
