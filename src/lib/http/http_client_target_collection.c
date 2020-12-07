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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "http_client_target_collection.h"
#include "../util/linked_list.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../net_transport/net_transport.h"

void rrr_http_client_target_destroy_and_close (
		struct rrr_http_client_target *target,
		struct rrr_net_transport *transport_or_null
) {
	RRR_FREE_IF_NOT_NULL(target->server);
	if (transport_or_null != NULL && target->keepalive_handle != 0) {
		//rrr_net_transport_handle_close_tag_list_push(transport_or_null, target->keepalive_handle);
		rrr_net_transport_handle_close(transport_or_null, target->keepalive_handle);
	}
	free(target);
}

int rrr_http_client_target_new (
		struct rrr_http_client_target **target,
		const char *server,
		uint16_t port
) {
	*target = NULL;

	int ret = 0;

	struct rrr_http_client_target *new_target = NULL;
	if ((new_target = malloc(sizeof(*new_target))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_client_target_new\n");
		ret = 1;
		goto out;
	}

	memset(new_target, '\0', sizeof(*new_target));

	if ((new_target->server = strdup(server)) == NULL) {
		RRR_MSG_0("Could not allocate memory for server in rrr_http_client_target_new\n");
		ret = 1;
		goto out_free;
	}

	new_target->port = port;
	new_target->last_used = rrr_time_get_64();

	*target = new_target;

	goto out;
//	out_free_server:
//		free(new_target->server);
	out_free:
		free(new_target);
	out:
		return ret;
}

void rrr_http_client_target_collection_clear (
		struct rrr_http_client_target_collection *collection,
		struct rrr_net_transport *transport_or_null
) {
	RRR_LL_DESTROY(collection, struct rrr_http_client_target, rrr_http_client_target_destroy_and_close(node, transport_or_null));
}

struct rrr_http_client_target *rrr_http_client_target_find_or_new (
		struct rrr_http_client_target_collection *collection,
		const char *server,
		uint16_t port
) {
	static struct rrr_http_client_target *result = NULL;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_http_client_target);
		if (strcmp(server, node->server) == 0 && port == node->port) {
			result = node;
			node->last_used = rrr_time_get_64();
			goto out;
		}
	RRR_LL_ITERATE_END();

	if (rrr_http_client_target_new(&result, server, port) != 0) {
		goto out;
	}

	RRR_LL_PUSH(collection, result);

	out:
	return result;
}

void rrr_http_client_target_collection_remove (
		struct rrr_http_client_target_collection *collection,
		int keepalive_handle,
		struct rrr_net_transport *transport_or_null
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_http_client_target);
		if (node->keepalive_handle == keepalive_handle) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; rrr_http_client_target_destroy_and_close(node, transport_or_null));
}
