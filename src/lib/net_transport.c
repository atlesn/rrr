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

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "../global.h"
#include "net_transport.h"
#include "net_transport_tls.h"
#include "net_transport_plain.h"

int rrr_net_transport_handle_collection_handle_add (
		struct rrr_net_transport_handle_collection *collection,
		int handle
) {
	int ret = 0;

	struct rrr_net_transport_handle *new_handle = NULL;

	if ((new_handle = malloc(sizeof(*new_handle))) == NULL) {
		RRR_MSG_ERR("Could not allocate handle in rrr_net_transport_handle_collection_handle_add\n");
		ret = 1;
		goto out;
	}

	memset(new_handle, '\0', sizeof(*new_handle));

	new_handle->handle = handle;

	RRR_LL_APPEND(collection, new_handle);

	out:
	return ret;
}

static int __rrr_net_transport_handle_destroy_with_callback (
		struct rrr_net_transport_handle *handle,
		int (*callback)(int handle, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if ((ret = callback(handle->handle, callback_arg)) != 0) {
		RRR_MSG_ERR("Warning: Error %i from callback in __rrr_net_transport_handle_destroy_with_callback\n", ret);
	}

	free(handle);

	// Always return success because we always free() regardless of callback result
	return RRR_LL_DID_DESTROY;
}

int rrr_net_transport_handle_collection_handle_remove (
		struct rrr_net_transport_handle_collection *collection,
		int handle,
		int (*destroy_func)(int handle, void *arg),
		void *destroy_func_arg
) {
	int ret = 0;

	int did_destroy = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
			did_destroy = 1;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(
			collection,
			__rrr_net_transport_handle_destroy_with_callback(node, destroy_func, destroy_func_arg)
	);

	if (did_destroy == 0) {
		RRR_MSG_ERR("Warning: Handle %i not found while destroying in rrr_net_transport_handle_collection_handle_remove\n", handle);
		ret = 1;
	}

	return ret;
}

void rrr_net_transport_handle_collection_clear (
		struct rrr_net_transport_handle_collection *collection,
		int (*destroy_func)(int handle, void *arg),
		void *destroy_func_arg
) {
	RRR_LL_DESTROY(
			collection,
			struct rrr_net_transport_handle,
			__rrr_net_transport_handle_destroy_with_callback(
					node,
					destroy_func,
					destroy_func_arg
			)
	);
}

int rrr_net_transport_new (struct rrr_net_transport **result, enum rrr_net_transport_type transport) {
	int ret = 0;

	*result = NULL;

	struct rrr_net_transport *new_transport = NULL;
	switch (transport) {
		case RRR_NET_TRANSPORT_PLAIN:
			ret = rrr_net_transport_plain_new((struct rrr_net_transport_plain **) &new_transport);
			break;
/*		case RRR_NET_TRANSPORT_TLS:
			ret = rrr_net_transport_tls_new(&((struct rrr_net_transport_tls *) new_transport));
			break;*/
		default:
			RRR_BUG("Transport method %i not implemented in rrr_net_transport_new\n", transport);
			break;
	};

	if (new_transport == NULL) {
		RRR_MSG_ERR("Could not allocate transport method in rrr_net_transport_new\n");
		ret = 1;
		goto out;
	}

	*result = new_transport;

	out:
	return ret;
}
