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
#include <pthread.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#define RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX 65535

#include "../global.h"
#include "net_transport.h"
#include "net_transport_tls.h"
#include "net_transport_plain.h"

#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK() \
		pthread_mutex_lock(&collection->lock)
#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK() \
		pthread_mutex_unlock(&collection->lock)

// TODO : Consider refcounting returned object
void *rrr_net_transport_handle_collection_handle_get_private_ptr (
		struct rrr_net_transport_handle_collection *collection,
		int handle
) {
	void *result = NULL;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			result = node->private_ptr;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return result;
}

static int __rrr_net_transport_handle_collection_handle_add_unlocked (
		struct rrr_net_transport_handle_collection *collection,
		int handle,
		void *private_ptr
) {
	int ret = 0;

	struct rrr_net_transport_handle *new_handle = NULL;

	if ((new_handle = malloc(sizeof(*new_handle))) == NULL) {
		RRR_MSG_ERR("Could not allocate handle in __rrr_net_transport_handle_collection_handle_add_unlocked\n");
		ret = 1;
		goto out;
	}

	memset(new_handle, '\0', sizeof(*new_handle));

	new_handle->handle = handle;
	new_handle->private_ptr = private_ptr;

	RRR_LL_APPEND(collection, new_handle);

	out:
	return ret;
}

int rrr_net_transport_handle_collection_handle_add (
		struct rrr_net_transport_handle_collection *collection,
		int handle,
		void *private_ptr
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	ret = __rrr_net_transport_handle_collection_handle_add_unlocked(collection, handle, private_ptr);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return ret;
}

/* Allocate an unused handle. The strategy is to begin with 1, check if it is available,
 * and if not continue incrementing to find the first available. This should be efficient
 * considering the lifetime of connections is usually short thus handles may be re-used. */
int rrr_net_transport_handle_collection_allocate_and_add_handle (
		int *final_handle,
		struct rrr_net_transport_handle_collection *collection,
		void *private_ptr
) {
	int ret = 0;

	*final_handle = 0;

	int new_handle = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	for (int i = 1; i <= RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX; i++) {
		int was_taken = 0;

		RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
			if (node->handle == i) {
				was_taken = 1;
				RRR_LL_ITERATE_LAST();
			}
		RRR_LL_ITERATE_END();

		if (was_taken == 0) {
			new_handle = i;
			break;
		}
	}

	if (new_handle == 0) {
		RRR_MSG_ERR("No free handles in rrr_net_transport_handle_collection_allocate_and_add_handle, max is %i\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_net_transport_handle_collection_handle_add_unlocked(collection, new_handle, private_ptr)) != 0) {
		ret = 1;
		goto out;
	}

	*final_handle = new_handle;

	out:
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}

static int __rrr_net_transport_handle_destroy_with_callback (
		struct rrr_net_transport_handle *handle,
		int (*callback)(int handle, void *private_ptr, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if ((ret = callback(handle->handle, handle->private_ptr, callback_arg)) != 0) {
		RRR_MSG_ERR("Warning: Error %i from callback in __rrr_net_transport_handle_destroy_with_callback\n", ret);
	}

	free(handle);

	// Always return success because we always free() regardless of callback result
	return RRR_LL_DID_DESTROY;
}

int rrr_net_transport_handle_collection_handle_remove (
		struct rrr_net_transport_handle_collection *collection,
		int handle,
		int (*destroy_func)(int handle, void *private_ptr, void *arg),
		void *destroy_func_arg
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

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

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return ret;
}

void rrr_net_transport_handle_collection_clear (
		struct rrr_net_transport_handle_collection *collection,
		int (*destroy_func)(int handle, void *private_ptr, void *arg),
		void *destroy_func_arg
) {
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_DESTROY(
			collection,
			struct rrr_net_transport_handle,
			__rrr_net_transport_handle_destroy_with_callback(
					node,
					destroy_func,
					destroy_func_arg
			)
	);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
}

int rrr_net_transport_new (struct rrr_net_transport **result, enum rrr_net_transport_type transport, int flags) {
	int ret = 0;

	*result = NULL;

	struct rrr_net_transport *new_transport = NULL;
	switch (transport) {
		case RRR_NET_TRANSPORT_PLAIN:
			if (flags != 0) {
				RRR_BUG("BUG: Plain method does not support flags in rrr_net_transport_new but flags were given\n");
			}
			ret = rrr_net_transport_plain_new((struct rrr_net_transport_plain **) &new_transport);
			break;
		case RRR_NET_TRANSPORT_TLS:
			ret = rrr_net_transport_tls_new((struct rrr_net_transport_tls **) &new_transport, flags);
			break;
		default:
			RRR_BUG("Transport method %i not implemented in rrr_net_transport_new\n", transport);
			break;
	};

	if (new_transport == NULL) {
		RRR_MSG_ERR("Could not allocate transport method in rrr_net_transport_new\n");
		ret = 1;
		goto out;
	}

	if (pthread_mutex_init (&new_transport->handles.lock, 0) != 0) {
		RRR_MSG_ERR("Could not initialize handle collection lock in rrr_net_transport_new\n");
		ret = 1;
		goto out_destroy;
	}

	*result = new_transport;

	goto out;
	out_destroy:
		new_transport->methods->destroy(new_transport);
	out:
		return ret;
}

void rrr_net_transport_destroy (struct rrr_net_transport *transport) {
	pthread_mutex_destroy(&transport->handles.lock);
	transport->methods->destroy(transport);
}

int rrr_net_transport_close (
		struct rrr_net_transport *transport,
		int handle
) {
	void *private_ptr = rrr_net_transport_handle_collection_handle_get_private_ptr(&transport->handles, handle);

	// Method must be able to handle any NULL private_ptr
	return transport->methods->close(transport, private_ptr, handle);
}
