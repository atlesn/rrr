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
struct rrr_net_transport_handle *rrr_net_transport_handle_get (
		struct rrr_net_transport *transport,
		int handle
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	struct rrr_net_transport_handle *result = NULL;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			result = node;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return result;
}

static int __rrr_net_transport_handle_create_and_push_unlocked (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		int handle,
		enum rrr_net_transport_socket_mode mode,
		void *private_ptr
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	*handle_final = NULL;

	struct rrr_net_transport_handle *new_handle = NULL;

	if ((new_handle = malloc(sizeof(*new_handle))) == NULL) {
		RRR_MSG_ERR("Could not allocate handle in __rrr_net_transport_handle_collection_handle_add_unlocked\n");
		ret = 1;
		goto out;
	}

	memset(new_handle, '\0', sizeof(*new_handle));

	new_handle->transport = transport;
	new_handle->handle = handle;
	new_handle->mode = mode;
	new_handle->submodule_private_ptr = private_ptr;

	RRR_LL_APPEND(collection, new_handle);

	*handle_final = new_handle;

	out:
	return ret;
}

int rrr_net_transport_handle_add (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		int handle,
		enum rrr_net_transport_socket_mode mode,
		void *private_ptr
) {
	int ret = 0;

	*handle_final = NULL;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	ret = __rrr_net_transport_handle_create_and_push_unlocked(handle_final, transport, handle, mode, private_ptr);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return ret;
}

/* Allocate an unused handle. The strategy is to begin with 1, check if it is available,
 * and if not continue incrementing to find the first available. This should be efficient
 * considering the lifetime of connections is usually short thus handles may be re-used. */
int rrr_net_transport_handle_allocate_and_add (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		void *private_ptr
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	*handle_final = NULL;

	int new_handle_id = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	if (RRR_LL_COUNT(collection) >= RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX) {
		RRR_MSG_ERR("Error: Max number of handles (%i) reached in rrr_net_transport_handle_allocate_and_add\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = 1;
		goto out;
	}

	int max_attempts = 100000;
	for (int i = collection->next_handle_position; --max_attempts > 0; i++) {
		if (i <= 0 || i > 99999999) {
			i = 1;
		}

		int was_taken = 0;
		RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
			if (node->handle == i) {
				was_taken = 1;
				RRR_LL_ITERATE_LAST();
			}
		RRR_LL_ITERATE_END();

		if (was_taken == 0) {
			new_handle_id = i;
			break;
		}
	}

	if (new_handle_id == 0) {
		RRR_MSG_ERR("Max attempts reached while allocating handle in rrr_net_transport_handle_allocate_and_add\n");
		ret = 1;
		goto out;
	}

	collection->next_handle_position = new_handle_id + 1;

	if (new_handle_id == 0) {
		RRR_MSG_ERR("No free handles in rrr_net_transport_handle_collection_allocate_and_add_handle, max is %i\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_net_transport_handle_create_and_push_unlocked(
			handle_final,
			transport,
			new_handle_id,
			mode,
			private_ptr
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}

static int __rrr_net_transport_handle_destroy (
		struct rrr_net_transport_handle *handle
) {
	rrr_read_session_collection_clear(&handle->read_sessions);

	handle->transport->methods->close(handle);

	if (handle->application_private_ptr != NULL && handle->application_ptr_destroy != NULL) {
		handle->application_ptr_destroy(handle->application_private_ptr);
	}

	free(handle);
	// Always return success because we always free() regardless of callback result
	return RRR_LL_DID_DESTROY;
}

int rrr_net_transport_handle_remove (
		struct rrr_net_transport *transport,
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	int ll_count = RRR_LL_COUNT(collection);

	RRR_LL_REMOVE_NODE(collection, struct rrr_net_transport_handle, handle, __rrr_net_transport_handle_destroy(node));

	if (ll_count == RRR_LL_COUNT(collection)) {
		RRR_MSG_ERR("Warning: Handle %i not found while destroying in rrr_net_transport_handle_collection_handle_remove\n", handle->handle);
		ret = 1;
	}

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return ret;
}

void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_DESTROY(
			collection,
			struct rrr_net_transport_handle,
			__rrr_net_transport_handle_destroy (node)
	);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
}

int rrr_net_transport_new (
		struct rrr_net_transport **result,
		enum rrr_net_transport_type transport,
		int flags,
		const char *certificate_file,
		const char *private_key_file
) {
	int ret = 0;

	*result = NULL;

	struct rrr_net_transport *new_transport = NULL;
	switch (transport) {
		case RRR_NET_TRANSPORT_PLAIN:
			if (flags != 0) {
				RRR_BUG("BUG: Plain method does not support flags in rrr_net_transport_new but flags were given\n");
			}
			if (certificate_file != NULL || private_key_file != NULL) {
				RRR_BUG("BUG: Plain method does not support certificate file and key file in rrr_net_transport_new but they were given\n");
			}
			ret = rrr_net_transport_plain_new((struct rrr_net_transport_plain **) &new_transport);
			break;
#ifdef RRR_WITH_OPENSSL
		case RRR_NET_TRANSPORT_TLS:
			ret = rrr_net_transport_tls_new((struct rrr_net_transport_tls **) &new_transport, flags, certificate_file, private_key_file);
			break;
#endif
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
		free(new_transport); // Must also free, destroy does not do that
	out:
		return ret;
}

void rrr_net_transport_destroy (struct rrr_net_transport *transport) {
	transport->methods->destroy(transport);
	pthread_mutex_destroy(&transport->handles.lock);
	free(transport);
}

#define RRR_NET_TRANSPORT_HANDLE_DECLARE_AND_GET(error_source) 										\
	struct rrr_net_transport_handle *handle = NULL;													\
	do {if ((handle = rrr_net_transport_handle_get(transport, transport_handle)) == NULL) {			\
		RRR_MSG_ERR("Could not find transport handle %i in " error_source "\n", transport_handle);	\
		return 1;																					\
	}} while(0)

int rrr_net_transport_close (
		struct rrr_net_transport *transport,
		int transport_handle
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_DECLARE_AND_GET("rrr_net_transport_close");

	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_REMOVE_NODE(collection, struct rrr_net_transport_handle, handle, ret = __rrr_net_transport_handle_destroy(node));
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return ret;
}

int rrr_net_transport_connect (
		int *handle,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {
	if (host == NULL) {
		RRR_BUG("host was NULL in rrr_net_transport_connect\n");
	}
	if (port == 0) {
		RRR_BUG("port was 0 in rrr_net_transport_connect\n");
	}
	return transport->methods->connect(handle, transport, port, host);
}

int rrr_net_transport_read_message (
		struct rrr_net_transport *transport,
		int transport_handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	RRR_NET_TRANSPORT_HANDLE_DECLARE_AND_GET("rrr_net_transport_read_message");

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to rrr_net_transport_read_message was not of CONNECTION type\n");
	}

	return transport->methods->read_message (
			handle,
			read_attempts,
			read_step_initial,
			read_step_max_size,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	);
}

int rrr_net_transport_read_message_all_handles (
		struct rrr_net_transport *transport,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if ((ret = transport->methods->read_message (
				node,
				read_attempts,
				read_step_initial,
				read_step_max_size,
				get_target_size,
				get_target_size_arg,
				complete_callback,
				complete_callback_arg
		)) != 0) {
			if (ret == RRR_READ_INCOMPLETE) {
				ret = 0;
				RRR_LL_ITERATE_NEXT();
			}
			else if (ret == RRR_READ_SOFT_ERROR) {
				ret = 0;
				RRR_LL_ITERATE_SET_DESTROY();
			}
			else {
				RRR_MSG_ERR("Error %i from read function in rrr_net_transport_read_message_all_handles\n", ret);
				ret = 1;
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_net_transport_handle_destroy(node));

	out:
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}

int rrr_net_transport_send_blocking (
		struct rrr_net_transport *transport,
		int transport_handle,
		const void *data,
		ssize_t size
) {
	RRR_NET_TRANSPORT_HANDLE_DECLARE_AND_GET("rrr_net_transport_send");

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to rrr_net_transport_send_blocking was not of CONNECTION type\n");
	}

	int ret = 0;

	ssize_t written_bytes = 0;
	ssize_t written_bytes_total = 0;

	while (ret != 0) {
		if ((ret = transport->methods->send (
				&written_bytes,
				handle,
				data + written_bytes_total,
				size - written_bytes_total
		)) != 0) {
			if (ret != RRR_NET_TRANSPORT_SEND_SOFT_ERROR) {
				RRR_MSG_ERR("Error from submodule send() in rrr_net_transport_send_blocking\n");
				goto out;
			}
		}
		written_bytes_total += written_bytes;
	}

	out:
	return ret;
}

int rrr_net_transport_bind_and_listen (
		int *new_handle,
		struct rrr_net_transport *transport,
		unsigned int port
) {
	return transport->methods->bind_and_listen(new_handle, transport, port);
}

int rrr_net_transport_accept (
		int *new_handle,
		struct sockaddr *sockaddr,
		socklen_t *socklen,
		struct rrr_net_transport *transport,
		int transport_handle
) {
	RRR_NET_TRANSPORT_HANDLE_DECLARE_AND_GET("rrr_net_transport_accept");

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
		RRR_BUG("BUG: Handle to rrr_net_transport_accept was not a listening FD\n");
	}

	return transport->methods->accept(new_handle, sockaddr, socklen, handle);
}

int rrr_net_transport_handle_bind_application_data (
		struct rrr_net_transport *transport,
		int transport_handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
) {
	RRR_NET_TRANSPORT_HANDLE_DECLARE_AND_GET("rrr_net_transport_handle_bind_application_data");

	if (handle->application_private_ptr != NULL) {
		RRR_BUG("rrr_net_transport_handle_bind_application_data called twice, pointer was already set\n");
	}

	handle->application_private_ptr = application_data;
	handle->application_ptr_destroy = application_data_destroy;

	return 0;
}
