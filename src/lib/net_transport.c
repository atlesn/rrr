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

#include "log.h"
#include "net_transport.h"
#include "net_transport_tls.h"
#include "net_transport_plain.h"

#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK() \
		pthread_mutex_lock(&collection->lock)

#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK() \
		pthread_mutex_unlock(&collection->lock)

static struct rrr_net_transport_handle *__rrr_net_transport_handle_get_and_lock (
		struct rrr_net_transport *transport,
		int handle
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	struct rrr_net_transport_handle *result = NULL;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			result = node;
			// Lock prior to releasing collection lock to prevent race conditions
			// with anyone calling close(). Closers will try to lock this lock
			// prior to destruction.
			pthread_mutex_lock(&result->lock);
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return result;
}

static void __rrr_net_transport_handle_unlock(void *arg) {
	struct rrr_net_transport_handle *handle = arg;
	pthread_mutex_unlock(&handle->lock);
}

#define RRR_NET_TRANSPORT_HANDLE_GET_AND_LOCK(error_source) 											\
	do {struct rrr_net_transport_handle *handle = NULL;													\
	if ((handle = __rrr_net_transport_handle_get_and_lock(transport, transport_handle)) == NULL) {		\
		RRR_MSG_0("Could not find transport handle %i in " error_source "\n", transport_handle);		\
		return 1;																						\
	}																									\
	pthread_cleanup_push(__rrr_net_transport_handle_unlock, handle)

#define RRR_NET_TRANSPORT_HANDLE_UNLOCK() \
	pthread_cleanup_pop(1); } while(0)

static int __rrr_net_transport_handle_create_and_push_return_locked (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		int handle,
		enum rrr_net_transport_socket_mode mode,
		void *submodule_private_ptr,
		int submodule_private_fd
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	*handle_final = NULL;

	struct rrr_net_transport_handle *new_handle = NULL;
	pthread_mutexattr_t mutexattr;

	if (pthread_mutexattr_init(&mutexattr) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_net_transport_handle_create_and_push_return_locked\n");
		ret = 1;
		goto out;

	}

	if (pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE) != 0) {
		RRR_MSG_0("pthread_mutexattr_settype failed in in __rrr_net_transport_handle_create_and_push_return_locked\n");
		ret = 1;
		goto out_destroy_mutexattr;

	}

	if ((new_handle = malloc(sizeof(*new_handle))) == NULL) {
		RRR_MSG_0("Could not allocate handle in __rrr_net_transport_handle_create_and_push_return_locked\n");
		ret = 1;
		goto out_destroy_mutexattr;
	}

	memset(new_handle, '\0', sizeof(*new_handle));

	if (pthread_mutex_init(&new_handle->lock, &mutexattr) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_net_transport_handle_create_and_push_return_locked\n");
		goto out_free;
	}

	pthread_mutex_lock(&new_handle->lock);
	new_handle->transport = transport;
	new_handle->handle = handle;
	new_handle->mode = mode;
	new_handle->submodule_private_ptr = submodule_private_ptr;
	new_handle->submodule_private_fd = submodule_private_fd;

	RRR_LL_APPEND(collection, new_handle);

	*handle_final = new_handle;

	goto out_destroy_mutexattr;
	out_free:
		free(new_handle);
	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&mutexattr);
	out:
		return ret;
}

/* Allocate an unused handle. The strategy is to begin with 1, check if it is available,
 * and if not continue incrementing to find the first available. This should be efficient
 * considering the lifetime of connections is usually short thus handles may be re-used. */
int rrr_net_transport_handle_allocate_and_add_return_locked (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		void *submodule_private_ptr,
		int submodule_private_fd
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	*handle_final = NULL;

	int new_handle_id = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	if (RRR_LL_COUNT(collection) >= RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX) {
		RRR_MSG_0("Error: Max number of handles (%i) reached in rrr_net_transport_handle_allocate_and_add\n",
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
		RRR_MSG_0("Max attempts reached while allocating handle in rrr_net_transport_handle_allocate_and_add\n");
		ret = 1;
		goto out;
	}

	collection->next_handle_position = new_handle_id + 1;

	if (new_handle_id == 0) {
		RRR_MSG_0("No free handles in rrr_net_transport_handle_collection_allocate_and_add_handle, max is %i\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_net_transport_handle_create_and_push_return_locked (
			handle_final,
			transport,
			new_handle_id,
			mode,
			submodule_private_ptr,
			submodule_private_fd
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}

static int __rrr_net_transport_handle_destroy (
		struct rrr_net_transport_handle *handle,
		int already_locked
) {
	if (already_locked != 1) {
		pthread_mutex_lock(&handle->lock);
	}

	rrr_read_session_collection_clear(&handle->read_sessions);

	handle->transport->methods->close(handle);

	if (handle->application_private_ptr != NULL && handle->application_ptr_destroy != NULL) {
		handle->application_ptr_destroy(handle->application_private_ptr);
	}

	pthread_mutex_unlock(&handle->lock);
	pthread_mutex_destroy(&handle->lock);

	free(handle);
	// Always return success because we always free() regardless of callback result
	return RRR_LL_DID_DESTROY;
}

void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_DESTROY(
			collection,
			struct rrr_net_transport_handle,
			__rrr_net_transport_handle_destroy (node, 0)
	);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
}

int rrr_net_transport_new (
		struct rrr_net_transport **result,
		enum rrr_net_transport_type transport,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path
) {
	int ret = 0;

	*result = NULL;

	struct rrr_net_transport *new_transport = NULL;
	pthread_mutexattr_t mutexattr;

	if (pthread_mutexattr_init(&mutexattr) != 0) {
		RRR_MSG_0("Could not initialize lock in rrr_net_transport_new\n");
		ret = 1;
		goto out;

	}

	if (pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE) != 0) {
		RRR_MSG_0("pthread_mutexattr_settype failed in in rrr_net_transport_new\n");
		ret = 1;
		goto out_destroy_mutexattr;

	}

	switch (transport) {
		case RRR_NET_TRANSPORT_PLAIN:
			if (flags != 0) {
				RRR_BUG("BUG: Plain method does not support flags in rrr_net_transport_new but flags were given\n");
			}
			if (certificate_file != NULL || private_key_file != NULL || ca_file != NULL || ca_path != NULL) {
				RRR_BUG("BUG: Plain method does not support TLS parameters in rrr_net_transport_new but they were given\n");
			}
			ret = rrr_net_transport_plain_new((struct rrr_net_transport_plain **) &new_transport);
			break;
#ifdef RRR_WITH_OPENSSL
		case RRR_NET_TRANSPORT_TLS:
			ret = rrr_net_transport_tls_new (
					(struct rrr_net_transport_tls **) &new_transport,
					flags,
					certificate_file,
					private_key_file,
					ca_file,
					ca_path
			);
			break;
#endif
		default:
			RRR_BUG("Transport method %i not implemented in rrr_net_transport_new\n", transport);
			break;
	};

	if (new_transport == NULL) {
		RRR_MSG_0("Could not allocate transport method in rrr_net_transport_new\n");
		ret = 1;
		goto out_destroy_mutexattr;
	}

	if (pthread_mutex_init (&new_transport->handles.lock, &mutexattr) != 0) {
		RRR_MSG_0("Could not initialize handle collection lock in rrr_net_transport_new\n");
		ret = 1;
		goto out_destroy;
	}

	*result = new_transport;

	goto out;
	out_destroy:
		new_transport->methods->destroy(new_transport);
		free(new_transport); // Must also free, destroy does not do that
	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&mutexattr);
	out:
		return ret;
}

void rrr_net_transport_destroy (struct rrr_net_transport *transport) {
	transport->methods->destroy(transport);
	pthread_mutex_destroy(&transport->handles.lock);
	free(transport);
}

void rrr_net_transport_collection_destroy (struct rrr_net_transport_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_net_transport, rrr_net_transport_destroy(node));
}

void rrr_net_transport_ctx_handle_close (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_handle_collection *collection = &handle->transport->handles;

	int did_destroy = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_REMOVE_NODE_IF_EXISTS(collection, struct rrr_net_transport_handle, handle, did_destroy = 1; __rrr_net_transport_handle_destroy(node, 1));
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	if (did_destroy != 1) {
		RRR_BUG("Could not find transport handle %i in rrr_net_transport_close\n", handle->handle);
	}
}

int rrr_net_transport_handle_close (
		struct rrr_net_transport *transport,
		int transport_handle
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;
	int did_destroy = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		pthread_mutex_lock(&node->lock);
		if (node->handle == transport_handle) {
			ret = __rrr_net_transport_handle_destroy(node, 1);
			did_destroy = 1;
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
		else {
			pthread_mutex_unlock(&node->lock);
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	if (did_destroy != 1) {
		RRR_MSG_0("Could not find transport handle %i in rrr_net_transport_close\n", transport_handle);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg,
		int close_after_callback
) {
	if (host == NULL) {
		RRR_BUG("host was NULL in rrr_net_transport_connect_and_destroy_after_callback\n");
	}
	if (port == 0) {
		RRR_BUG("port was 0 in rrr_net_transport_connect_and_destroy_after_callback\n");
	}

	struct rrr_net_transport_handle *handle;
	struct sockaddr_storage addr;
	socklen_t socklen = sizeof(addr);

	// TODO : Distinguish between soft and hard connect errors

	if (transport->methods->connect (
			&handle,
			(struct sockaddr *) &addr,
			&socklen,
			transport,
			port,
			host
	) != 0) {
		return 1;
	}

	callback(handle, (struct sockaddr *) &addr, socklen, callback_arg);

	if (close_after_callback) {
		rrr_net_transport_ctx_handle_close(handle);
	}
	else {
		pthread_mutex_unlock(&handle->lock);
	}

	return 0;
}

int rrr_net_transport_connect_and_close_after_callback (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
) {
	return __rrr_net_transport_connect (transport, port, host, callback, callback_arg, 1);
}

int rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
) {
	return __rrr_net_transport_connect (transport, port, host, callback, callback_arg, 0);
}

int rrr_net_transport_ctx_read_message (
		struct rrr_net_transport_handle *handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to rrr_net_transport_read_message was not of CONNECTION type\n");
	}

	uint64_t bytes_read = 0;
	int ret = handle->transport->methods->read_message (
			&bytes_read,
			handle,
			read_attempts,
			read_step_initial,
			read_step_max_size,
			read_flags,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	);
	handle->bytes_read_total += bytes_read;

	return ret;
}

int rrr_net_transport_ctx_send_nonblock (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
) {
	int ret = 0;

	if (size < 0) {
		RRR_BUG("BUG: Size was < 0 in rrr_net_transport_ctx_send_nonblock\n");
	}

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to rrr_net_transport_ctx_send_nonblock was not of CONNECTION type\n");
	}

	uint64_t written_bytes = 0;

	if ((ret = handle->transport->methods->send (
			&written_bytes,
			handle,
			data,
			size
	)) != 0) {
		if (ret != RRR_NET_TRANSPORT_SEND_SOFT_ERROR) {
			RRR_MSG_1("Error from submodule send() in rrr_net_transport_send_nonblock\n");
			goto out;
		}
	}

	uint64_t size_tmp = (size >= 0 ? size : 0);
	if (written_bytes != size_tmp) {
		RRR_MSG_1("Not all bytes were sent %li < %li in rrr_net_transport_ctx_send_nonblock\n", written_bytes, size);
		ret = RRR_NET_TRANSPORT_SEND_INCOMPLETE;
	}

	handle->bytes_written_total += written_bytes;

	out:
	return ret;
}

int rrr_net_transport_ctx_send_blocking (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
) {
	int ret = 0;

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to rrr_net_transport_send_blocking was not of CONNECTION type\n");
	}

	uint64_t written_bytes = 0;
	uint64_t written_bytes_total = 0;

	do {
		if ((ret = handle->transport->methods->send (
				&written_bytes,
				handle,
				data + written_bytes_total,
				size - written_bytes_total
		)) != 0) {
			if (ret != RRR_NET_TRANSPORT_SEND_SOFT_ERROR) {
				RRR_MSG_0("Error from submodule send() in rrr_net_transport_send_blocking\n");
				break;
			}
		}
		written_bytes_total += written_bytes;
	} while (ret != 0);

	return ret;
}

void rrr_net_transport_ctx_handle_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
) {
	if (handle->application_private_ptr != NULL) {
		RRR_BUG("rrr_net_transport_handle_application_data_bind called twice, pointer was already set\n");
	}
	handle->application_private_ptr = application_data;
	handle->application_ptr_destroy = application_data_destroy;
}

int rrr_net_transport_handle_with_transport_ctx_do (
		struct rrr_net_transport *transport,
		int transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET_AND_LOCK("rrr_net_transport_handle_with_transport_ctx_do ");
	ret = callback(handle, arg);
	RRR_NET_TRANSPORT_HANDLE_UNLOCK();

	return ret;
}

int rrr_net_transport_iterate_with_callback (
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	int ret = 0;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		pthread_mutex_lock(&node->lock);

		if (mode != RRR_NET_TRANSPORT_SOCKET_MODE_ANY && mode != node->mode) {
			goto unlock;
		}

		if ((ret = callback (
				node,
				arg
		)) != 0) {
			if (ret == RRR_READ_INCOMPLETE) {
				ret = 0;
				goto unlock;
			}
			else if (ret == RRR_READ_SOFT_ERROR) {
				ret = 0;
				// For nice treatment of remote, for instance send a disconnect packet
				if (node->application_ptr_iterator_pre_destroy != NULL) {
					ret = node->application_ptr_iterator_pre_destroy(node, node->application_private_ptr);
				}

				if (ret == RRR_NET_TRANSPORT_READ_HARD_ERROR) {
					RRR_MSG_0("Internal error in rrr_net_transport_iterate_with_callback\n");
					RRR_LL_ITERATE_LAST();
					goto unlock;
				}

				// When pre_destroy returns 0 or is not set, go ahead with destruction
				if (ret == 0) {
					__rrr_net_transport_handle_destroy(node, 1);
					RRR_LL_ITERATE_SET_DESTROY();
					RRR_LL_ITERATE_NEXT(); // Skips unlock() at the bottom
				}
			}
			else {
				RRR_MSG_0("Error %i from read function in rrr_net_transport_iterate_with_callback\n", ret);
				ret = 1;
				RRR_LL_ITERATE_LAST();
			}
		}
		unlock:
		pthread_mutex_unlock(&node->lock);
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}
/*
 * These are disabled. They might not work correctly, especially not destruction
 * of handles when read functions return error. Test after enabling.
int rrr_net_transport_read_message (
		struct rrr_net_transport *transport,
		int transport_handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET_AND_LOCK("rrr_net_transport_read_message");

	ret = rrr_net_transport_ctx_read_message(
			handle,
			read_attempts,
			read_step_initial,
			read_step_max_size,
			read_flags,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	);

	RRR_NET_TRANSPORT_HANDLE_UNLOCK();

	return ret;
}

int rrr_net_transport_read_message_all_handles (
		struct rrr_net_transport *transport,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		pthread_mutex_lock(&node->lock);
		if ((ret = transport->methods->read_message (
				node,
				read_attempts,
				read_step_initial,
				read_step_max_size,
				read_flags,
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
				__rrr_net_transport_handle_destroy(node, 1);
				RRR_LL_ITERATE_SET_DESTROY();
				RRR_LL_ITERATE_NEXT(); // Skips unlock() at the bottom
			}
			else {
				RRR_MSG_0("Error %i from read function in rrr_net_transport_read_message_all_handles\n", ret);
				ret = 1;
				RRR_LL_ITERATE_LAST();
			}
		}
		pthread_mutex_unlock(&node->lock);
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}
*/
int rrr_net_transport_send_blocking (
		struct rrr_net_transport *transport,
		int transport_handle,
		const void *data,
		ssize_t size
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET_AND_LOCK("rrr_net_transport_send");

	ret = rrr_net_transport_ctx_send_blocking(handle, data, size);

	RRR_NET_TRANSPORT_HANDLE_UNLOCK();

	return ret;
}

int rrr_net_transport_bind_and_listen (
		struct rrr_net_transport *transport,
		unsigned int port,
		void (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	return transport->methods->bind_and_listen(transport, port, callback, arg);
}

int rrr_net_transport_accept (
		struct rrr_net_transport *transport,
		int transport_handle,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET_AND_LOCK("rrr_net_transport_accept");

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
		RRR_BUG("BUG: Handle to rrr_net_transport_accept was not a listening FD\n");
	}

	ret = transport->methods->accept(handle, callback, callback_arg);

	RRR_NET_TRANSPORT_HANDLE_UNLOCK();

	return ret;
}
