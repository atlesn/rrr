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

#include "net_transport.h"
#include "net_transport_plain.h"
#include "net_transport_config.h"

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
#	include "net_transport_tls.h"
#endif

#include "../log.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"

#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK() 		\
	pthread_mutex_lock(&collection->lock)

#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_TRYLOCK() 	\
	pthread_mutex_trylock(&collection->lock)

#define RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK() 	\
	pthread_mutex_unlock(&collection->lock)

#define RRR_NET_TRANSPORT_HANDLE_TRYLOCK(handle,ctx)	\
	pthread_mutex_trylock(&((handle)->lock_))

#define RRR_NET_TRANSPORT_HANDLE_LOCK(_handle,ctx)		\
	pthread_mutex_lock(&((_handle)->lock_))

#define RRR_NET_TRANSPORT_HANDLE_UNLOCK(_handle,ctx)	\
	pthread_mutex_unlock(&((_handle)->lock_))

static struct rrr_net_transport_handle *__rrr_net_transport_handle_get_and_lock (
		struct rrr_net_transport *transport,
		int handle,
		const char *source
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	struct rrr_net_transport_handle *result = NULL;

	// May be used to print debug messages
	(void)(source);

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			result = node;
			// Lock prior to releasing collection lock to prevent race conditions
			// with anyone calling close(). Closers will try to lock this lock
			// prior to destruction.
			RRR_NET_TRANSPORT_HANDLE_LOCK(result, source);
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();

	return result;
}

static void __rrr_net_transport_handle_unlock(void *arg) {
	struct rrr_net_transport_handle *handle = arg;
	RRR_NET_TRANSPORT_HANDLE_UNLOCK(handle, "wrapper");
}

#define RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN(error_source) 															\
	do {struct rrr_net_transport_handle *handle = NULL;																	\
	if ((handle = __rrr_net_transport_handle_get_and_lock(transport, transport_handle, error_source)) == NULL) {		\
		RRR_MSG_0("Could not find transport handle %i in " error_source "\n", transport_handle);						\
		return 1;																										\
	}																													\
	pthread_cleanup_push(__rrr_net_transport_handle_unlock, handle)

#define RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT() \
	pthread_cleanup_pop(1); } while(0)

static int __rrr_net_transport_handle_create_and_push (
		struct rrr_net_transport *transport,
		int handle,
		enum rrr_net_transport_socket_mode mode,
		int (*submodule_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS),
		void *submodule_callback_arg
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	struct rrr_net_transport_handle *new_handle = NULL;

	if ((new_handle = malloc(sizeof(*new_handle))) == NULL) {
		RRR_MSG_0("Could not allocate handle in __rrr_net_transport_handle_create_and_push_return_locked\n");
		ret = 1;
		goto out;
	}

	memset(new_handle, '\0', sizeof(*new_handle));

	if (rrr_posix_mutex_init(&new_handle->lock_, RRR_POSIX_MUTEX_IS_RECURSIVE) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_net_transport_handle_create_and_push_return_locked\n");
		ret = 1;
		goto out_free;
	}

	RRR_NET_TRANSPORT_HANDLE_LOCK(new_handle, "__rrr_net_transport_handle_create_and_push");
	new_handle->transport = transport;

	// NOTE : These shallow members may be accessed with only collection lock held
	new_handle->handle = handle;
	new_handle->mode = mode;

	if ((ret = submodule_callback (
			&new_handle->submodule_private_ptr,
			&new_handle->submodule_private_fd,
			submodule_callback_arg
	)) != 0) {
		RRR_NET_TRANSPORT_HANDLE_UNLOCK(new_handle, "__rrr_net_transport_handle_create_and_push");
		goto out_destroy_mutex;
	}

	RRR_LL_APPEND(collection, new_handle);
	RRR_NET_TRANSPORT_HANDLE_UNLOCK(new_handle, "__rrr_net_transport_handle_create_and_push");

	goto out;
	out_destroy_mutex:
		pthread_mutex_destroy(&new_handle->lock_);
	out_free:
		free(new_handle);
	out:
		return ret;
}

/* Allocate an unused handle. The strategy is to begin with 1, check if it is available,
 * and if not continue incrementing to find the first available. This should be efficient
 * considering the lifetime of connections is usually short thus handles may be re-used. */
int rrr_net_transport_handle_allocate_and_add (
		int *handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*submodule_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS),
		void *submodule_callback_arg
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	*handle_final = 0;

	int new_handle_id = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	if (RRR_LL_COUNT(collection) >= RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX) {
		RRR_MSG_0("Error: Max number of handles (%i) reached in rrr_net_transport_handle_allocate_and_add\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
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
		RRR_MSG_0("No free handles in rrr_net_transport_handle_collection_allocate_and_add_handle, max is %i\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	collection->next_handle_position = new_handle_id + 1;

	if ((ret = __rrr_net_transport_handle_create_and_push (
			transport,
			new_handle_id,
			mode,
			submodule_callback,
			submodule_callback_arg
	)) != 0) {
		goto out;
	}

	*handle_final = new_handle_id;

	out:
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}

static int __rrr_net_transport_handle_destroy (
		struct rrr_net_transport_handle *handle,
		int already_locked
) {
	if (already_locked != 1) {
		RRR_NET_TRANSPORT_HANDLE_LOCK(handle, "__rrr_net_transport_handle_destroy");
	}

	rrr_read_session_collection_clear(&handle->read_sessions);

	handle->transport->methods->close(handle);

	if (handle->application_private_ptr != NULL && handle->application_ptr_destroy != NULL) {
		handle->application_ptr_destroy(handle->application_private_ptr);
	}

	RRR_NET_TRANSPORT_HANDLE_UNLOCK(handle, "__rrr_net_transport_handle_destroy");
	pthread_mutex_destroy(&handle->lock_);

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

int rrr_net_transport_handle_close_tag_list_push (
		struct rrr_net_transport *transport,
		int handle
) {
	int ret = 0;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	struct rrr_net_transport_handle_close_tag_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_net_transport_handle_close_tag_list_push\n");
		ret = 1;
		goto out;
	}
	memset(node, '\0', sizeof(*node));

	node->transport_handle = handle;

	RRR_LL_APPEND(&transport->handles.close_tags, node);

	out:
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}

static void __rrr_net_transport_handle_close_tag_node_process_and_destroy (
		struct rrr_net_transport *transport,
		struct rrr_net_transport_handle_close_tag_node *node
) {
	// Ignore errors
	//printf("Close handle %i which has been tagged\n", node->transport_handle);
	rrr_net_transport_handle_close(transport, node->transport_handle);
	free(node);
}

static void __rrr_net_transport_handle_close_tag_list_process_and_clear_locked (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;
	RRR_LL_DESTROY(&collection->close_tags, struct rrr_net_transport_handle_close_tag_node, __rrr_net_transport_handle_close_tag_node_process_and_destroy(transport, node));
}

static void rrr_net_transport_maintenance (struct rrr_net_transport *transport) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	__rrr_net_transport_handle_close_tag_list_process_and_clear_locked(transport);
	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
}

int rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		int flags,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
	int ret = 0;

	*result = NULL;

	struct rrr_net_transport *new_transport = NULL;

	switch (config->transport_type) {
		case RRR_NET_TRANSPORT_PLAIN:
			if (flags != 0) {
				RRR_BUG("BUG: Plain method does not support flags in rrr_net_transport_new but flags were given\n");
			}
			if (config->tls_certificate_file != NULL || config->tls_key_file != NULL || config->tls_ca_file != NULL || config->tls_ca_path != NULL) {
				RRR_BUG("BUG: Plain method does not support TLS parameters in rrr_net_transport_new but they were given\n");
			}
			if (alpn_protos != NULL) {
				RRR_BUG("BUG: Plain method does not support ALPN in rrr_net_transport_new but it was given\n");
			}
			ret = rrr_net_transport_plain_new((struct rrr_net_transport_plain **) &new_transport);
			break;
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
		case RRR_NET_TRANSPORT_TLS:
			ret = rrr_net_transport_tls_new (
					(struct rrr_net_transport_tls **) &new_transport,
					flags,
					config->tls_certificate_file,
					config->tls_key_file,
					config->tls_ca_file,
					config->tls_ca_path,
					alpn_protos,
					alpn_protos_length
			);
			break;
#endif
		default:
			RRR_BUG("Transport method %i not implemented in rrr_net_transport_new\n", config->transport_type);
			break;
	};

	if (ret != 0) {
		RRR_MSG_0("Could not create transport method in rrr_net_transport_new\n");
		goto out;
	}

	if (rrr_posix_mutex_init (&new_transport->handles.lock, RRR_POSIX_MUTEX_IS_RECURSIVE) != 0) {
		RRR_MSG_0("Could not initialize handle collection lock in rrr_net_transport_new\n");
		ret = 1;
		goto out_destroy;
	}

	new_transport->handles.owner = pthread_self();

	*result = new_transport;

	goto out;
	out_destroy:
		new_transport->methods->destroy(new_transport);
	out:
		return ret;
}

void rrr_net_transport_destroy (struct rrr_net_transport *transport) {
	rrr_net_transport_maintenance(transport);

	rrr_net_transport_common_cleanup(transport);

	pthread_mutex_destroy(&transport->handles.lock);

	// The matching destroy function of the new function which allocated
	// memory for the transport will free()
	transport->methods->destroy(transport);
}

void rrr_net_transport_destroy_void (void *arg) {
	rrr_net_transport_destroy(arg);
}

void rrr_net_transport_collection_destroy (struct rrr_net_transport_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_net_transport, rrr_net_transport_destroy(node));
}

void rrr_net_transport_collection_cleanup (struct rrr_net_transport_collection *collection) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport);
		rrr_net_transport_common_cleanup(node);
	RRR_LL_ITERATE_END();
}

void rrr_net_transport_ctx_handle_close_while_locked (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_handle_collection *collection = &handle->transport->handles;

	const int already_locked = 1;
	int did_destroy = 0;

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();
	RRR_LL_REMOVE_NODE_IF_EXISTS(collection, struct rrr_net_transport_handle, handle, did_destroy = 1; __rrr_net_transport_handle_destroy(node, already_locked));
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

	if (collection->owner != pthread_self()) {
		RRR_BUG("BUG: rrr_net_transport_handle_close called from non-owner of collection, this might cause deadlocking. Close tagging should be used instead.");
	}

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		// We are allowed to read the handle integer without handle lock
		// held. When the handle integer is written, the collection lock
		// is held. We should also be the same thread as the one who wrote it.
		if (node->handle == transport_handle) {
			RRR_NET_TRANSPORT_HANDLE_LOCK(node, "rrr_net_transport_handle_close");
			ret = __rrr_net_transport_handle_destroy(node, 1);
			did_destroy = 1;
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
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
		void (*callback)(struct rrr_net_transport_handle *transport_handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg,
		int close_after_callback
) {
	if (host == NULL) {
		RRR_BUG("host was NULL in rrr_net_transport_connect_and_destroy_after_callback\n");
	}
	if (port == 0) {
		RRR_BUG("port was 0 in rrr_net_transport_connect_and_destroy_after_callback\n");
	}

	int ret = 0;

	int transport_handle = 0;
	struct sockaddr_storage addr;
	socklen_t socklen = sizeof(addr);

	// TODO : Distinguish between soft and hard connect errors

	if ((ret = transport->methods->connect (
			&transport_handle,
			(struct sockaddr *) &addr,
			&socklen,
			transport,
			port,
			host
	)) != 0) {
		goto out;
	}

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("__rrr_net_transport_connect");

	callback(handle, (struct sockaddr *) &addr, socklen, callback_arg);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

	// Safe to pass in pointer, transport is only accessed if it exists in the list
	if (close_after_callback) {
		rrr_net_transport_handle_close (transport, transport_handle);
	}

	out:
	return ret;
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
	rrr_net_transport_maintenance(transport);

	return __rrr_net_transport_connect (transport, port, host, callback, callback_arg, 0);
}

int rrr_net_transport_ctx_check_alive (
		struct rrr_net_transport_handle *handle
) {
	return handle->transport->methods->poll(handle);
}

int rrr_net_transport_ctx_read_message (
		struct rrr_net_transport_handle *handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		ssize_t read_max_size,
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
			read_max_size,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	);
	handle->bytes_read_total += bytes_read;

	return ret;
}

int rrr_net_transport_ctx_send_nonblock (
		uint64_t *written_bytes,
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

	if ((ret = handle->transport->methods->send (
			written_bytes,
			handle,
			data,
			size
	)) != 0) {
		if (ret != RRR_NET_TRANSPORT_SEND_SOFT_ERROR) {
			RRR_MSG_1("Error from submodule send() in rrr_net_transport_send_nonblock\n");
			goto out;
		}
	}

	uint64_t size_tmp_u = size;
	if (*written_bytes != size_tmp_u) {
		ret = RRR_NET_TRANSPORT_SEND_INCOMPLETE;
	}

	handle->bytes_written_total += *written_bytes;

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
			if (ret != RRR_NET_TRANSPORT_SEND_INCOMPLETE) {
				break;
			}
		}
		written_bytes_total += written_bytes;
		pthread_testcancel();
	} while (ret != RRR_NET_TRANSPORT_SEND_OK);

	handle->bytes_written_total += written_bytes_total;

	return ret;
}

int rrr_net_transport_ctx_read (
		uint64_t *bytes_read,
		struct rrr_net_transport_handle *handle,
		char *buf,
		size_t buf_size
) {
	int ret = handle->transport->methods->read(bytes_read, handle, buf, buf_size);

	handle->bytes_read_total += *bytes_read;

	return ret;
}

int rrr_net_transport_ctx_handle_has_application_data (
		struct rrr_net_transport_handle *handle
) {
	return (handle->application_private_ptr != NULL);
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

void rrr_net_transport_ctx_get_socket_stats (
		uint64_t *bytes_read_total,
		uint64_t *bytes_written_total,
		uint64_t *bytes_total,
		struct rrr_net_transport_handle *handle
) {
	if (bytes_read_total != NULL) {
		*bytes_read_total = handle->bytes_read_total;
	}
	if (bytes_written_total != NULL) {
		*bytes_written_total = handle->bytes_written_total;
	}
	if (bytes_total != NULL) {
		*bytes_total = handle->bytes_read_total + handle->bytes_written_total;
	}
}

int rrr_net_transport_ctx_is_tls (
		struct rrr_net_transport_handle *handle
) {
	return handle->transport->methods->is_tls();
}

void rrr_net_transport_ctx_selected_proto_get (
		const char **proto,
		struct rrr_net_transport_handle *handle
) {
	handle->transport->methods->selected_proto_get(proto, handle);
}

int rrr_net_transport_handle_with_transport_ctx_do (
		struct rrr_net_transport *transport,
		int transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("rrr_net_transport_handle_with_transport_ctx_do ");
	ret = callback(handle, arg);
	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

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
//		printf("mode %i vs %i handle %u\n", mode, node->mode, node->handle);

		if (mode == RRR_NET_TRANSPORT_SOCKET_MODE_ANY || mode == node->mode) {
			RRR_NET_TRANSPORT_HANDLE_LOCK(node, "rrr_net_transport_iterate_with_callback");
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
			RRR_NET_TRANSPORT_HANDLE_UNLOCK(node, "rrr_net_transport_iterate_with_callback");
		}
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

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("rrr_net_transport_send");

	ret = rrr_net_transport_ctx_send_blocking(handle, data, size);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

	return ret;
}

int rrr_net_transport_send_nonblock (
		uint64_t *written_bytes,
		struct rrr_net_transport *transport,
		int transport_handle,
		const void *data,
		ssize_t size
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("rrr_net_transport_send");

	ret = rrr_net_transport_ctx_send_nonblock(written_bytes, handle, data, size);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

	return ret;
}

int rrr_net_transport_read (
		uint64_t *bytes_read,
		struct rrr_net_transport *transport,
		int transport_handle,
		char *buf,
		size_t buf_size
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("rrr_net_transport_send");

	ret = rrr_net_transport_ctx_read(bytes_read, handle, buf, buf_size);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

	return ret;
}

static int __rrr_net_transport_bind_and_listen_callback_intermediate (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS
) {
	int ret = 0;

	(void)(arg);

	if (final_callback) {
		RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("__rrr_net_transport_accept_callback_intermediate");

		final_callback(handle, final_callback_arg);

		RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();
	}

	return ret;
}

int rrr_net_transport_bind_and_listen (
		struct rrr_net_transport *transport,
		unsigned int port,
		int do_ipv6,
		void (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),
		void *arg
) {
	return transport->methods->bind_and_listen (
			transport,
			port,
			do_ipv6,
			__rrr_net_transport_bind_and_listen_callback_intermediate,
			NULL,
			callback,
			arg
	);
}

int rrr_net_transport_bind_and_listen_dualstack (
		struct rrr_net_transport *transport,
		unsigned int port,
		void (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),
		void *arg
) {
	int ret_6 = transport->methods->bind_and_listen (
			transport,
			port,
			1, // IPv6
			__rrr_net_transport_bind_and_listen_callback_intermediate,
			NULL,
			callback,
			arg
	);

	int ret_4 = transport->methods->bind_and_listen (
			transport,
			port,
			0, // IPv4
			__rrr_net_transport_bind_and_listen_callback_intermediate,
			NULL,
			callback,
			arg
	);

	int ret = RRR_NET_TRANSPORT_READ_OK;

	if (ret_6 != 0 && ret_4 != 0) {
		RRR_MSG_0("Listening failed for both IPv4 and IPv6 on port %u\n", port);
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
	}
	else if (ret_6) {
		RRR_DBG_1("Note: Listening failed for IPv6 on port %u, but IPv4 listening succedded. Assuming IPv4-only stack.\n", port);
	}
	else if (ret_4) {
		RRR_DBG_1("Note: Listening failed for IPv4 on port %u, but IPv6 listening succedded. Assuming dual-stack.\n", port);
	}

	return ret;
}

static int __rrr_net_transport_accept_callback_intermediate (
		RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS
) {
	(void)(arg);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("__rrr_net_transport_accept_callback_intermediate");

	final_callback(handle, sockaddr, socklen, final_callback_arg);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

	return 0;
}

int rrr_net_transport_accept (
		struct rrr_net_transport *transport,
		int transport_handle,
		void (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *callback_arg
) {
	int ret = 0;

	rrr_net_transport_maintenance(transport);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_IN("rrr_net_transport_accept");

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
		RRR_BUG("BUG: Handle to rrr_net_transport_accept was not a listening FD\n");
	}

	ret = transport->methods->accept (
			handle,
			__rrr_net_transport_accept_callback_intermediate,
			NULL,
			callback,
			callback_arg
	);

	RRR_NET_TRANSPORT_HANDLE_WRAP_LOCK_OUT();

	return ret;
}

int rrr_net_transport_accept_all_handles (
		struct rrr_net_transport *transport,
		void (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	rrr_net_transport_maintenance(transport);

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_LOCK();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->mode == RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
			RRR_NET_TRANSPORT_HANDLE_LOCK(node, "rrr_net_transport_accept_all_handles");
			ret = transport->methods->accept (
					node,
					__rrr_net_transport_accept_callback_intermediate,
					NULL,
					callback,
					callback_arg
			);
			if (ret != 0) {
				RRR_LL_ITERATE_LAST();
			}
			RRR_NET_TRANSPORT_HANDLE_UNLOCK(node, "rrr_net_transport_accept_all_handles");
		}
	RRR_LL_ITERATE_END();

	RRR_NET_TRANSPORT_HANDLE_COLLECTION_UNLOCK();
	return ret;
}
