/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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
#include <limits.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#define RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX 65535

#include "../log.h"

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_plain.h"
#include "net_transport_config.h"

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
#	include "net_transport_tls.h"
#endif

#include "../event/event.h"
#include "../ip/ip_util.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"
#include "../socket/rrr_socket_send_chunk.h"

static struct rrr_net_transport_handle *__rrr_net_transport_handle_get (
		struct rrr_net_transport *transport,
		int handle,
		const char *source
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	struct rrr_net_transport_handle *result = NULL;

	// May be used to print debug messages
	(void)(source);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			result = node;
			// Lock prior to releasing collection lock to prevent race conditions
			// with anyone calling close(). Closers will try to lock this lock
			// prior to destruction.
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return result;
}

#define RRR_NET_TRANSPORT_HANDLE_GET(error_source)                                                                             \
    struct rrr_net_transport_handle *handle = NULL;                                                                            \
    do {if ((handle = __rrr_net_transport_handle_get(transport, transport_handle, error_source)) == NULL) {                    \
        RRR_MSG_0("Could not find transport handle %i in " error_source "\n", transport_handle);                               \
        return 1;                                                                                                              \
    }} while (0)

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

	new_handle->transport = transport;

	// NOTE : These shallow members may be accessed with only collection lock held
	new_handle->handle = handle;
	new_handle->mode = mode;

	rrr_event_collection_init(&new_handle->events, transport->event_queue);

	if ((ret = submodule_callback (
			&new_handle->submodule_private_ptr,
			&new_handle->submodule_fd,
			submodule_callback_arg
	)) != 0) {
		goto out_free;
	}

	RRR_LL_APPEND(collection, new_handle);

	goto out;
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
	return ret;
}

static int __rrr_net_transport_handle_destroy (
		struct rrr_net_transport_handle *handle
) {
	// Delete events first as libevent might produce warnings if
	// this is performed after FD is closed
	rrr_event_collection_clear(&handle->events);

	rrr_read_session_collection_clear(&handle->read_sessions);

	handle->transport->methods->close(handle);

	if (handle->application_private_ptr != NULL && handle->application_ptr_destroy != NULL) {
		handle->application_ptr_destroy(handle->application_private_ptr);
	}

	RRR_FREE_IF_NOT_NULL(handle->match_string);

	rrr_socket_send_chunk_collection_clear(&handle->send_chunks);

	free(handle);
	// Always return success because we always free() regardless of callback result
	return RRR_LL_DID_DESTROY;
}

void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_LL_DESTROY(
			collection,
			struct rrr_net_transport_handle,
			__rrr_net_transport_handle_destroy (node)
	);
}

int rrr_net_transport_handle_close_tag_list_push (
		struct rrr_net_transport *transport,
		int handle
) {
	int ret = 0;

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
	return ret;
}

static void __rrr_net_transport_handle_close_tag_node_process_and_destroy (
		struct rrr_net_transport *transport,
		struct rrr_net_transport_handle_close_tag_node *node
) {
	// Ignore errors
	rrr_net_transport_handle_close(transport, node->transport_handle);
	free(node);
}

static void __rrr_net_transport_handle_close_tag_list_process_and_clear_locked (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;
	RRR_LL_DESTROY(&collection->close_tags, struct rrr_net_transport_handle_close_tag_node, __rrr_net_transport_handle_close_tag_node_process_and_destroy(transport, node));
}

static void __rrr_net_transport_maintenance (struct rrr_net_transport *transport) {
	__rrr_net_transport_handle_close_tag_list_process_and_clear_locked(transport);
}

void rrr_net_transport_stats_get (
		int *handle_count,
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;
	*handle_count = RRR_LL_COUNT(collection);
}

int rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		int flags,
		struct rrr_event_queue *queue,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
#if !defined(RRR_WITH_LIBRESSL) && !defined(RRR_WITH_OPENSSL)
	(void)(alpn_protos_length);
#endif
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

	rrr_event_collection_init(&new_transport->events, queue);
	new_transport->event_queue = queue;

	*result = new_transport;

	goto out;
//	out_destroy:
//		new_transport->methods->destroy(new_transport);
	out:
		return ret;
}

void rrr_net_transport_destroy (
		struct rrr_net_transport *transport
) {
	__rrr_net_transport_maintenance(transport);

	rrr_net_transport_common_cleanup(transport);

	rrr_event_collection_clear(&transport->events);

	// The matching destroy function of the new function which allocated
	// memory for the transport will free()
	transport->methods->destroy(transport);
}

void rrr_net_transport_destroy_void (
		void *arg
) {
	rrr_net_transport_destroy(arg);
}

int rrr_net_transport_handle_close (
		struct rrr_net_transport *transport,
		int transport_handle
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;
	int did_destroy = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		// We are allowed to read the handle integer without handle lock
		// held. When the handle integer is written, the collection lock
		// is held. We should also be the same thread as the one who wrote it.
		if (node->handle == transport_handle) {
			ret = __rrr_net_transport_handle_destroy(node);
			did_destroy = 1;
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);

	if (did_destroy != 1) {
		RRR_MSG_0("Could not find transport handle %i in rrr_net_transport_close\n", transport_handle);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_net_transport_ctx_send_nonblock (
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
		if (ret != RRR_NET_TRANSPORT_SEND_INCOMPLETE) {
			RRR_DBG_7("Error %i from submodule send() in rrr_net_transport_send_nonblock, connection should be closed\n", ret);
			goto out;
		}
	}

	uint64_t size_tmp_u = size;
	if (ret == 0 && *written_bytes != size_tmp_u) {
		ret = RRR_NET_TRANSPORT_SEND_INCOMPLETE;
	}

	handle->bytes_written_total += *written_bytes;

	out:
	return ret;
}

#define CHECK_READ_WRITE_RETURN()                                                                              \
    do {if ((ret_tmp & ~(RRR_READ_INCOMPLETE)) != 0) {                                                         \
        if (rrr_net_transport_handle_close_tag_list_push (handle->transport, handle->handle)) {                \
            RRR_MSG_0("Failed to add handle to close tag list in __rrr_net_transport_event_*\n");              \
            rrr_event_dispatch_break(handle->transport->event_queue);                                          \
        }                                                                                                      \
	EVENT_ACTIVATE(handle->transport->event_maintenance);                                                  \
    } else if ( flags != 0 /* Don't double reactivate, client must send more data or writes are needed */ &&   \
        rrr_read_session_collection_has_unprocessed_data(&handle->read_sessions)) {                            \
        EVENT_ACTIVATE(handle->event_read);                                                                    \
    }} while(0)

static void __rrr_net_transport_event_first_read_timeout (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(flags);

	RRR_DBG_7("net transport fd %i no data received within %" PRIu64 " ms, closing connection\n",
			fd, handle->transport->first_read_timeout_ms);

	int ret_tmp = RRR_READ_EOF;
	CHECK_READ_WRITE_RETURN();
}

static void __rrr_net_transport_event_hard_read_timeout (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(flags);

	RRR_DBG_7("net transport fd %i no data received for %" PRIu64 " ms, closing connection\n",
			fd, handle->transport->hard_read_timeout_ms);

	int ret_tmp = RRR_READ_EOF;
	CHECK_READ_WRITE_RETURN();
}

static void __rrr_net_transport_event_handshake (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(fd);

	int ret_tmp = 0;

	if (handle->handshake_complete) {
		RRR_BUG("BUG: __rrr_net_transport_event_handshake called after handshake was complete\n");
	}

	if ((ret_tmp = handle->transport->methods->handshake(handle)) != 0) {
		if (ret_tmp == RRR_NET_TRANSPORT_SEND_INCOMPLETE) {
			EVENT_ACTIVATE(handle->event_handshake);
			return;
		}

		RRR_DBG_7("net transport fd %i handshake error, closing connection. Return was %i.\n",
				handle->submodule_fd, ret_tmp);

		ret_tmp = RRR_READ_EOF;
		goto check_return;
	}

	RRR_DBG_7("net transport fd %i handshake complete\n",
			handle->submodule_fd);

	if (handle->transport->handshake_complete_callback != NULL) {
		handle->transport->handshake_complete_callback(handle, handle->transport->handshake_complete_callback_arg);
	}

	handle->handshake_complete = 1;
	EVENT_REMOVE(handle->event_handshake);

	check_return:
	CHECK_READ_WRITE_RETURN();
}

static void __rrr_net_transport_event_read (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(fd);

	int ret_tmp = 0;

	if (!handle->handshake_complete) {
		return;
	}

	if ((flags & EV_READ) && handle->transport->hard_read_timeout_ms > 0) {
		EVENT_ADD(handle->event_hard_read_timeout);
	}

	EVENT_REMOVE(handle->event_first_read_timeout);

	ret_tmp = handle->transport->read_callback (
		handle,
		handle->transport->read_callback_arg
	);

	CHECK_READ_WRITE_RETURN();
}

static int __rrr_net_transport_event_write_send_chunk_callback (
		ssize_t *written_bytes,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		ssize_t data_size,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(addr);
	(void)(addr_len);

	uint64_t written_bytes_u64 = 0;

	int ret = __rrr_net_transport_ctx_send_nonblock (
			&written_bytes_u64,
			handle,
			data,
			data_size
	);

	*written_bytes = written_bytes_u64;

	return ret;
}

static void __rrr_net_transport_event_write (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	if (!handle->handshake_complete) {
		return;
	}

	(void)(fd);
	(void)(flags);

	int ret_tmp = 0;

	if (RRR_LL_COUNT(&handle->send_chunks) > 0) {
		ret_tmp = rrr_socket_send_chunk_collection_send_with_callback (
				&handle->send_chunks,
				__rrr_net_transport_event_write_send_chunk_callback,
				handle
		);
	}

	if (RRR_LL_COUNT(&handle->send_chunks) == 0) {
		EVENT_REMOVE(handle->event_write);
	}

	CHECK_READ_WRITE_RETURN();
}

static void __rrr_net_transport_handle_event_read_add_if_needed (
		struct rrr_net_transport_handle *handle
) {
	if (!EVENT_PENDING(handle->event_read)) {
		EVENT_ADD(handle->event_read);
	}
}

static int __rrr_net_transport_handle_events_setup_connected (
	struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	// READ

	if ((ret = rrr_event_collection_push_read (
			&handle->event_read,
			&handle->events,
			handle->submodule_fd,
			__rrr_net_transport_event_read,
			handle,
			handle->transport->soft_read_timeout_ms * 1000
	)) != 0) {
		goto out;
	}

	__rrr_net_transport_handle_event_read_add_if_needed (handle);

	// HANDSHAKE

	if ((ret = rrr_event_collection_push_periodic (
			&handle->event_handshake,
			&handle->events,
			__rrr_net_transport_event_handshake,
			handle,
			1000 // 1 ms
	)) != 0) {
		goto out;
	}

	EVENT_ACTIVATE(handle->event_handshake);

	// WRITE

	if ((ret = rrr_event_collection_push_write (
			&handle->event_write,
			&handle->events,
			handle->submodule_fd,
			__rrr_net_transport_event_write,
			handle,
			handle->transport->soft_read_timeout_ms * 1000
	)) != 0) {
		goto out;
	}

	// Don't add write to events, it is done when data is pushed and we need to write

	if (handle->transport->first_read_timeout_ms > 0) {
		if ((ret = rrr_event_collection_push_periodic (
				&handle->event_first_read_timeout,
				&handle->events,
				__rrr_net_transport_event_first_read_timeout,
				handle,
				handle->transport->first_read_timeout_ms * 1000
		)) != 0) {
			goto out;
		}

		EVENT_ADD(handle->event_first_read_timeout);
	}

	if (handle->transport->hard_read_timeout_ms > 0) {
		if ((ret = rrr_event_collection_push_periodic (
				&handle->event_hard_read_timeout,
				&handle->events,
				__rrr_net_transport_event_hard_read_timeout,
				handle,
				handle->transport->hard_read_timeout_ms * 1000
		)) != 0) {
			goto out;
		}

		EVENT_ADD(handle->event_hard_read_timeout);
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

	RRR_NET_TRANSPORT_HANDLE_GET("__rrr_net_transport_connect");

	if (handle->submodule_fd == 0) {
		RRR_BUG("BUG: Submodule FD not set in __rrr_net_transport_connect\n");
	}

	memcpy(&handle->connected_addr, &addr, socklen);
	handle->connected_addr_len = socklen;

	if (transport->event_queue != NULL) {
		if ((ret = __rrr_net_transport_handle_events_setup_connected (
				handle
		)) != 0) {
			goto out;
		}
	}

	callback(handle, (struct sockaddr *) &addr, socklen, callback_arg);

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
	return __rrr_net_transport_connect (transport, port, host, callback, callback_arg, 0);
}

int rrr_net_transport_handle_get_by_match (
		struct rrr_net_transport *transport,
		const char *string,
		uint64_t number
) {
	int result_handle = 0;

	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (number != node->match_number) {
			RRR_LL_ITERATE_NEXT();
		}
		else if (string == NULL && node->match_string == NULL) {
			// OK, match
		}
		else if (node->match_string == NULL || string == NULL) {
			RRR_LL_ITERATE_NEXT();
		}
		else if (strcmp(string, node->match_string) != 0) {
			RRR_LL_ITERATE_NEXT();
		}

		result_handle = node->handle;
		RRR_LL_ITERATE_LAST();
	RRR_LL_ITERATE_END();

	return result_handle;
}

int rrr_net_transport_is_tls (
		struct rrr_net_transport *transport
) {
	return transport->methods->is_tls();
}

void rrr_net_transport_ctx_notify_read (
		struct rrr_net_transport_handle *handle
) {
	EVENT_ACTIVATE(handle->event_read);
}

void rrr_net_transport_notify_read_all_connected (
		struct rrr_net_transport *transport
) {
	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (node->mode == RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
			rrr_net_transport_ctx_notify_read(node);
		}
	RRR_LL_ITERATE_END();
}

int rrr_net_transport_ctx_get_fd (
		struct rrr_net_transport_handle *handle
) {
	return handle->submodule_fd;
}

void *rrr_net_transport_ctx_get_private_ptr (
		struct rrr_net_transport_handle *handle
) {
	return handle->application_private_ptr;
}

int rrr_net_transport_ctx_get_handle (
		struct rrr_net_transport_handle *handle
) {
	return handle->handle;
}

int rrr_net_transport_ctx_handle_match_data_set (
		struct rrr_net_transport_handle *handle,
		const char *string,
		uint64_t number
) {
	RRR_FREE_IF_NOT_NULL(handle->match_string);
	if ((handle->match_string = strdup(string)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_net_transport_ctx_handle_match_data_set\n");
		return 1;
	}

	handle->match_number = number;

	return 0;
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
		uint64_t ratelimit_interval_us,
		ssize_t ratelimit_max_bytes,
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
			ratelimit_interval_us,
			ratelimit_max_bytes,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	);
	handle->bytes_read_total += bytes_read;

	if (ret == RRR_NET_TRANSPORT_READ_RATELIMIT) {
		EVENT_REMOVE(handle->event_read);
	}

	return ret;
}

int rrr_net_transport_ctx_send_waiting_chunk_count (
		struct rrr_net_transport_handle *handle
) {
	return RRR_LL_COUNT(&handle->send_chunks);
}

int rrr_net_transport_ctx_send_push (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
) {
	int ret = rrr_socket_send_chunk_collection_push_const (&handle->send_chunks, data, size);

	EVENT_ADD(handle->event_write);

	return ret;
}

int rrr_net_transport_ctx_send_urgent (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
) {
	uint64_t written_bytes_u64 = 0;

	int ret = __rrr_net_transport_ctx_send_nonblock (
			&written_bytes_u64,
			handle,
			data,
			size
	);

	if ((ssize_t) written_bytes_u64 != size || ret != 0) {
		RRR_DBG_7("net transport fd %i not all bytes were sent in urgen send (%" PRIu64 "<%lli) ret was %i\n",
			handle->submodule_fd, written_bytes_u64, (long long int) size, ret);

		// Mask all errors
		ret = RRR_NET_TRANSPORT_SEND_SOFT_ERROR;
	}

	return ret;
}

static int __rrr_net_transport_ctx_send_push_nullsafe_callback (
		const void *data,
		rrr_nullsafe_len data_len,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	return rrr_net_transport_ctx_send_push(handle, data, data_len);
}

int rrr_net_transport_ctx_send_push_nullsafe (
		struct rrr_net_transport_handle *handle,
		const struct rrr_nullsafe_str *nullsafe
) {
	return rrr_nullsafe_str_with_raw_do_const(nullsafe, __rrr_net_transport_ctx_send_push_nullsafe_callback, handle);
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

void rrr_net_transport_ctx_handle_pre_destroy_function_set (
		struct rrr_net_transport_handle *handle,
		int (*pre_destroy_function)(struct rrr_net_transport_handle *handle, void *ptr)
) {
	handle->application_ptr_iterator_pre_destroy = pre_destroy_function;
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
	return rrr_net_transport_is_tls(handle->transport);
}

void rrr_net_transport_ctx_connected_address_to_str (
		char *buf,
		size_t buf_size,
		struct rrr_net_transport_handle *handle
) {
	if (handle->connected_addr_len == 0) {
		snprintf(buf, buf_size, "(unknown)");
	}
	else {
		rrr_ip_to_str(buf, buf_size, (const struct sockaddr *) &handle->connected_addr, handle->connected_addr_len);
	}
}

void rrr_net_transport_ctx_connected_address_get (
		const struct sockaddr **addr,
		socklen_t *addr_len,
		const struct rrr_net_transport_handle *handle
) {
	*addr = (const struct sockaddr *) &handle->connected_addr;
	*addr_len = handle->connected_addr_len;
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

	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_with_transport_ctx_do ");
	ret = callback(handle, arg);

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

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (mode == RRR_NET_TRANSPORT_SOCKET_MODE_ANY || mode == node->mode) {
			if ((ret = callback (
					node,
					arg
			)) != 0) {
				if (ret == RRR_READ_INCOMPLETE) {
					ret = 0;
					RRR_LL_ITERATE_NEXT();
				}
				else if (ret == RRR_READ_SOFT_ERROR || ret == RRR_READ_EOF) {
					ret = 0;
					// For nice treatment of remote, for instance send a disconnect packet
					if (node->application_ptr_iterator_pre_destroy != NULL) {
						ret = node->application_ptr_iterator_pre_destroy(node, node->application_private_ptr);
					}

					if (ret == RRR_NET_TRANSPORT_READ_HARD_ERROR) {
						RRR_MSG_0("Internal error in rrr_net_transport_iterate_with_callback\n");
						RRR_LL_ITERATE_BREAK();
					}

					// When pre_destroy returns 0 or is not set, go ahead with destruction
					if (ret == 0) {
						__rrr_net_transport_handle_destroy(node);
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
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);

	return ret;
}

int rrr_net_transport_match_data_set (
		struct rrr_net_transport *transport,
		int transport_handle,
		const char *string,
		uint64_t number
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_match_data_set");

	ret = rrr_net_transport_ctx_handle_match_data_set(handle, string, number);

	return ret;
}

int rrr_net_transport_check_handshake_complete (
		struct rrr_net_transport *transport,
		int transport_handle
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_match_data_set");

	ret = (handle->handshake_complete ? RRR_READ_OK : RRR_READ_INCOMPLETE);

	return ret;
}

static void __rrr_net_transport_event_maintenance (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport *transport = arg;

	(void)(fd);
	(void)(flags);

	__rrr_net_transport_maintenance(transport);
}

static void __rrr_net_transport_event_read_add (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport *transport = arg;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	(void)(fd);
	(void)(flags);

	// Re-add read-events (if they where deleted due to ratelimiting)

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		__rrr_net_transport_handle_event_read_add_if_needed(node);
	RRR_LL_ITERATE_END();
}

static int __rrr_net_transport_accept_callback_intermediate (
		RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS
) {
	(void)(arg);

	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("__rrr_net_transport_accept_callback_intermediate");

	if ((ret = __rrr_net_transport_handle_events_setup_connected (
			handle
	)) != 0) {
		goto out;
	}

	memcpy(&handle->connected_addr, sockaddr, socklen);
	handle->connected_addr_len = socklen;

	final_callback(handle, sockaddr, socklen, final_callback_arg);

	// For handshake purposes
	EVENT_ACTIVATE(handle->event_read);

	out:
	return ret;
}

static void __rrr_net_transport_event_accept (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(fd);
	(void)(flags);

	int did_accept = 0;
	int ret_tmp = handle->transport->methods->accept (
			&did_accept,
			handle,
			__rrr_net_transport_accept_callback_intermediate,
			NULL,
			handle->transport->accept_callback,
			handle->transport->accept_callback_arg
	);

	if (ret_tmp != 0) {
		rrr_event_dispatch_break(handle->transport->event_queue);
	}
}

static int __rrr_net_transport_handle_events_setup_listen (
	struct rrr_net_transport_handle *handle
) {
	int ret = 0;

	if ((ret = rrr_event_collection_push_read (
			&handle->event_read,
			&handle->events,
			handle->submodule_fd,
			__rrr_net_transport_event_accept,
			handle,
			0
	)) != 0) {
		goto out;
	}

	EVENT_ADD(handle->event_read);

	out:
	return ret;
}

static int __rrr_net_transport_bind_and_listen_callback_intermediate (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS
) {
	(void)(arg);

	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("__rrr_net_transport_bind_and_listen_callback_intermediate");

	if ((ret = __rrr_net_transport_handle_events_setup_listen (
			handle
	)) != 0) {
		goto out;
	}

	if (final_callback) {
		final_callback(handle, final_callback_arg);
	}

	out:
	return ret;
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
		RRR_DBG_1("Note: Listening failed for IPv6 on port %u, but IPv4 listening succeeded. Assuming IPv4-only stack.\n", port);
	}
	else if (ret_4) {
		RRR_DBG_1("Note: Listening failed for IPv4 on port %u, but IPv6 listening succeeded. Assuming dual-stack.\n", port);
	}

	return ret;
}

int rrr_net_transport_accept_all_handles (
		struct rrr_net_transport *transport,
		int at_most_one_accept,
		void (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->mode == RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
			int did_accept = 0;
			ret = transport->methods->accept (
					&did_accept,
					node,
					__rrr_net_transport_accept_callback_intermediate,
					NULL,
					callback,
					callback_arg
			);

			if (ret != 0 || (at_most_one_accept && did_accept)) {
				RRR_LL_ITERATE_LAST();
			}
		}
	RRR_LL_ITERATE_END();

	return ret;
}

void rrr_net_transport_event_activate_all_connected_read (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		EVENT_ACTIVATE(node->event_read);
	RRR_LL_ITERATE_END();
}

int rrr_net_transport_event_setup (
		struct rrr_net_transport *transport,
		uint64_t first_read_timeout_ms,
		uint64_t soft_read_timeout_ms,
		uint64_t hard_read_timeout_ms,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *accept_callback_arg,
		void (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS),
		void *handshake_complete_callback_arg,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg
) {
	int ret = 0;

	rrr_net_transport_common_cleanup (transport);

	transport->first_read_timeout_ms = first_read_timeout_ms;
	transport->soft_read_timeout_ms = soft_read_timeout_ms;
	transport->hard_read_timeout_ms = hard_read_timeout_ms;

	rrr_time_from_usec(&transport->first_read_timeout_tv, first_read_timeout_ms * 1000);
	rrr_time_from_usec(&transport->soft_read_timeout_tv, soft_read_timeout_ms * 1000);
	rrr_time_from_usec(&transport->hard_read_timeout_tv, hard_read_timeout_ms * 1000);

	transport->accept_callback = accept_callback;
	transport->accept_callback_arg = accept_callback_arg;

	transport->handshake_complete_callback = handshake_complete_callback;
	transport->handshake_complete_callback_arg = handshake_complete_callback_arg;

	transport->read_callback = read_callback;
	transport->read_callback_arg = read_callback_arg;

	if ((ret = rrr_event_collection_push_oneshot (
			&transport->event_maintenance,
			&transport->events,
			__rrr_net_transport_event_maintenance,
			transport
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_event_collection_push_periodic (
			&transport->event_read_add,
			&transport->events,
			__rrr_net_transport_event_read_add,
			transport,
			50 * 1000 // 50 ms
	)) != 0) {
		goto out;
	}

	EVENT_ADD(transport->event_read_add);

	out:
	return ret;
}
