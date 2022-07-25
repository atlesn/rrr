/*

Read Route Record

Copyright (C) 2020-2022 Atle Solbakken atle@goliathdns.no

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
#include <assert.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#define RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX 65535

#include "../log.h"
#include "../rrr_types.h"
#include "../allocator.h"

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_plain.h"
#include "net_transport_config.h"
#include "net_transport_ctx.h"
#include "net_transport_connection_id.h"

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
#	include "net_transport_tls.h"
#endif

#if defined(RRR_WITH_HTTP3)
#	include "net_transport_quic.h"
#endif

#include "../event/event.h"
#include "../ip/ip_util.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"
#include "../helpers/nullsafe_str.h"
#include "../socket/rrr_socket_send_chunk.h"

static struct rrr_net_transport_handle *__rrr_net_transport_handle_get (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle,
		const char *source
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	struct rrr_net_transport_handle *result = NULL;

	// May be used to print debug messages
	(void)(source);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			result = node;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return result;
}

static int __rrr_net_transport_handle_destroy (
		struct rrr_net_transport_handle *handle
) {
#ifdef RRR_NET_TRANSPORT_READ_RET_DEBUG
	RRR_DBG_7("net transport fd %i h %i [%s] destroy handle. Read return values encountered: ok %u incomplete %u soft %u hard %u eof %u\n",
			handle->submodule_fd,
			handle->handle,
			handle->transport->application_name,
			handle->read_ret_debug_ok,
			handle->read_ret_debug_incomplete,
			handle->read_ret_debug_soft_error,
			handle->read_ret_debug_hard_error,
			handle->read_ret_debug_eof
	);
#endif

	// Delete events first as libevent might produce warnings if
	// this is performed after FD is closed
	rrr_event_collection_clear(&handle->events);

	rrr_read_session_collection_clear(&handle->read_sessions);

	// Submodule should free any data stored in submodule_private_ptr
	handle->transport->methods->close(handle);

	if (handle->application_private_ptr != NULL && handle->application_ptr_destroy != NULL) {
		handle->application_ptr_destroy(handle->application_private_ptr);
	}

	RRR_FREE_IF_NOT_NULL(handle->match_string);
	RRR_FREE_IF_NOT_NULL(handle->application_close_reason_string);

	rrr_socket_send_chunk_collection_clear(&handle->send_chunks);

	rrr_net_transport_connection_id_collection_clear(&handle->cids);

	rrr_free(handle);

	return RRR_LL_DID_DESTROY;
}

static int __rrr_net_transport_iterate_with_callback (
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode search_mode,
		struct rrr_net_transport_handle *search_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	int ret = 0;

	// This function is only allowed to return OK or HARD ERROR (0 or 1)

	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (search_mode != RRR_NET_TRANSPORT_SOCKET_MODE_ANY && search_mode != node->mode) {
			RRR_LL_ITERATE_NEXT();
		}

		if (search_handle != NULL) {
			if (search_handle != node) {
				RRR_LL_ITERATE_NEXT();
			}

			// There can only be one match if we match on handle
			RRR_LL_ITERATE_LAST();
		}

		if ((ret = callback (node, arg)) != 0) {
			if (ret == RRR_READ_INCOMPLETE) {
				ret = 0;
			}
			else if (ret == RRR_READ_SOFT_ERROR || ret == RRR_READ_EOF) {
				// For nice treatment of remote, for instance send a disconnect packet
				if ((ret = transport->methods->pre_destroy (
						node,
						node->submodule_private_ptr,
						node->application_private_ptr
				)) == RRR_NET_TRANSPORT_READ_HARD_ERROR) {
					RRR_MSG_0("Internal error from pre destroy function in %s\n", __func__);
					goto out;
				}

				// When pre_destroy returns 0, go ahead with destruction
				if (ret == 0) {
					__rrr_net_transport_handle_destroy(node);
					RRR_LL_ITERATE_SET_DESTROY();
				}
				else {
					ret = 0;
				}
			}
			else {
				RRR_MSG_0("Error %i from callback function in %s\n", ret, __func__);
				ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);

	out:
	return ret;
}

int rrr_net_transport_iterate_by_mode_and_do (
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	return __rrr_net_transport_iterate_with_callback (
			transport,
			mode,
			NULL,
			callback,
			arg
	);
}

#define RRR_NET_TRANSPORT_HANDLE_GET(error_source)                                                                             \
    struct rrr_net_transport_handle *handle = NULL;                                                                            \
    do {if ((handle = __rrr_net_transport_handle_get(transport, transport_handle, error_source)) == NULL) {                    \
        RRR_MSG_0("Could not find transport handle %i in " error_source "\n", transport_handle);                               \
        return 1;                                                                                                              \
    }} while (0)

static int __rrr_net_transport_iterate_by_handle_ptr_and_do (
		struct rrr_net_transport *transport,
		struct rrr_net_transport_handle *handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	return __rrr_net_transport_iterate_with_callback (
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_ANY,
			handle,
			callback,
			arg
	);
}

static int __rrr_net_transport_iterate_by_handle_and_do (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	RRR_NET_TRANSPORT_HANDLE_GET("__rrr_net_transport_iterate_by_handle_and_do");
	return __rrr_net_transport_iterate_by_handle_ptr_and_do (
			transport,
			handle,
			callback,
			arg
	);
}

static int __rrr_net_transport_handle_create_and_push (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle,
		enum rrr_net_transport_socket_mode mode,
		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const struct rrr_socket_datagram *datagram,
		int (*submodule_callback)(RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS),
		void *submodule_callback_arg
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	struct rrr_net_transport_handle *new_handle = NULL;

	if ((new_handle = rrr_allocate(sizeof(*new_handle))) == NULL) {
		RRR_MSG_0("Could not allocate handle rrr_net_transport_handle_create_and_push\n");
		ret = 1;
		goto out;
	}

	memset(new_handle, '\0', sizeof(*new_handle));

	new_handle->transport = transport;
	new_handle->handle = handle;
	new_handle->mode = mode;

	rrr_event_collection_init(&new_handle->events, transport->event_queue);

	if ((ret = submodule_callback (
			&new_handle->submodule_private_ptr,
			&new_handle->submodule_fd,
			connection_ids,
			datagram,
			submodule_callback_arg
	)) != 0) {
		goto out_free;
	}

	RRR_LL_APPEND(collection, new_handle);

	goto out;
//	out_destroy:
//		__rrr_net_transport_handle_destroy(new_handle);
	out_free:
		rrr_free(new_handle);
	out:
		return ret;
}

/* Allocate an unused handle. The strategy is to begin with 1, check if it is available,
 * and if not continue incrementing to find the first available. This should be efficient
 * considering the lifetime of connections is usually short thus handles may be re-used. */
int rrr_net_transport_handle_allocate_and_add (
		rrr_net_transport_handle *handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const struct rrr_socket_datagram *datagram,
		int (*submodule_callback)(RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS),
		void *submodule_callback_arg
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	int ret = 0;

	*handle_final = 0;

	rrr_net_transport_handle new_handle_id = 0;

	if (RRR_LL_COUNT(collection) >= RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX) {
		RRR_MSG_0("Error: Max number of handles (%i) reached in rrr_net_transport_handle_allocate_and_add\n",
				RRR_NET_TRANSPORT_AUTOMATIC_HANDLE_MAX);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	int max_attempts = 100000;
	for (rrr_net_transport_handle i = collection->next_handle_position; --max_attempts > 0; i++) {
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
			connection_ids,
			datagram,
			submodule_callback,
			submodule_callback_arg
	)) != 0) {
		goto out;
	}

	*handle_final = new_handle_id;

	out:
	return ret;
}

struct rrr_net_transport_handle_close_callback_data {
	int found;
};

static int __rrr_net_transport_handle_close_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_net_transport_handle_close_callback_data *callback_data = arg;

	(void)(handle);

	callback_data->found = 1;

	// Makes iterator destroy the connection
	return RRR_READ_EOF;
}

static int __rrr_net_transport_handle_close (
		struct rrr_net_transport_handle *handle
) {
	struct rrr_net_transport_handle_close_callback_data callback_data = {
		0
	};

	// In case a pre-destroy function is not ready to destroy, this cause the
	// read function to just call close() again. The handle is destroyed when
	// pre-destroy finally returns OK (see iterator code). If the hard read
	// timeout is reached, the handle will be destroyed regardless of what
	// the pre-destroy function returns.

	handle->close_now = 1;

	int ret = __rrr_net_transport_iterate_with_callback (
			handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_ANY,
			handle,
			__rrr_net_transport_handle_close_callback,
			&callback_data
	);

	if (callback_data.found != 1) {
		RRR_BUG("BUG: Handle %p not found in %s\n", handle, __func__);
	}

	return ret;
}

static void __rrr_net_transport_handle_remove_and_destroy (
		struct rrr_net_transport *transport,
		struct rrr_net_transport_handle *handle
) {
	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (node == handle) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&transport->handles, 0; __rrr_net_transport_handle_destroy(node));
}

static int __rrr_net_transport_handle_send_nonblock (
		rrr_biglength *written_bytes,
		struct rrr_net_transport_handle *handle,
		const void *data,
		rrr_biglength size
) {
	int ret = 0;

	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to __rrr_net_transport_handle_send_nonblock was not of CONNECTION type\n");
	}

	if ((ret = handle->transport->methods->send (
			written_bytes,
			handle,
			data,
			size
	)) != 0) {
		if (ret != RRR_NET_TRANSPORT_SEND_INCOMPLETE) {
			RRR_DBG_7("net transport fd %i [%s] return %i from submodule send function, connection should be closed\n",
					handle->submodule_fd, handle->transport->application_name, ret);
			goto out;
		}
	}

	if (ret == 0 && *written_bytes != size) {
		ret = RRR_NET_TRANSPORT_SEND_INCOMPLETE;
	}

	handle->bytes_written_total += (uint64_t) *written_bytes;

	out:
	return ret;
}

static int __rrr_net_transport_receive (
		const struct rrr_net_transport_handle *listen_handle,
		const struct rrr_socket_datagram *datagram,
		struct rrr_net_transport_handle *handle
) {
	RRR_DBG_7("net transport fd %i [%s] deliver datagram of size %llu to handle %i\n",
			listen_handle->submodule_fd,
			listen_handle->transport->application_name,
			(long long unsigned) datagram->msg_len,
			handle->handle
	);

	return rrr_net_transport_ctx_receive(handle, datagram);
}

static int __rrr_net_transport_decode_client (
		struct rrr_net_transport_handle *handle
) {
	int ret = RRR_NET_TRANSPORT_READ_OK;

	struct rrr_net_transport_connection_id_pair connection_ids = RRR_NET_TRANSPORT_CONNECTION_ID_PAIR_DEFAULT_INITIALIZER;
	uint8_t buf[65536];
	struct rrr_socket_datagram datagram;

	if ((ret = handle->transport->methods->decode (
			&connection_ids,
			&datagram,
			buf,
			sizeof(buf),
			handle
	)) != 0) {
		goto out;
	}

	if (datagram.msg_len == 0 || connection_ids.dst.length == 0) {
		goto out;
	}

	if (!rrr_net_transport_connection_id_collection_has(&handle->cids, &connection_ids.dst)) {
		RRR_DBG_7("net transport fd %i [%s] datagram of size %llu not delivered to handle (cid mismatch)\n",
				handle->submodule_fd,
				handle->transport->application_name,
				(long long unsigned) datagram.msg_len
		);
		goto out;
	}

	if ((ret = __rrr_net_transport_receive(handle, &datagram, handle)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void __rrr_net_transport_handle_event_read_add_if_needed (
		struct rrr_net_transport_handle *handle
) {
	if (handle->event_read.event != NULL && !EVENT_PENDING(handle->event_read)) {
		EVENT_ADD(handle->event_read);
	}
}

#define CHECK_CLOSE_NOW()                                                                                      \
    if (handle->close_now) { ret_tmp = RRR_READ_EOF; goto check_read_write_return; }

#define CHECK_READ_WRITE_RETURN()                                                                              \
    goto check_read_write_return;                                                                              \
    check_read_write_return:                                                                                   \
    do {if ((ret_tmp & ~(RRR_READ_INCOMPLETE)) != 0) {                                                         \
        __rrr_net_transport_handle_close(handle);                                                              \
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

	RRR_DBG_7("net transport fd %i [%s] no data received within %" PRIu64 " ms, closing connection\n",
			fd, handle->transport->application_name, handle->transport->first_read_timeout_ms);

	int ret_tmp = RRR_READ_EOF;
	CHECK_READ_WRITE_RETURN();
}

static void __rrr_net_transport_event_hard_read_timeout (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;
	struct rrr_net_transport *transport = handle->transport;

	(void)(fd);
	(void)(flags);

	RRR_DBG_7("net transport fd %i [%s] no data received for %" PRIu64 " ms, closing connection\n",
			handle->submodule_fd, handle->transport->application_name, handle->transport->hard_read_timeout_ms);

	int ret_tmp = RRR_READ_EOF;
	CHECK_READ_WRITE_RETURN();
	// Use stored pointer to transport in case handle has already been freed
	__rrr_net_transport_handle_remove_and_destroy(transport, handle);
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
			return;
		}

		RRR_DBG_7("net transport fd %i [%s] handshake error, closing connection. Return was %i.\n",
				handle->submodule_fd, handle->transport->application_name, ret_tmp);

		ret_tmp = RRR_READ_EOF;
		goto check_read_write_return;
	}

	RRR_DBG_7("net transport fd %i h %i [%s] handshake complete\n",
			handle->submodule_fd, handle->handle, handle->transport->application_name);

	if (handle->transport->handshake_complete_callback != NULL) {
		if ((ret_tmp = handle->transport->handshake_complete_callback(handle, handle->transport->handshake_complete_callback_arg)) != 0) {
			// Noisy
			// RRR_DBG_7("net transport fd %i h %i [%s] return %i from downstream handshake callback\n",
			//	handle->submodule_fd, handle->handle, handle->transport->application_name, ret_tmp);
			goto check_read_write_return;
		}
	}

	handle->handshake_complete = 1;

	EVENT_REMOVE(handle->event_handshake);
	EVENT_ADD(handle->event_read);

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

//	Noisy
//	RRR_DBG_7("net transport fd %i h %i [%s] read event handshake complete %i\n",
//		handle->submodule_fd, handle->handle, handle->transport->application_name, handle->handshake_complete);

	CHECK_CLOSE_NOW();

	if (handle->submodule_fd > 0 && handle->transport->methods->decode != NULL) {
		if ((ret_tmp = __rrr_net_transport_decode_client(handle)) != 0) {
			goto err;
		}
	}

	if (!handle->handshake_complete) {
		return;
	}

	EVENT_REMOVE(handle->event_first_read_timeout);
	EVENT_REMOVE(handle->event_read_notify);

	if ((ret_tmp = handle->transport->read_callback (
			handle,
			handle->transport->read_callback_arg
	)) == 0 || flags & EV_READ) {
		// Touch (prevent hard timeout) if:
		// - We are in timeout event and something by chance was read (callback returns 0)
		// - We are in read event (data was present on the socket)
		rrr_net_transport_ctx_touch (handle);
	}

	err:

#ifdef RRR_NET_TRANSPORT_READ_RET_DEBUG
	switch (ret_tmp) {
		case RRR_READ_OK:
			handle->read_ret_debug_ok++;
			break;
		case RRR_READ_INCOMPLETE:
			handle->read_ret_debug_incomplete++;
			break;
		case RRR_READ_SOFT_ERROR:
			handle->read_ret_debug_soft_error++;
			break;
		case RRR_READ_HARD_ERROR:
			handle->read_ret_debug_hard_error++;
			break;
		case RRR_READ_EOF:
			handle->read_ret_debug_eof++;
			break;
	};
#endif

	CHECK_READ_WRITE_RETURN();
}

static int __rrr_net_transport_event_write_send_chunk_callback (
		rrr_biglength *written_bytes,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength data_size,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	(void)(addr);
	(void)(addr_len);

	int ret = __rrr_net_transport_handle_send_nonblock (
			written_bytes,
			handle,
			data,
			data_size
	);

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

	if (rrr_socket_send_chunk_collection_count(&handle->send_chunks) > 0) {
		ret_tmp = rrr_socket_send_chunk_collection_send_with_callback (
				&handle->send_chunks,
				__rrr_net_transport_event_write_send_chunk_callback,
				handle
		);
	}

	if (rrr_socket_send_chunk_collection_count(&handle->send_chunks) == 0) {
		if (ret_tmp == 0 && handle->close_when_send_complete) {
			ret_tmp = RRR_SOCKET_READ_EOF;
		}
		EVENT_REMOVE(handle->event_write);
	}

	CHECK_READ_WRITE_RETURN();
}

static void __rrr_net_transport_handle_event_clear (
		struct rrr_net_transport_handle *handle
) {
	rrr_event_collection_clear(&handle->events);
	rrr_event_collection_init(&handle->events, handle->transport->event_queue);
	rrr_event_handle_clear (&handle->event_handshake);
	rrr_event_handle_clear (&handle->event_read);
	rrr_event_handle_clear (&handle->event_read_notify);
	rrr_event_handle_clear (&handle->event_write);
	rrr_event_handle_clear (&handle->event_first_read_timeout);
	rrr_event_handle_clear (&handle->event_hard_read_timeout);
}

#define RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_FIRST_READ  (1<<0)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_HARD        (1<<1)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ           (1<<2)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_DECODE_SERVER         (1<<3)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_ACCEPT         (1<<4)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE               (1<<5)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE_ALL           (1<<6)
#define RRR_NET_TRANSPORT_EVENT_SETUP_F_HANDSHAKE           (1<<7)

static int __rrr_net_transport_handle_event_setup (
		struct rrr_net_transport_handle *handle,
		int flags
);

static int __rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		uint16_t port,
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

	rrr_net_transport_handle transport_handle = 0;
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
		if ((ret = __rrr_net_transport_handle_event_setup (
			handle,
				RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_HANDSHAKE |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_HARD |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_FIRST_READ
		)) != 0) {
			goto out;
		}
	}

	callback(handle, (struct sockaddr *) &addr, socklen, callback_arg);

	// Safe to pass in pointer, transport is only accessed if it exists in the list
	if (close_after_callback) {
		__rrr_net_transport_handle_close (handle);
	}

	out:
	return ret;
}

int rrr_net_transport_connect_and_close_after_callback (
		struct rrr_net_transport *transport,
		uint16_t port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
) {
	return __rrr_net_transport_connect (transport, port, host, callback, callback_arg, 1);
}

int rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		uint16_t port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
) {
	return __rrr_net_transport_connect (transport, port, host, callback, callback_arg, 0);
}

void rrr_net_transport_handle_touch (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle
) {
	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			rrr_net_transport_ctx_touch(node);
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();
}

static void __rrr_net_transport_handle_ptr_close_reason_set (
		struct rrr_net_transport_handle *handle,
		enum rrr_net_transport_close_reason submodule_close_reason,
		uint64_t application_close_reason,
		const char *application_reason_string
) {
	handle->submodule_close_reason = submodule_close_reason;
	handle->application_close_reason = application_close_reason;

	RRR_FREE_IF_NOT_NULL(handle->application_close_reason_string);
	if (application_reason_string != NULL && (handle->application_close_reason_string = rrr_strdup(application_reason_string)) == NULL) {
		RRR_MSG_0("Warning: Failed to allocate memory for reason string in %s\n", __func__);
	}
}

// Close using iterator method which includes calling any pre destroy method
void rrr_net_transport_handle_ptr_close_with_reason (
		struct rrr_net_transport_handle *handle,
		enum rrr_net_transport_close_reason submodule_close_reason,
		uint64_t application_close_reason,
		const char *application_close_reason_string
) {
	__rrr_net_transport_handle_ptr_close_reason_set (
			handle,
			submodule_close_reason,
			application_close_reason,
			application_close_reason_string
	);

	__rrr_net_transport_handle_close(handle);
}

void rrr_net_transport_handle_close_with_reason (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle,
		enum rrr_net_transport_close_reason submodule_close_reason,
		uint64_t application_close_reason,
		const char *application_close_reason_string
) {
	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (node->handle == handle) {
			rrr_net_transport_handle_ptr_close_with_reason (
					node,
					submodule_close_reason,
					application_close_reason,
					application_close_reason_string
			);
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();
}

void rrr_net_transport_handle_ptr_close (
		struct rrr_net_transport_handle *handle
) {
	__rrr_net_transport_handle_close(handle);
}

rrr_net_transport_handle rrr_net_transport_handle_get_by_match (
		struct rrr_net_transport *transport,
		const char *string,
		uint64_t number
) {
	rrr_net_transport_handle result_handle = 0;

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

static struct rrr_net_transport_handle *__rrr_net_transport_handle_get_by_cid (
		struct rrr_net_transport *transport,
		const struct rrr_net_transport_connection_id *cid
) {
	assert(cid->length > 0);

	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (rrr_net_transport_connection_id_collection_has(&node->cids, cid))
			return node;
	RRR_LL_ITERATE_END();

	return NULL;
}

rrr_net_transport_handle rrr_net_transport_handle_get_by_cid (
		struct rrr_net_transport *transport,
		const struct rrr_net_transport_connection_id *cid
) {
	struct rrr_net_transport_handle *handle = __rrr_net_transport_handle_get_by_cid (transport, cid);
	return handle != NULL ? handle->handle : 0;
}

static struct rrr_net_transport_handle *__rrr_net_transport_handle_get_by_cid_pair (
		struct rrr_net_transport *transport,
		const struct rrr_net_transport_connection_id_pair *cids
) {
	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (rrr_net_transport_connection_id_collection_has(&node->cids, &cids->a))
			return node;
		if (rrr_net_transport_connection_id_collection_has(&node->cids, &cids->b))
			return node;
	RRR_LL_ITERATE_END();

	return NULL;
}

rrr_net_transport_handle rrr_net_transport_handle_get_by_cid_pair (
		struct rrr_net_transport *transport,
		const struct rrr_net_transport_connection_id_pair *cids
) {
	struct rrr_net_transport_handle *handle = __rrr_net_transport_handle_get_by_cid_pair (transport, cids);
	return handle != NULL ? handle->handle : 0;
}

int rrr_net_transport_handle_with_transport_ctx_do (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_with_transport_ctx_do");
	ret = callback(handle, arg);

	return ret;
}

static int __rrr_net_transport_handle_ptr_cid_push (
		struct rrr_net_transport_handle *handle,
		const struct rrr_net_transport_connection_id *cid
) {
	int ret = 0;

	if (__rrr_net_transport_handle_get_by_cid (handle->transport, cid) != NULL) {
		ret = RRR_NET_TRANSPORT_READ_BUSY;
		goto out;
	}

	if ((ret = rrr_net_transport_ctx_connection_id_push(handle, cid)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_net_transport_handle_cid_push (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const struct rrr_net_transport_connection_id *cid
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_cid_push");

	return __rrr_net_transport_handle_ptr_cid_push (handle, cid);
}

int rrr_net_transport_handle_cids_push (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const struct rrr_net_transport_connection_id_pair *cids
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_cids_push");

	int ret = 0;

	if (cids->a.length > 0 && (ret = __rrr_net_transport_handle_ptr_cid_push (handle, &cids->a)) != 0) {
		goto out;
	}

	if (cids->b.length > 0 && (ret = __rrr_net_transport_handle_ptr_cid_push (handle, &cids->b)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_net_transport_handle_cid_remove (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const struct rrr_net_transport_connection_id *cid
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_cid_remove");

	rrr_net_transport_ctx_connection_id_remove(handle, cid);

	return 0;
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

	// Re-add read-events (if they where deleted due to ratelimiting or not yet added)

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

	if ((ret = __rrr_net_transport_handle_event_setup (
		handle,
			RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ |
			RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE |
			RRR_NET_TRANSPORT_EVENT_SETUP_F_HANDSHAKE |
			RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_HARD |
			RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_FIRST_READ
	)) != 0) {
		goto out;
	}

	memcpy(&handle->connected_addr, sockaddr, socklen);
	handle->connected_addr_len = socklen;

	final_callback(handle, sockaddr, socklen, final_callback_arg);

	out:
	return ret;
}

static void __rrr_net_transport_event_accept (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *listen_handle = arg;
	rrr_net_transport_handle new_handle = 0;

	(void)(fd);
	(void)(flags);

	int ret_tmp = listen_handle->transport->methods->accept (
			&new_handle,
			listen_handle,
			NULL,
			NULL,
			__rrr_net_transport_accept_callback_intermediate,
			NULL,
			listen_handle->transport->accept_callback,
			listen_handle->transport->accept_callback_arg
	);

	if (ret_tmp != 0) {
		rrr_event_dispatch_break(listen_handle->transport->event_queue);
	}
}

struct rrr_net_transport_decode_receive_callback_data {
	const struct rrr_net_transport_handle *listen_handle;
	const struct rrr_socket_datagram *datagram;
};
		
static int __rrr_net_transport_decode_receive_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_net_transport_decode_receive_callback_data *callback_data = arg;
	return __rrr_net_transport_receive(callback_data->listen_handle, callback_data->datagram, handle);
}

static int __rrr_net_transport_decode_server (
		struct rrr_net_transport_handle *listen_handle
) {
	int ret = RRR_NET_TRANSPORT_READ_OK;

	rrr_net_transport_handle new_handle = 0;
	struct rrr_net_transport_handle *handle = NULL;
	struct rrr_net_transport_connection_id_pair connection_ids = RRR_NET_TRANSPORT_CONNECTION_ID_PAIR_DEFAULT_INITIALIZER;
	uint8_t buf[65536];
	struct rrr_socket_datagram datagram;

	if ((ret = listen_handle->transport->methods->decode (
			&connection_ids,
			&datagram,
			buf,
			sizeof(buf),
			listen_handle
	)) != 0) {
		goto out;
	}

	if (datagram.msg_len == 0 || connection_ids.dst.length == 0) {
		goto out;
	}

	// Try to find existing handle and deliver the datagram to it. If non-existent,
	// call accept to create a new handle. Accept may or may not create a new handle,
	// and if no handle is created, no further processing of the datagram occurs.

	struct rrr_net_transport_decode_receive_callback_data callback_data = {
		listen_handle,
		&datagram
	};

	if ((handle = __rrr_net_transport_handle_get_by_cid(listen_handle->transport, &connection_ids.dst)) != NULL) {
		if ((ret = __rrr_net_transport_iterate_by_handle_ptr_and_do (
				listen_handle->transport,
				handle,
				__rrr_net_transport_decode_receive_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
		goto out;
	}

	if ((ret = listen_handle->transport->methods->accept (
			&new_handle,
			listen_handle,
			&connection_ids,
			&datagram,
			__rrr_net_transport_accept_callback_intermediate,
			NULL,
			listen_handle->transport->accept_callback,
			listen_handle->transport->accept_callback_arg
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			// OK, drop packet
			ret = RRR_NET_TRANSPORT_READ_OK;
		}
		goto out;
	}

	if (new_handle > 0) {
		if ((ret = __rrr_net_transport_iterate_by_handle_and_do (
				listen_handle->transport,
				new_handle,
				__rrr_net_transport_decode_receive_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}
	else {
		RRR_DBG_7("net transport fd %i [%s] datagram of size %llu not delivered to any handle\n",
				listen_handle->submodule_fd,
				listen_handle->transport->application_name,
				(long long unsigned) datagram.msg_len
		);
	}

	out:
	return ret;
}

static void __rrr_net_transport_event_decode_server (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_net_transport_handle *listen_handle = arg;

	(void)(fd);
	(void)(flags);

	if (__rrr_net_transport_decode_server (listen_handle) == RRR_NET_TRANSPORT_READ_HARD_ERROR) {
		// Unhandled error
		rrr_event_dispatch_break(listen_handle->transport->event_queue);
	}
}

static int __rrr_net_transport_handle_event_setup (
		struct rrr_net_transport_handle *handle,
		int flags
) {
	int ret = 0;

	// FIRST READ TIMEOUT

	if ( flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_FIRST_READ &&
	     handle->transport->first_read_timeout_ms > 0
	) {
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

	// HARD TIMEOUT

	if ( flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_HARD &&
	     handle->transport->hard_read_timeout_ms > 0
	) {
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

	// READ
	if (flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ) {
		assert(!(flags & (RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_DECODE_SERVER|RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_ACCEPT)));
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
		EVENT_ADD(handle->event_read);
	}

	// READ (decode packet and look up or create connection)
	if (flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_DECODE_SERVER) {
		assert(!(flags & (RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ|RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_ACCEPT)));
		if ((ret = rrr_event_collection_push_read (
				&handle->event_read,
				&handle->events,
				handle->submodule_fd,
				__rrr_net_transport_event_decode_server,
				handle,
				0
		)) != 0) {
			goto out;
		}
		EVENT_ADD(handle->event_read);
	}

	// READ (accept connections)
	if (flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_ACCEPT) {
		assert(!(flags & (RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ|RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_DECODE_SERVER)));
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
	}

	// READ NOTIFY
	if (flags & (RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ|RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_DECODE_SERVER|RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_ACCEPT)) {
		if ((ret = rrr_event_collection_push_periodic (
				&handle->event_read_notify,
				&handle->events,
				__rrr_net_transport_event_read,
				handle,
				1 * 1000 // 1 ms
		)) != 0) {
			goto out;
		}
	}

	// WRITE
	if (flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE) {
		assert(!(flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE_ALL));
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
	}

	// WRITE (write for all connections)
	if (flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE_ALL) {
		assert(!(flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE));
		if ((ret = rrr_event_collection_push_write (
				&handle->event_write,
				&handle->events,
				handle->submodule_fd,
				__rrr_net_transport_event_write,
				handle,
				0
		)) != 0) {
			goto out;
		}
	}

	// HANDSHAKE
	if (flags & RRR_NET_TRANSPORT_EVENT_SETUP_F_HANDSHAKE) { 
		if ((ret = rrr_event_collection_push_read (
				&handle->event_handshake,
				&handle->events,
				handle->submodule_fd,
				__rrr_net_transport_event_handshake,
				handle,
				1000 // 1 ms
		)) != 0) {
			goto out;
		}

		EVENT_ADD(handle->event_handshake);
		EVENT_ACTIVATE(handle->event_handshake);
	}

	out:
	return ret;
}

static int __rrr_net_transport_bind_and_listen_callback_intermediate (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS
) {
	(void)(arg);

	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("__rrr_net_transport_bind_and_listen_callback_intermediate");

	if ((ret = __rrr_net_transport_handle_event_setup (
			handle,
			handle->transport->methods->decode != NULL
				? RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_DECODE_SERVER | RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE_ALL
				: RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_ACCEPT
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
		uint16_t port,
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

void rrr_net_transport_event_activate_all_connected_read (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_handle);
		if (node->event_read.event != NULL)
			EVENT_ACTIVATE(node->event_read);
	RRR_LL_ITERATE_END();
}

static int __rrr_net_transport_event_setup (
		struct rrr_net_transport *transport,
		uint64_t first_read_timeout_ms,
		uint64_t soft_read_timeout_ms,
		uint64_t hard_read_timeout_ms,
		rrr_length send_chunk_count_limit,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *accept_callback_arg,
		int (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS),
		void *handshake_complete_callback_arg,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg
) {
	int ret = 0;

	rrr_net_transport_common_cleanup (transport);

	transport->first_read_timeout_ms = first_read_timeout_ms;
	transport->soft_read_timeout_ms = soft_read_timeout_ms;
	transport->hard_read_timeout_ms = hard_read_timeout_ms;
	transport->send_chunk_count_limit = send_chunk_count_limit;

	rrr_time_from_usec(&transport->first_read_timeout_tv, first_read_timeout_ms * 1000);
	rrr_time_from_usec(&transport->soft_read_timeout_tv, soft_read_timeout_ms * 1000);
	rrr_time_from_usec(&transport->hard_read_timeout_tv, hard_read_timeout_ms * 1000);

	transport->accept_callback = accept_callback;
	transport->accept_callback_arg = accept_callback_arg;

	transport->handshake_complete_callback = handshake_complete_callback;
	transport->handshake_complete_callback_arg = handshake_complete_callback_arg;

	transport->read_callback = read_callback;
	transport->read_callback_arg = read_callback_arg;

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

int rrr_net_transport_is_tls (
		struct rrr_net_transport *transport
) {
	return transport->methods->is_tls();
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

int rrr_net_transport_handle_notify_read (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_notify_read");

	rrr_net_transport_ctx_notify_read(handle);

	return 0;
}

int rrr_net_transport_handle_match_data_set (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const char *string,
		uint64_t number
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_match_data_set");

	RRR_FREE_IF_NOT_NULL(handle->match_string);
	if ((handle->match_string = rrr_strdup(string)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return 1;
	}

	handle->match_number = number;

	return 0;
}

int rrr_net_transport_handle_migrate (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		uint16_t port,
		const char *host,
		void (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *callback_arg
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_migrate");

	int ret = 0;

	struct sockaddr_storage addr;
	socklen_t socklen = sizeof(addr);

	if ((ret = transport->methods->migrate (
			handle,
			(struct sockaddr *) &addr,
			&socklen,
			transport,
			port,
			host
	)) != 0) {
		goto out;
	}

	if (handle->submodule_fd == 0) {
		RRR_BUG("BUG: Submodule FD not set in %s\n", __func__);
	}

	memcpy(&handle->connected_addr, &addr, socklen);
	handle->connected_addr_len = socklen;

	if (transport->event_queue != NULL) {
		__rrr_net_transport_handle_event_clear(handle);
		if ((ret = __rrr_net_transport_handle_event_setup (
			handle,
				RRR_NET_TRANSPORT_EVENT_SETUP_F_READ_READ |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_WRITE |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_HARD |
				RRR_NET_TRANSPORT_EVENT_SETUP_F_TIMEOUT_FIRST_READ
		)) != 0) {
			goto out;
		}
	}

	callback(handle, (struct sockaddr *) &addr, socklen, callback_arg);

	out:
	return ret;
}

void rrr_net_transport_handle_ptr_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
) {
	if (handle->application_private_ptr != NULL) {
		RRR_BUG("rrr_net_transport_handle_ptr_application_data_bind called twice, pointer was already set\n");
	}
	handle->application_private_ptr = application_data;
	handle->application_ptr_destroy = application_data_destroy;
}

void rrr_net_transport_handle_ptr_application_pre_destroy_function_set (
		struct rrr_net_transport_handle *handle,
		int (*application_pre_destroy)(RRR_NET_TRANSPORT_APPLICATION_PRE_DESTROY_ARGS)
) {
	handle->application_pre_destroy = application_pre_destroy;
}

int rrr_net_transport_handle_ptr_modify (
		struct rrr_net_transport_handle *handle,
		int (*submodule_callback)(RRR_NET_TRANSPORT_MODIFY_CALLBACK_ARGS),
		void *submodule_callback_arg
) {
	int ret = 0;

	void *submodule_private_ptr = handle->submodule_private_ptr;
	int submodule_fd = handle->submodule_fd;

	if ((ret = submodule_callback (
			&submodule_private_ptr,
			&submodule_fd,
			submodule_callback_arg
	)) != 0) {
		goto out;
	}

	if (submodule_private_ptr != handle->submodule_private_ptr) {
		RRR_DBG_7("net transport fd %i [%s] new submodule data\n",
				handle->submodule_fd, handle->transport->application_name);
		handle->submodule_private_ptr = submodule_private_ptr;
	}

	if (submodule_fd != handle->submodule_fd) {
		RRR_DBG_7("net transport fd %i [%s] new fd %i\n",
				handle->submodule_fd, handle->transport->application_name, submodule_fd);
		handle->submodule_fd = submodule_fd;
	}

	out:
	return ret;
}

int rrr_net_transport_handle_ptr_read_stream (
		uint64_t *bytes_read,
		struct rrr_net_transport_handle *handle,
		int (*callback)(RRR_NET_TRANSPORT_READ_STREAM_CALLBACK_ARGS),
		void *arg
) {
	int ret = handle->transport->methods->read_stream(bytes_read, handle, callback, arg);

	handle->bytes_read_total += *bytes_read;

	return ret;
}

int rrr_net_transport_handle_check_handshake_complete (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle
) {
	int ret = 0;

	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_match_data_set");

	ret = (handle->handshake_complete ? RRR_READ_OK : RRR_READ_INCOMPLETE);

	return ret;
}

int rrr_net_transport_handle_stream_open_local (
		int64_t *result,
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		int flags,
		void *stream_open_callback_arg_local
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_stream_open");

	return rrr_net_transport_ctx_stream_open_local(result, handle, flags, stream_open_callback_arg_local);
}

int rrr_net_transport_handle_stream_consume (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		int64_t stream_id,
		size_t consumed
) {
	RRR_NET_TRANSPORT_HANDLE_GET("rrr_net_transport_handle_stream_consume");

	return rrr_net_transport_ctx_stream_consume(handle, stream_id, consumed);
}

void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
) {
	struct rrr_net_transport_handle_collection *collection = &transport->handles;

	// If application wishes a pre-destroy function to be called, the
	// iterator function must be used to close the connections prior
	// to calling cleanup.

	RRR_LL_DESTROY(
			collection,
			struct rrr_net_transport_handle,
			__rrr_net_transport_handle_destroy (node)
	);
}

enum rrr_net_transport_type rrr_net_transport_type_get (
		const struct rrr_net_transport *transport
) {
	return transport->transport_type;
}

void rrr_net_transport_stats_get (
		rrr_length *listening_count,
		rrr_length *connected_count,
		struct rrr_net_transport *transport
) {
	*listening_count = 0;
	*connected_count = 0;

	RRR_LL_ITERATE_BEGIN(&transport->handles, struct rrr_net_transport_handle);
		if (node->mode == RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN) {
			rrr_length_inc_bug(listening_count);
		}
		else {
			rrr_length_inc_bug(connected_count);
		}
	RRR_LL_ITERATE_END();
}

static int __rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		const char *application_name,
		int flags,
		struct rrr_event_queue *queue,
		const char *alpn_protos,
		unsigned int alpn_protos_length,
		int do_setup_events,
		uint64_t first_read_timeout_ms,
		uint64_t soft_read_timeout_ms,
		uint64_t hard_read_timeout_ms,
		rrr_length send_chunk_count_limit,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *accept_callback_arg,
		int (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS),
		void *handshake_complete_callback_arg,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg,
		int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS),
		void *stream_open_callback_arg
) {
#if !defined(RRR_WITH_LIBRESSL) && !defined(RRR_WITH_OPENSSL) && !defined(RRR_WITH_HTTP3)
	(void)(alpn_protos_length);
#endif
#if !defined(RRR_WITH_HTTP3)
	(void)(stream_open_callback);
	(void)(stream_open_callback_arg);
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
			if (stream_open_callback != NULL) {
				RRR_BUG("BUG: Stream open callback provided to rrr_net_transport_new in plain mode\n");
			}
			ret = rrr_net_transport_plain_new((struct rrr_net_transport_plain **) &new_transport);
			break;
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
		case RRR_NET_TRANSPORT_TLS:
			if (stream_open_callback != NULL) {
				RRR_BUG("BUG: Stream open callback provided to rrr_net_transport_new in TLS mode\n");
			}
			if (flags & RRR_NET_TRANSPORT_F_QUIC_STREAM_OPEN_CB_LOCAL_ONLY) {
				RRR_BUG("BUG: Stream open local only flag provided to rrr_net_transport_new in TLS mode\n");
			}
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
#if defined(RRR_WITH_HTTP3)
		case RRR_NET_TRANSPORT_QUIC:
			if (stream_open_callback == NULL) {
				RRR_BUG("BUG: Stream open callback not provided to rrr_net_transport_new in QUIC mode\n");
			}
			ret = rrr_net_transport_quic_new (
					(struct rrr_net_transport_tls **) &new_transport,
					flags,
					config->tls_certificate_file,
					config->tls_key_file,
					config->tls_ca_file,
					config->tls_ca_path,
					alpn_protos,
					alpn_protos_length,
					stream_open_callback,
					stream_open_callback_arg
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

	if (do_setup_events) {
		if ((ret = __rrr_net_transport_event_setup (
				new_transport,
				first_read_timeout_ms,
				soft_read_timeout_ms,
				hard_read_timeout_ms,
				send_chunk_count_limit,
				accept_callback,
				accept_callback_arg,
				handshake_complete_callback,
				handshake_complete_callback_arg,
				read_callback,
				read_callback_arg
		)) != 0) {
			goto out_destroy;
		}
	}

	new_transport->transport_type = config->transport_type;
	strncpy(new_transport->application_name, application_name, sizeof(new_transport->application_name));
	new_transport->application_name[sizeof(new_transport->application_name)-1] = '\0';

	*result = new_transport;

	goto out;
	out_destroy:
		new_transport->methods->destroy(new_transport);
	out:
		return ret;
}

int rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		const char *application_name,
		int flags,
		struct rrr_event_queue *queue,
		const char *alpn_protos,
		unsigned int alpn_protos_length,
		uint64_t first_read_timeout_ms,
		uint64_t soft_read_timeout_ms,
		uint64_t hard_read_timeout_ms,
		rrr_length send_chunk_count_limit,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *accept_callback_arg,
		int (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS),
		void *handshake_complete_callback_arg,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg,
		int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS),
		void *stream_open_callback_arg
) {
	return __rrr_net_transport_new (
			result,
			config,
			application_name,
			flags,
			queue,
			alpn_protos,
			alpn_protos_length,
			1, /* Do setup events */
			first_read_timeout_ms,
			soft_read_timeout_ms,
			hard_read_timeout_ms,
			send_chunk_count_limit,
			accept_callback,
			accept_callback_arg,
			handshake_complete_callback,
			handshake_complete_callback_arg,
			read_callback,
			read_callback_arg,
			stream_open_callback,
			stream_open_callback_arg
	);
}

int rrr_net_transport_new_simple (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		const char *application_name,
		int flags,
		struct rrr_event_queue *queue
) {
	return __rrr_net_transport_new (
			result,
			config,
			application_name,
			flags,
			queue,
			NULL,
			0,
			0, /* Do not setup events */
			0,
			0,
			0,
			0,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
	);
}

void rrr_net_transport_destroy (
		struct rrr_net_transport *transport
) {
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
