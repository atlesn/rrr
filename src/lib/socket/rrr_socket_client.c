/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "../log.h"
#include "../allocator.h"

#include "rrr_socket.h"
#include "rrr_socket_common.h"
#include "rrr_socket_client.h"
#include "rrr_socket_read.h"
#include "rrr_socket_constants.h"
#include "rrr_socket_send_chunk.h"

#include "../read.h"
#include "../rrr_strerror.h"
#include "../array.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../messages/msg.h"
#include "../util/posix.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../util/macro_utils.h"

#define RRR_SOCKET_CLIENT_COLLECTION_DEFAULT_CONNECT_TIMEOUT_S 5
#define RRR_SOCKET_CLIENT_COLLECTION_DEFAULT_IDLE_TIMEOUT_S 0 /* No timeout */

struct rrr_socket_client_collection {
	RRR_LL_HEAD(struct rrr_socket_client);
	char *creator;

	struct rrr_event_queue *queue;

	// Called when a chunk is successfully sent or a client is destroyed with unsent data (if set)
	void (*chunk_send_notify_callback)(RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS);
	void *chunk_send_notify_callback_arg;

	// Called when a client FD is closed for whatever reason (if set)
	void (*client_fd_close_callback)(RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS);
	void *client_fd_close_callback_arg;

	// Common settings
	rrr_biglength read_step_max_size;
	int read_flags_socket;

	// Settings for array reading
	int array_do_sync_byte_by_byte;
	unsigned array_message_max_size;
	const struct rrr_array_tree *array_tree;

	// Setable values
	uint64_t connect_timeout_us;
	uint64_t idle_timeout_us;

	// Common callbacks
	void (*event_read_callback)(evutil_socket_t fd, short flags, void *arg);
	int  (*callback_private_data_new)(void **target, int fd, void *private_arg);
	void (*callback_private_data_destroy)(void *private_data);
	void *callback_private_data_arg;
	void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS);
	void *callback_set_read_flags_arg;

	// Callbacks for message mode
	RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_SEMICOLON;
	void *callback_msg_arg;

	// Callbacks for raw mode
	int (*get_target_size)(RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS);
	void *get_target_size_arg;
	int (*complete_callback)(RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS);
	void *complete_callback_arg;

	// Callbacks for array tree mode
	int (*array_callback)(RRR_SOCKET_CLIENT_ARRAY_CALLBACK_ARGS);
	void *array_callback_arg;

	// Callback for parse errors
	void (*error_callback)(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS);
	void *error_callback_arg;

	// Callback for new accepted connections
	int (*accept_callback)(RRR_SOCKET_CLIENT_ACCEPT_CALLBACK_ARGS);
	void *accept_callback_arg;
};

struct rrr_socket_client_fd {
	RRR_LL_NODE(struct rrr_socket_client_fd);

	struct rrr_socket_client *client;

	int fd;

	struct rrr_event_collection events;
	rrr_event_handle event_read;
	rrr_event_handle event_write;
	rrr_event_handle event_timeout;

	// Used when identified by raw address
	struct sockaddr_storage addr;
	socklen_t addr_len;

	// Used when identified by string (e.g. hostname)
	char *addr_string;
};

/*
 * - When accepting or pushing an fd, connected_fd is set immediately.
 *
 * - When connecting, multiple possible connections/suggestions are active. When one of them succeed, the
 *   connected_fd is set to it's fd and the other fds are closed.
 */
struct rrr_socket_client {
	RRR_LL_NODE(struct rrr_socket_client);
	RRR_LL_HEAD(struct rrr_socket_client_fd);

	struct rrr_socket_client_collection *collection;

	struct rrr_socket_send_chunk_collection send_chunks;
	struct rrr_read_session_collection read_sessions;

	// Not to be freed, managed by linked list
	struct rrr_socket_client_fd *connected_fd;

	uint64_t last_seen;

	enum rrr_socket_client_collection_create_type create_type;

	int close_when_send_complete;

	void *private_data;
};

static int __rrr_socket_client_fd_destroy (
		struct rrr_socket_client_fd *client_fd
) {
	struct rrr_socket_client_collection *collection = client_fd->client->collection;

	if (collection->client_fd_close_callback) {
		collection->client_fd_close_callback (
				client_fd->fd,
				(const struct sockaddr *) &client_fd->addr,
				client_fd->addr_len,
				client_fd->addr_string,
				client_fd->client->create_type,
				client_fd->client->connected_fd == client_fd,
				collection->client_fd_close_callback_arg
		);
	}

	rrr_event_collection_clear(&client_fd->events);
	if (client_fd->fd > 0) {
		rrr_socket_close(client_fd->fd);
	}
	RRR_FREE_IF_NOT_NULL(client_fd->addr_string);
	rrr_free(client_fd);
	return 0;
}

static int __rrr_socket_client_fd_new (
		struct rrr_socket_client_fd **result,
		struct rrr_socket_client *client,
		struct rrr_event_queue *queue,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const char *addr_string
) {
	int ret = 0;

	struct rrr_socket_client_fd *client_fd = rrr_allocate_zero(sizeof(*client_fd));
	if (client_fd == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (addr_string != NULL) {
		if ((client_fd->addr_string = rrr_strdup(addr_string)) == NULL) {
			RRR_MSG_0("Could not allocate memory for address string in %s\n", __func__);
			ret = 1;
			goto out_free;
		}
	}

	if (addr_len > sizeof(client_fd->addr)) {
		RRR_BUG("BUG: Address length too long in %s\n", __func__);
	}

	rrr_event_collection_init(&client_fd->events, queue);

	client_fd->fd = fd;
	if (addr != NULL) {
		memcpy (&client_fd->addr, addr, addr_len);
	}
	client_fd->addr_len = addr_len;
	client_fd->client = client;

	*result = client_fd;

	goto out;
	out_free:
		rrr_free(client_fd);
	out:
		return ret;
}

static void __rrr_socket_client_chunk_send_notify_success_callback (
		const void *data,
		rrr_biglength data_size,
		rrr_biglength data_pos,
		void *chunk_private_data,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	if (client->collection->chunk_send_notify_callback) {
		client->collection->chunk_send_notify_callback (
				1, // Success
				client->connected_fd->fd,
				data,
				data_size,
				data_pos,
				chunk_private_data,
				client->collection->chunk_send_notify_callback_arg
		);
	}
}

static void __rrr_socket_client_chunk_send_notify_fail_callback (
		const void *data,
		rrr_biglength data_size,
		rrr_biglength data_pos,
		void *chunk_private_data,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	if (client->collection->chunk_send_notify_callback) {
		client->collection->chunk_send_notify_callback (
				0, // Fail
				client->connected_fd->fd,
				data,
				data_size,
				data_pos,
				chunk_private_data,
				client->collection->chunk_send_notify_callback_arg
		);
	}
}

/*
 * Ensure that the client is removed from the collection before using
 */
static int __rrr_socket_client_destroy_dangerous (
		struct rrr_socket_client *client
) {
	struct rrr_socket_client_collection *collection = client->collection;

	RRR_LL_DESTROY(client, struct rrr_socket_client_fd, __rrr_socket_client_fd_destroy(node));
	if (client->private_data != NULL) {
		client->collection->callback_private_data_destroy(client->private_data);
	}
	if (collection->chunk_send_notify_callback) {
		rrr_socket_send_chunk_collection_clear_with_callback (
				&client->send_chunks,
				__rrr_socket_client_chunk_send_notify_fail_callback,
				client
		);
	}
	else {
		rrr_socket_send_chunk_collection_clear(&client->send_chunks);
	}
	rrr_read_session_collection_clear(&client->read_sessions);
	rrr_free(client);
	return 0;
}

static int __rrr_socket_client_private_data_create_as_needed (
		struct rrr_socket_client *client
) {
	int ret = 0;

	if (client->collection->callback_private_data_new != NULL) {
		if ((ret = client->collection->callback_private_data_new (
				&client->private_data,
				client->connected_fd->fd,
				client->collection->callback_private_data_arg
		)) != 0) {
			RRR_MSG_0("Error while initializing private data in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static void __rrr_socket_client_send_push_notify (
		struct rrr_socket_client *client
) {
	if (client->connected_fd == NULL || !EVENT_INITIALIZED(client->connected_fd->event_write)) {
		return;
	}

	EVENT_ADD(client->connected_fd->event_write);
}

static int __rrr_socket_client_connected_fd_finalize_and_create_private_data (
		struct rrr_socket_client *client,
		int fd
) {
	int ret = 0;

	int destroyed = 0;
	RRR_LL_ITERATE_BEGIN(client, struct rrr_socket_client_fd);
		if (node->fd != fd) {
			RRR_LL_ITERATE_SET_DESTROY();
			destroyed++;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(client, __rrr_socket_client_fd_destroy(node));
	
	RRR_DBG_7("fd %i in client collection remaining during connect finalize, %i other fds were closed. Connection is ready.\n",
		fd, destroyed);

	if (RRR_LL_COUNT(client) != 1) {
		RRR_BUG("BUG: FD count was not exactly 1 in %s\n", __func__);
	}

	client->connected_fd = RRR_LL_FIRST(client);

	ret = __rrr_socket_client_private_data_create_as_needed(client);

	if (rrr_socket_send_chunk_collection_count(&client->send_chunks) > 0) {
		__rrr_socket_client_send_push_notify(client);
	}

	return ret;
}

static int __rrr_socket_client_new_and_add (
		struct rrr_socket_client **result,
		struct rrr_socket_client_collection *collection,
		enum rrr_socket_client_collection_create_type create_type
) {
	int ret = 0;

	*result = NULL;

	struct rrr_socket_client *client = rrr_allocate (sizeof(*client));
	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(client, '\0', sizeof(*client));

	client->last_seen = rrr_time_get_64();
	client->collection = collection;
	client->create_type = create_type;

	*result = client;
	RRR_LL_UNSHIFT(collection, client);

	out:
	return ret;
}

static void __rrr_socket_client_collection_clear (
		struct rrr_socket_client_collection *collection
) {
	RRR_LL_DESTROY(collection,struct rrr_socket_client,__rrr_socket_client_destroy_dangerous(node));
}

void rrr_socket_client_collection_set_connect_timeout (
		struct rrr_socket_client_collection *collection,
		uint64_t connect_timeout_us
) {
	collection->connect_timeout_us = connect_timeout_us;
}

void rrr_socket_client_collection_set_idle_timeout (
		struct rrr_socket_client_collection *collection,
		uint64_t idle_timeout_us
) {
	collection->idle_timeout_us = idle_timeout_us;
}

void rrr_socket_client_collection_destroy (
		struct rrr_socket_client_collection *collection
) {
	__rrr_socket_client_collection_clear(collection);
	RRR_FREE_IF_NOT_NULL(collection->creator);
	rrr_free(collection);
}

static void __rrr_socket_client_collection_find_and_destroy (
		struct rrr_socket_client_collection *collection,
		const struct rrr_socket_client *client
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if (node == client) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy_dangerous(node));
}

static void __rrr_socket_client_fd_find_and_destroy (
		struct rrr_socket_client_collection *collection,
		struct rrr_socket_client *client,
		int fd
) {
	RRR_LL_ITERATE_BEGIN(client, struct rrr_socket_client_fd);
		if (fd == node->fd) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(client, __rrr_socket_client_fd_destroy(node));

	if (RRR_LL_COUNT(client) == 0) {
		__rrr_socket_client_collection_find_and_destroy(collection, client);
	}
}

static int __rrr_socket_client_collection_new (
		struct rrr_socket_client_collection **target,
		struct rrr_event_queue *queue,
		const char *creator
) {
	int ret = 0;

	*target = NULL;

	struct rrr_socket_client_collection *collection = NULL;

	if ((collection = rrr_allocate(sizeof(*collection))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(collection, '\0', sizeof(*collection));
	if ((collection->creator = rrr_strdup(creator)) == NULL) {
		RRR_MSG_0("Could not allocate memory for creator in %s\n", __func__);
		ret = 1;
		goto out_free;
	}
	collection->queue = queue;

	rrr_socket_client_collection_set_connect_timeout (collection, RRR_SOCKET_CLIENT_COLLECTION_DEFAULT_CONNECT_TIMEOUT_S * 1000 * 1000);
	rrr_socket_client_collection_set_idle_timeout (collection, RRR_SOCKET_CLIENT_COLLECTION_DEFAULT_IDLE_TIMEOUT_S * 1000 * 1000);

	*target = collection;

	goto out;
	out_free:
		rrr_free(collection);
	out:
		return ret;
}

int rrr_socket_client_collection_new (
		struct rrr_socket_client_collection **target,
		struct rrr_event_queue *queue,
		const char *creator
) {
	return __rrr_socket_client_collection_new(target, queue, creator);
}

int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
) {
	return RRR_LL_COUNT(collection);
}

void rrr_socket_client_collection_send_chunk_iterate (
		struct rrr_socket_client_collection *collection,
		void (*callback)(int *do_remove, const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		rrr_socket_send_chunk_collection_iterate(&node->send_chunks, callback, callback_arg);
	RRR_LL_ITERATE_END();
}

static void __rrr_socket_client_read_callback_address_deduct (
		const struct sockaddr **result_addr,
		socklen_t *result_addr_len,
		const struct rrr_read_session *read_session,
		const struct rrr_socket_client *client
) {
	switch (client->create_type) {
		case RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_INBOUND:
		case RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND:
			*result_addr = (const struct sockaddr *) &client->connected_fd->addr;
			*result_addr_len = client->connected_fd->addr_len;
		       break;
		default:
		       *result_addr = (const struct sockaddr *) &read_session->src_addr;
		       *result_addr_len = read_session->src_addr_len;
	};
}

static void __rrr_socket_client_read_callback_flags_deduct (
		int *read_flags_socket,
		int *do_soft_error_propagates,
		const struct rrr_socket_client *client
) {
	const struct rrr_socket_client_collection *collection = client->collection;

	*read_flags_socket = client->collection->read_flags_socket;

	if (collection->callback_set_read_flags != NULL) {
		collection->callback_set_read_flags(read_flags_socket, do_soft_error_propagates, client->private_data, collection->callback_set_read_flags_arg);
	}
}

#define DEDUCT_ADDRESS()                            \
	const struct sockaddr *addr;                \
	socklen_t addr_len;                         \
	__rrr_socket_client_read_callback_address_deduct (&addr, &addr_len, read_session, client)

#define DEDUCT_READ_FLAGS()                         \
	int read_flags_socket = 0;                  \
	int do_soft_error_propagates = 1;           \
	__rrr_socket_client_read_callback_flags_deduct (&read_flags_socket, &do_soft_error_propagates, client);

#define ENFORCE_SOFT_ERROR_PROPAGATES()             \
	if (!do_soft_error_propagates) { RRR_BUG("BUG: Soft error propagation is implied in %s and must be set to 1\n", __func__); }

static int __rrr_socket_client_collection_read_raw_get_target_size_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	DEDUCT_ADDRESS();

	return collection->get_target_size (
			read_session,
			addr,
			addr_len,
			client->private_data,
			collection->get_target_size_arg
	);
}

static int __rrr_socket_client_collection_read_raw_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	DEDUCT_ADDRESS();

	return collection->complete_callback (
			read_session,
			addr,
			addr_len,
			client->private_data,
			collection->complete_callback_arg
	);
}

static void __rrr_socket_client_fd_event_timeout (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client_fd *client_fd = arg;

	(void)(flags);
	(void)(fd);

	RRR_DBG_7("Disconnecting fd %i in client collection following soft inactivity timeout of %" PRIu64 " ms\n",
			client_fd->fd, client_fd->client->collection->idle_timeout_us / 1000);

	__rrr_socket_client_collection_find_and_destroy (client_fd->client->collection, client_fd->client);
}

static int __rrr_socket_client_fd_event_setup (
		struct rrr_socket_client_fd *client_fd,
		void (*event_read_callback)(evutil_socket_t fd, short flags, void *arg),
		void *event_read_callback_arg,
		void (*event_write_callback)(evutil_socket_t fd, short flags, void *arg),
		void *event_write_callback_arg
) {
	int ret = 0;

	if (event_read_callback != NULL) {
		if ((ret = rrr_event_collection_push_read (
				&client_fd->event_read,
				&client_fd->events,
				client_fd->fd,
				event_read_callback,
				event_read_callback_arg,
				client_fd->client->collection->connect_timeout_us
		)) != 0) {
			RRR_MSG_0("Failed to create read event in %s\n", __func__);
			ret = 1;
			goto out;
		}

		EVENT_ADD(client_fd->event_read);
	}

	if (event_write_callback != NULL) {
		if ((ret = rrr_event_collection_push_write (
				&client_fd->event_write,
				&client_fd->events,
				client_fd->fd,
				event_write_callback,
				event_write_callback_arg,
				client_fd->client->collection->connect_timeout_us
		)) != 0) {
			RRR_MSG_0("Failed to create write event in %s\n", __func__);
			ret = 1;
			goto out;
		}

		EVENT_ADD(client_fd->event_write);
	}

	if ( client_fd->client->collection->idle_timeout_us > 0 &&
	     client_fd->client->create_type != RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN &&
	     client_fd->client->create_type != RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT
	) {
		if ((ret = rrr_event_collection_push_periodic (
				&client_fd->event_timeout,
				&client_fd->events,
				__rrr_socket_client_fd_event_timeout,
				client_fd,
				client_fd->client->collection->idle_timeout_us
		)) != 0) {
				RRR_MSG_0("Failed to create timeout event in %s\n", __func__);
				ret = 1;
				goto out;
		}

		// Don't add yet, for now only connect timeout applies
	}

	out:
	return ret;
}

static void __rrr_socket_client_return_value_process (
		struct rrr_socket_client_collection *collection,
		struct rrr_socket_client *client,
		int ret
) {
	uint64_t timeout = rrr_time_get_64() - (RRR_SOCKET_CLIENT_HARD_TIMEOUT_S * 1000 * 1000);

	if (ret == 0) {
		client->last_seen = rrr_time_get_64();
	}
	else if (ret == RRR_READ_INCOMPLETE || ret == RRR_SOCKET_NOT_READY) {
		if ((client->last_seen < timeout) &&
		    (client->create_type != RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT && client->create_type != RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN)
		) {
			RRR_DBG_7("Disconnecting fd %i in client collection following hard inactivity timeout\n", client->connected_fd->fd);
			ret = RRR_READ_EOF;
		}
		else {
			// OK, mask
			ret = 0;
		}
	}
	else if (ret == RRR_READ_EOF) {
		// OK, propagate
	}
	else if (ret == RRR_READ_SOFT_ERROR) {
		RRR_DBG_7("Disconnecting fd %i in client collection following soft error\n", client->connected_fd->fd);
		// Mask with EOF
		ret = RRR_READ_EOF;
	}
	else {
		// Hard errror propagates
	}

	if (ret != 0) {
		__rrr_socket_client_collection_find_and_destroy (collection, client);
		if (ret != RRR_READ_EOF) {
			rrr_event_dispatch_break(collection->queue);
		}
	}
}

static int __rrr_socket_client_collection_read_message_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

#if SSIZE_MAX > RRR_LENGTH_MAX
	if ((rrr_slength) read_session->rx_buf_wpos > (rrr_slength) RRR_LENGTH_MAX) {
		RRR_MSG_0("Message was too long in %s\n", __func__);
		return RRR_READ_SOFT_ERROR;
	}
#endif

	// Callbacks are allowed to set the pointer to NULL if they wish to take control of memory,
	// make sure no pointers to local variables are used but only the pointer to rx_buf_ptr

	return rrr_msg_to_host_and_verify_with_callback (
			(struct rrr_msg **) &read_session->rx_buf_ptr,
			(rrr_length) read_session->rx_buf_wpos,
			collection->callback_msg,
			collection->callback_addr_msg,
			collection->callback_log_msg,
			collection->callback_ctrl_msg,
			collection->callback_stats_msg,
			client->private_data,
			collection->callback_msg_arg
	);
}

static int __rrr_socket_client_connected_fd_ensure (
		struct rrr_socket_client *client,
		int fd,
		short flags
) {
	int ret = 0;

	if (flags & EV_TIMEOUT) {
		RRR_DBG_7("fd %i in client collection connect attempt timed out\n", fd);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out_destroy;
	}

	if ((ret = rrr_socket_send_check(fd)) == 0) {
		RRR_DBG_7("fd %i in client collection send check succeeded, choosing this fd.\n", fd);
		ret = __rrr_socket_client_connected_fd_finalize_and_create_private_data(client, fd);
		goto out;
	}
	else if (ret == RRR_SOCKET_NOT_READY) {
		RRR_DBG_7("fd %i in client collection not yet ready.\n", fd);
		goto out;
	}

	RRR_DBG_7("fd %i in client collection send check failed, return was %i. Closing.\n", fd, ret);

	out_destroy:
		__rrr_socket_client_fd_find_and_destroy(client->collection, client, fd);
	out:
		return ret;
}

#define CONNECTED_FD_ENSURE()                                                          \
	do {if (client->connected_fd == NULL) {                                        \
		if (__rrr_socket_client_connected_fd_ensure(client, fd, flags) != 0) { \
			return;                                                        \
		}                                                                      \
	}} while(0)

#define TIMEOUT_UPDATE()                                                                       \
	if (!(flags & EV_TIMEOUT) && EVENT_INITIALIZED(client->connected_fd->event_timeout)) { \
		EVENT_ADD(client->connected_fd->event_timeout);                                \
	}

static int __rrr_socket_client_send_tick (
		struct rrr_socket_client *client
) {
	int ret;

	if ((ret = rrr_socket_send_chunk_collection_send_and_notify (
			&client->send_chunks,
			client->connected_fd->fd,
			__rrr_socket_client_chunk_send_notify_success_callback,
			client
	)) != RRR_SOCKET_OK && ret != RRR_SOCKET_WRITE_INCOMPLETE) {
		RRR_DBG_7("Disconnecting fd %i in client collection following send error, return was %i\n",
				client->connected_fd->fd, ret);
	}

	return ret;
}

static void __rrr_socket_client_event_write (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	(void)(fd);
	(void)(flags);

	CONNECTED_FD_ENSURE();

	if (client->connected_fd == NULL) {
		RRR_BUG("BUG: Connected FD not set in %s\n", __func__);
	}
	if (client->connected_fd->fd != fd) {
		RRR_BUG("BUG: FD mismatch in %s\n", __func__);
	}

	if (rrr_socket_send_chunk_collection_count(&client->send_chunks) > 0) {
		TIMEOUT_UPDATE();
	}

	int ret_tmp = __rrr_socket_client_send_tick (client);

	if (ret_tmp != 0 && ret_tmp != RRR_SOCKET_WRITE_INCOMPLETE) {
		// Do nothing more, also not on hard errors
		goto destroy;
	}

	if (rrr_socket_send_chunk_collection_count(&client->send_chunks) == 0) {
		EVENT_REMOVE(client->connected_fd->event_write);
		if (client->close_when_send_complete) {
			RRR_DBG_7("Disconnecting fd %i in client collection as close when send complete is set and send buffer is empty\n",
					client->connected_fd->fd);
			goto destroy;
		}
	}

	return;

	destroy:
	__rrr_socket_client_collection_find_and_destroy (collection, client);
	return;
}

static void __rrr_socket_client_event_message_error_callback (
		struct rrr_read_session *read_session,
		int is_hard_err,
		void *arg
) {
	struct rrr_socket_client *client = arg;

	(void)(read_session);
	(void)(is_hard_err);
	(void)(client);

	// Any error message goes here
}

static void __rrr_socket_client_event_read_message (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	(void)(fd);
	(void)(flags);

	CONNECTED_FD_ENSURE();
	TIMEOUT_UPDATE();
	DEDUCT_READ_FLAGS();
	ENFORCE_SOFT_ERROR_PROPAGATES();

	uint64_t bytes_read = 0;

	__rrr_socket_client_return_value_process (
		collection,
		client,
		rrr_socket_read_message_default (
				&bytes_read,
				&client->read_sessions,
				fd,
				sizeof(struct rrr_msg),
				collection->read_step_max_size,
				0, // No max size
				read_flags_socket,
				0, // No ratelimit interval
				0, // No ratelimit max bytes
				rrr_read_common_get_session_target_length_from_message_and_checksum,
				NULL,
				__rrr_socket_client_event_message_error_callback,
				client,
				__rrr_socket_client_collection_read_message_complete_callback,
				client
		)
	);
}

static void __rrr_socket_client_event_read_error_callback (
		struct rrr_read_session *read_session,
		int is_hard_err,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	DEDUCT_ADDRESS();

	if (collection->error_callback == NULL)
		return;

	collection->error_callback(
			read_session,
			addr,
			addr_len,
			is_hard_err,
			client->private_data,
			collection->error_callback_arg
	);
}

static void __rrr_socket_client_event_read_raw (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	(void)(fd);
	(void)(flags);

	CONNECTED_FD_ENSURE();
	TIMEOUT_UPDATE();
	DEDUCT_READ_FLAGS();
	ENFORCE_SOFT_ERROR_PROPAGATES();

	uint64_t bytes_read = 0;

	__rrr_socket_client_return_value_process (
		collection,
		client,
		rrr_socket_read_message_default (
				&bytes_read,
				&client->read_sessions,
				fd,
				4096,
				collection->read_step_max_size,
				0, // No max size
				read_flags_socket,
				0, // No ratelimit interval
				0, // No ratelimit max bytes
				__rrr_socket_client_collection_read_raw_get_target_size_callback,
				client,
				__rrr_socket_client_event_read_error_callback,
				client,
				__rrr_socket_client_collection_read_raw_complete_callback,
				client
		)
	);
}

static int __rrr_socket_client_event_read_array_tree_callback (
		struct rrr_read_session *read_session,
		struct rrr_array *array_final,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	DEDUCT_ADDRESS();

	return collection->array_callback (
			read_session,
			addr,
			addr_len,
			array_final,
			client->private_data,
			collection->array_callback_arg
	);
}

static void __rrr_socket_client_event_read_array_tree (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	(void)(fd);
	(void)(flags);

	CONNECTED_FD_ENSURE();
	TIMEOUT_UPDATE();
	DEDUCT_READ_FLAGS();

	uint64_t bytes_read = 0;

	struct rrr_array array_tmp = {0};
	int ret = rrr_socket_common_receive_array_tree (
		&bytes_read,
		&client->read_sessions,
		fd,
		read_flags_socket,
		&array_tmp,
		collection->array_tree,
		collection->array_do_sync_byte_by_byte,
		collection->read_step_max_size,
		0, // No ratelimit interval
		0, // No ratelimit max bytes
		collection->array_message_max_size,
		__rrr_socket_client_event_read_array_tree_callback,
		__rrr_socket_client_event_read_error_callback,
		client
	);

	// Prevent connection closure upon parse errors. Read session is still cleared by read framework,
	// and parsing commenses when more data is avilable. For files with finite size, soft error should
	// propagate instead to force closure.
	if (ret == RRR_READ_SOFT_ERROR && do_soft_error_propagates) {
		// Propagate return value
		RRR_DBG_7("fd %i in client collection soft error while reading (propagate)\n", fd);
	}
	else {
		// Ignore any soft error
		ret &= ~(RRR_READ_SOFT_ERROR);
		RRR_DBG_7("fd %i in client collection soft error while reading (ignore)\n", fd);
	}

	__rrr_socket_client_return_value_process (
		collection,
		client,
		ret
	);

	rrr_array_clear(&array_tmp);
}

static void __rrr_socket_client_event_read_ignore (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	(void)(fd);
	(void)(flags);

	CONNECTED_FD_ENSURE();
	TIMEOUT_UPDATE();
	DEDUCT_READ_FLAGS();

	char buf[1024];
	rrr_biglength read_bytes = 0;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	__rrr_socket_client_return_value_process (
			collection,
			client,
			rrr_socket_read (
					buf,
					&read_bytes,
					fd,
					sizeof(buf),
					(struct sockaddr *) &addr,
					&addr_len,
					read_flags_socket
			)
	);

	if (read_bytes > 0) {
		RRR_DBG_7("fd %i in client collection, ignoring %lli received bytes\n",
				client->connected_fd->fd, (long long int) read_bytes);
	}
}

static int __rrr_socket_client_fd_reset (
		struct rrr_socket_client_fd *client_fd,
		void (*event_read_callback)(evutil_socket_t fd, short flags, void *arg),
		void (*event_write_callback)(evutil_socket_t fd, short flags, void *arg)
) {
	rrr_event_collection_clear_soft(&client_fd->events);
	return __rrr_socket_client_fd_event_setup (
			client_fd,
			event_read_callback,
			client_fd->client,
			event_write_callback,
			client_fd->client
	);
}

static int __rrr_socket_client_fd_push (
		struct rrr_socket_client *client,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const char *addr_string,
		void (*event_read_callback)(evutil_socket_t fd, short flags, void *arg),
		void (*event_write_callback)(evutil_socket_t fd, short flags, void *arg)
) {
	int ret = 0;

	struct rrr_socket_client_fd *client_fd = NULL;

	if ((ret = __rrr_socket_client_fd_new (
			&client_fd,
			client,
			client->collection->queue,
			fd,
			addr,
			addr_len,
			addr_string
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_socket_client_fd_event_setup (
			client_fd,
			event_read_callback,
			client,
			event_write_callback,
			client
	)) != 0) {
		goto out_destroy_client_fd;
	}

	RRR_LL_PUSH(client, client_fd);

	goto out;
	out_destroy_client_fd:
		__rrr_socket_client_fd_destroy(client_fd);
	out:
		return ret;
}

static int __rrr_socket_client_collection_fd_push (
		struct rrr_socket_client **result,
		struct rrr_socket_client_collection *collection,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const char *addr_string,
		enum rrr_socket_client_collection_create_type create_type,
		void (*event_read_callback)(evutil_socket_t fd, short flags, void *arg),
		void (*event_write_callback)(evutil_socket_t fd, short flags, void *arg)
) {
	int ret = 0;

	struct rrr_socket_client *client_new = NULL;

	if ((ret = __rrr_socket_client_new_and_add (
			&client_new,
			collection,
			create_type
	)) != 0) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		goto out;
	}

	if ((ret = __rrr_socket_client_fd_push (
			client_new,
			fd,
			addr,
			addr_len,
			addr_string,
			event_read_callback,
			event_write_callback
	)) != 0) {
		goto out;
	}

	RRR_DBG_7("fd %i added to client collection (not yet ready)\n", fd);

	*result = client_new;
	client_new = NULL;

	out:
	if (client_new != NULL) {
		__rrr_socket_client_collection_find_and_destroy(collection, client_new);
	}
	return ret;
}

#define CONNECTED_CALLBACKS               \
	collection->event_read_callback,  \
	__rrr_socket_client_event_write

static int __rrr_socket_client_reset (
		struct rrr_socket_client *client,
		struct rrr_socket_client_collection *collection
) {
	int ret = 0;

	client->collection = collection;

	RRR_LL_ITERATE_BEGIN(client, struct rrr_socket_client_fd);
		if ((ret = __rrr_socket_client_fd_reset (
				node,
				CONNECTED_CALLBACKS
		)) != 0) {
			goto out;
		}
				
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_socket_client_collection_not_ready_fd_push (
		struct rrr_socket_client **result,
		struct rrr_socket_client_collection *collection,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const char *addr_string,
		enum rrr_socket_client_collection_create_type create_type
) {
	return __rrr_socket_client_collection_fd_push (
			result,
			collection,
			fd,
			addr,
			addr_len,
			addr_string,
			create_type,
			CONNECTED_CALLBACKS
	);
}

static int __rrr_socket_client_not_ready_fd_push (
		struct rrr_socket_client *client,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const char *addr_string
) {
	struct rrr_socket_client_collection *collection = client->collection;

	return __rrr_socket_client_fd_push (
			client,
			fd,
			addr,
			addr_len,
			addr_string,
			CONNECTED_CALLBACKS
	);
}

static int __rrr_socket_client_collection_connected_fd_push (
		struct rrr_socket_client **result,
		struct rrr_socket_client_collection *collection,
		int connected_fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const char *addr_string,
		enum rrr_socket_client_collection_create_type create_type
) {
	int ret = 0;

	struct rrr_socket_client *client_new = NULL;

	if ((ret = __rrr_socket_client_collection_not_ready_fd_push (
			&client_new,
			collection,
			connected_fd,
			addr,
			addr_len,
			addr_string,
			create_type
	)) != 0) {
		goto out;
	}

	RRR_DBG_7("fd %i finalize connected (direct add)\n", connected_fd);

	if ((ret = __rrr_socket_client_connected_fd_finalize_and_create_private_data(client_new, connected_fd)) != 0) {
		goto out;
	}

	*result = client_new;
	client_new = NULL;

	out:
	if (client_new != NULL) {
		__rrr_socket_client_collection_find_and_destroy(collection, client_new);
	}
	return ret;
}

static int __rrr_socket_client_send_push_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_client *client,
		void **data,
		rrr_biglength data_size,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	int ret = 0;

	if (client->create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN) {
		RRR_BUG("BUG: Attempted to push data to listening socket in %s\n", __func__);
	}

	if ((ret = rrr_socket_send_chunk_collection_push_with_private_data (
			send_chunk_count,
			&client->send_chunks,
			data,
			data_size,
			RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL,
			private_data_new,
			private_data_arg,
			private_data_destroy
	)) != 0) {
		goto out;
	}

	__rrr_socket_client_send_push_notify(client);

	out:
	return ret;
}

static int __rrr_socket_client_send_push (
		rrr_length *send_chunk_count,
		struct rrr_socket_client *client,
		void **data,
		rrr_biglength data_size
) {
	return __rrr_socket_client_send_push_with_private_data (
			send_chunk_count,
			client,
			data,
			data_size,
			NULL,
			NULL,
			NULL
	);
}

static int __rrr_socket_client_send_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_client *client,
		const void *data,
		rrr_biglength data_size
) {
	int ret = 0;

	if (client->create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN) {
		RRR_BUG("BUG: Attempted to push data to listening socket in %s\n", __func__);
	}

	if ((ret = rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			&client->send_chunks,
			data,
			data_size,
			RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL
	)) != 0) {
		goto out;
	}

	__rrr_socket_client_send_push_notify(client);

	out:
	return ret;
}

static int __rrr_socket_client_send_push_const_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_client *client,
		const void *data,
		rrr_biglength data_size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
) {
	int ret = 0;

	if (client->create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN) {
		RRR_BUG("BUG: Attempted to push data to listening socket in %s\n", __func__);
	}

	if ((ret = rrr_socket_send_chunk_collection_push_const_with_private_data (
			send_chunk_count,
			&client->send_chunks,
			data,
			data_size,
			RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy
	)) != 0) {
		goto out;
	}

	__rrr_socket_client_send_push_notify(client);

	out:
	return ret;
}

static int __rrr_socket_client_sendto_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_client *client,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength data_size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
) {
	int ret = 0;

	if (client->create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN) {
		RRR_BUG("BUG: Attempted to push data to listening socket in %s\n", __func__);
	}

	if ((ret = rrr_socket_send_chunk_collection_push_const_with_address_and_private_data (
			send_chunk_count,
			&client->send_chunks,
			addr,
			addr_len,
			data,
			data_size,
			RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy
	)) != 0) {
		goto out;
	}

	__rrr_socket_client_send_push_notify(client);

	out:
	return ret;
}

static void __rrr_socket_client_close_when_send_complete (
		struct rrr_socket_client *client
) {
	if (client->close_when_send_complete) {
		return;
	}

	if (client->connected_fd != NULL) {
		RRR_DBG_7("fd %i in client collection close when send complete set, close is now pending\n",
				client->connected_fd->fd);
	}
	else {
		RRR_DBG_7("fd (not ready) in client collection close when send complete set, close is now pending\n");
	}

	client->close_when_send_complete = 1;

	__rrr_socket_client_send_push_notify(client);
}

void rrr_socket_client_collection_close_outbound_when_send_complete (
		struct rrr_socket_client_collection *collection
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if (node->create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND) {
			__rrr_socket_client_close_when_send_complete(node);
		}
	RRR_LL_ITERATE_END();
}

void rrr_socket_client_collection_send_push_const_multicast (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const void *data,
		rrr_biglength size,
		rrr_length send_chunk_limit
) {
	*send_chunk_count = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if (node->create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN) {
			RRR_LL_ITERATE_NEXT();
		}

		rrr_length count_tmp = 0;
		int ret_tmp;
		if ((ret_tmp = __rrr_socket_client_send_push_const (&count_tmp, node, data, size)) != 0) {
			RRR_DBG_7("Send failed with return value %i during multicast send, destroying client\n", ret_tmp);
			RRR_LL_ITERATE_SET_DESTROY();
		}

		if (count_tmp > send_chunk_limit) {
			RRR_MSG_0("Send chunk limit reach for fd %i in client collection multicast send (%i>%i), closing connection.\n",
					node->connected_fd->fd, count_tmp, send_chunk_limit);
			RRR_LL_ITERATE_SET_DESTROY();
		}

		*send_chunk_count += count_tmp;
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy_dangerous(node));
}

#define FIND_LOOP_BEGIN()                                                 \
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);       \
		if (node->close_when_send_complete) {                     \
			RRR_LL_ITERATE_NEXT();                            \
		}                                                         \
		struct rrr_socket_client *client = node;                  \
		RRR_LL_ITERATE_BEGIN(client, struct rrr_socket_client_fd)

#define FIND_LOOP_END()                                                   \
		RRR_LL_ITERATE_END();                                     \
	RRR_LL_ITERATE_END()

static struct rrr_socket_client *__rrr_socket_client_collection_find_by_address (
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	FIND_LOOP_BEGIN();
		if (node->addr_len == addr_len && memcmp(&node->addr, addr, addr_len) == 0) {
			return client;
		}
	FIND_LOOP_END();
	return NULL;
}

static struct rrr_socket_client *__rrr_socket_client_collection_find_by_address_string (
		struct rrr_socket_client_collection *collection,
		const char *addr_string
) {
	FIND_LOOP_BEGIN();
		if (node->addr_string != NULL && strcmp(node->addr_string, addr_string) == 0) {
			return client;
		}
	FIND_LOOP_END();
	return NULL;
}

static struct rrr_socket_client *__rrr_socket_client_collection_find_by_fd (
		struct rrr_socket_client_collection *collection,
		int fd
) {
	FIND_LOOP_BEGIN();
		if (node->fd == fd) {
			return client;
		}
	FIND_LOOP_END();
	return NULL;
}

int rrr_socket_client_collection_send_push (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		rrr_biglength data_size
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(collection, fd);

	if (client == NULL) {
		return RRR_READ_SOFT_ERROR;
	}

	return __rrr_socket_client_send_push (
			send_chunk_count,
			client,
			data,
			data_size
	);
}

int rrr_socket_client_collection_send_push_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		rrr_biglength data_size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(collection, fd);

	if (client == NULL) {
		return RRR_READ_SOFT_ERROR;
	}

	return __rrr_socket_client_send_push_with_private_data (
			send_chunk_count,
			client,
			data,
			data_size,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy
	);
}

int rrr_socket_client_collection_send_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		const void *data,
		rrr_biglength data_size
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(collection, fd);

	if (client == NULL) {
		return RRR_READ_SOFT_ERROR;
	}

	return __rrr_socket_client_send_push_const (
			send_chunk_count,
			client,
			data,
			data_size
	);
}

void rrr_socket_client_collection_close_when_send_complete_by_address (
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_address(collection, addr, addr_len);

	if (client != NULL) {
		__rrr_socket_client_close_when_send_complete (client);
	}
}

void rrr_socket_client_collection_close_when_send_complete_by_address_string (
		struct rrr_socket_client_collection *collection,
		const char *addr_string
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_address_string(collection, addr_string);

	if (client != NULL) {
		__rrr_socket_client_close_when_send_complete (client);
	}
}

void rrr_socket_client_collection_close_when_send_complete_by_fd (
		struct rrr_socket_client_collection *collection,
		int fd
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(collection, fd);

	if (client != NULL) {
		__rrr_socket_client_close_when_send_complete (client);
	}
}

int rrr_socket_client_collection_migrate_by_fd (
		struct rrr_socket_client_collection *target,
		struct rrr_socket_client_collection *source,
		int fd
) {
	int ret = 0;

	assert(target != source);

	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(source, fd);

	if (client == NULL) {
		goto out;
	}

	RRR_DBG_7("fd %i in client collection migrating to other collection\n",
			client->connected_fd->fd);

	int found = 0;
	RRR_LL_ITERATE_BEGIN(source, struct rrr_socket_client);
		if (node == client) {
			found = 1;
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(source, 0);
	assert(found == 1);

	if ((ret = __rrr_socket_client_reset (client, target)) != 0) {
		__rrr_socket_client_destroy_dangerous(client);
		goto out;
	}

	RRR_LL_APPEND(target, client);

	out:
	return ret;
}

void rrr_socket_client_collection_close_by_fd (
		struct rrr_socket_client_collection *collection,
		int fd
) {
	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(collection, fd);

	if (client == NULL) {
		return;
	}

	RRR_DBG_7("fd %i in client collection close now (external call)\n",
			client->connected_fd->fd);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if (node == client) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy_dangerous(node));
}

int rrr_socket_client_collection_has_fd (
		struct rrr_socket_client_collection *collection,
		int fd
) {
	return __rrr_socket_client_collection_find_by_fd(collection, fd) != NULL;
}

static int __rrr_socket_client_collection_find_by_address_or_connect (
		struct rrr_socket_client **result,
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len,
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
) {
	int ret = 0;

	*result = NULL;

	int tmp_fd = -1;

	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_address(collection, addr, addr_len);

	if (client == NULL) {
		if ((ret = connect_callback (&tmp_fd, addr, addr_len, connect_callback_data)) != 0) {
			goto out;
		}

		if (tmp_fd < 0) {
			RRR_BUG("BUG: FD not set after connect callback in %s\n", __func__);
		}

		if ((ret = __rrr_socket_client_collection_not_ready_fd_push (
				&client, 
				collection, 
				tmp_fd, 
				addr,
				addr_len, 
				NULL,
				RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND
		)) != 0) {
			RRR_MSG_0("Failed to push new connection in %s\n", __func__);
			goto out_close;
		}
	}

	*result = client;

	goto out;
	out_close:
		rrr_socket_close(tmp_fd);
	out:
		return ret;
}

int rrr_socket_client_collection_send_push_const_by_address_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
) {
	int ret = 0;

	struct rrr_socket_client *client = NULL;

	if ((ret = __rrr_socket_client_collection_find_by_address_or_connect (&client, collection, addr, addr_len, connect_callback, connect_callback_data)) != 0)  {
		goto out;
	}

	if ((ret = __rrr_socket_client_send_push_const_with_private_data (
			send_chunk_count,
			client,
			data,
			size,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_socket_client_collection_find_by_address_string_or_connect (
		struct rrr_socket_client **result,
		struct rrr_socket_client_collection *collection,
		const char *addr_string,
		int (*resolve_callback)(
				size_t *address_count,
				struct sockaddr ***addresses,
				socklen_t **address_lengths,
				void *callback_data
		),
		void *resolve_callback_data,
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
) {
	int ret = 0;

	size_t address_count = 0;
	struct sockaddr **addresses = NULL;
	socklen_t *address_lengths = NULL;

	*result = NULL;

	int tmp_fd = -1;

	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_address_string(collection, addr_string);

	if (client != NULL) {
		goto found;
	}

	if ((ret = resolve_callback (
			&address_count,
			&addresses,
			&address_lengths,
			resolve_callback_data
	)) != 0) {
		goto out;
	}

	if (address_count == 0) {
		RRR_BUG("BUG: address count was zero after resolve callback in %s, callback must return error\n", __func__);
	}

	if ((ret = __rrr_socket_client_new_and_add (
			&client,
			collection,
			RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND
	)) != 0) {
		RRR_MSG_0("Could not create client in %s\n", __func__);
		goto out;
	}

	for (size_t i = 0; i < address_count; i++) {
		if ((ret = connect_callback (&tmp_fd, addresses[i], address_lengths[i], connect_callback_data)) == 0) {
			if (tmp_fd < 0) {
				RRR_BUG("BUG: FD not set after connect callback in %s\n", __func__);
			}

			RRR_DBG_7("client collection connect to '%s' suggestion %llu/%llu now pending\n",
					addr_string, (long long unsigned int) i + 1, (long long unsigned int) address_count);

			if ((ret = __rrr_socket_client_not_ready_fd_push (
					client,
					tmp_fd, 
					addresses[i], 
					address_lengths[i],
					addr_string
			)) != 0) {
				RRR_MSG_0("Failed to push new connection in %s\n", __func__);
				goto out;
			}
			tmp_fd = -1;
		}
		else {
			RRR_DBG_7("client collection connect to '%s' suggestion %llu/%llu failed\n",
					addr_string, (long long unsigned int) i + 1, (long long unsigned int) address_count);
		}
	}

	if (RRR_LL_COUNT(client) == 0) {
		RRR_DBG_7("client collection connect to '%s' failed, no suggestions succeeded\n", addr_string);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	found:
	*result = client;
	client = NULL;

	goto out;
	out:
	if (tmp_fd != -1) {
		rrr_socket_close(tmp_fd);
	}
	for (size_t i = 0; i < address_count; i++) {
		rrr_free(addresses[i]);
	}
	RRR_FREE_IF_NOT_NULL(addresses);
	RRR_FREE_IF_NOT_NULL(address_lengths);
	if (client != NULL) {
		__rrr_socket_client_collection_find_and_destroy(collection, client);
	}
	return ret;
}

int rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const char *addr_string,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*resolve_callback)(
				size_t *address_count,
				struct sockaddr ***addresses,
				socklen_t **address_lengths,
				void *callback_data
		),
		void *resolve_callback_data,
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
) {
	int ret = 0;

	struct rrr_socket_client *client = NULL;

	if ((ret = __rrr_socket_client_collection_find_by_address_string_or_connect (
			&client,
			collection,
			addr_string,
			resolve_callback,
			resolve_callback_data,
			connect_callback,
			connect_callback_data
	)) != 0)  {
		goto out;
	}

	if ((ret = __rrr_socket_client_send_push_const_with_private_data (
			send_chunk_count,
			client,
			data,
			size,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_socket_client_collection_sendto_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
) {
	int ret = 0;

	struct rrr_socket_client *client = NULL;

	if ((client = __rrr_socket_client_collection_find_by_fd (collection, fd)) == NULL)  {
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	if ((ret = __rrr_socket_client_sendto_push_const (
			send_chunk_count,
			client,
			addr,
			addr_len,
			data,
			size,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}


static void __rrr_socket_client_event_accept (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;
	struct rrr_socket_client_collection *collection = client->collection;

	(void)(flags);

	int ret_tmp = 0;

	struct sockaddr_storage addr = {0};
	socklen_t addr_len = sizeof(addr);

	ret_tmp = rrr_socket_accept(fd, (struct sockaddr *) &addr, &addr_len, collection->creator);
	if (ret_tmp == -1) {
		if (errno != EWOULDBLOCK) {
			RRR_MSG_0("Error while accepting connection in %s: %s\n", __func__, rrr_strerror(errno));
			ret_tmp = 1;
			goto out;
		}
		ret_tmp = 0;
		goto out;
	}

	int connected_fd = ret_tmp;

	struct rrr_socket_client *client_new = NULL;
	if ((ret_tmp = __rrr_socket_client_collection_connected_fd_push (
			&client_new,
			collection,
			connected_fd,
			(const struct sockaddr *) &addr,
			addr_len,
			NULL,
			RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_INBOUND
	)) != 0) {
		goto out;
	}

	if (collection->accept_callback != NULL) {
		if ((ret_tmp = collection->accept_callback((const struct sockaddr *) &addr, addr_len, client_new->private_data, collection->accept_callback_arg)) != 0) {
			RRR_MSG_0("Error %i from accept callback in %s\n", ret_tmp, __func__);
			goto out;
		}
	}

	out:
	if (ret_tmp != 0) {
		rrr_event_dispatch_break(collection->queue);
	}
}

int rrr_socket_client_collection_listen_fd_push (
		struct rrr_socket_client_collection *collection,
		int fd
) {
	int ret = 0;

	struct rrr_socket_client *client_new = NULL;

	if ((ret = __rrr_socket_client_collection_fd_push (
			&client_new,
			collection,
			fd,
			NULL,
			0,
			NULL,
			RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN,
			__rrr_socket_client_event_accept,
			NULL
	)) != 0) {
		goto out;
	}

	RRR_DBG_7("fd %i added to client collection (accepting)\n", fd);

	out:
	return ret;
}

static void __rrr_socket_client_collection_event_setup (
		struct rrr_socket_client_collection *collection,
		rrr_biglength read_step_max_size,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		void (*event_read_callback)(evutil_socket_t fd, short flags, void *arg),
		int  (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg
) {
	__rrr_socket_client_collection_clear(collection);

	collection->read_step_max_size = read_step_max_size;
	collection->read_flags_socket = read_flags_socket;

	collection->event_read_callback = event_read_callback;

	collection->callback_private_data_new = callback_private_data_new;
	collection->callback_private_data_destroy = callback_private_data_destroy;
	collection->callback_private_data_arg = callback_private_data_arg;
	collection->callback_set_read_flags = callback_set_read_flags;
	collection->callback_set_read_flags_arg = callback_set_read_flags_arg;
}

int rrr_socket_client_collection_connected_fd_push (
		struct rrr_socket_client_collection *collection,
		int fd,
		enum rrr_socket_client_collection_create_type create_type
) {
	struct rrr_socket_client *client_dummy = NULL;
	return __rrr_socket_client_collection_connected_fd_push (
			&client_dummy,
			collection,
			fd,
			NULL,
			0,
			NULL,
			create_type
	);
}

void rrr_socket_client_collection_send_notify_setup (
		struct rrr_socket_client_collection *collection,
		void (*callback)(RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS),
		void *callback_arg
) {
	collection->chunk_send_notify_callback = callback;
	collection->chunk_send_notify_callback_arg = callback_arg;
}

void rrr_socket_client_collection_fd_close_notify_setup (
		struct rrr_socket_client_collection *collection,
		void (*callback)(RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS),
		void *callback_arg
) {
	collection->client_fd_close_callback = callback;
	collection->client_fd_close_callback_arg = callback_arg;
}

void rrr_socket_client_collection_event_setup (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		rrr_biglength read_step_max_size,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
) {
	collection->callback_msg = callback_msg;
	collection->callback_addr_msg = callback_addr_msg;
	collection->callback_log_msg = callback_log_msg;
	collection->callback_ctrl_msg = callback_ctrl_msg;
	collection->callback_stats_msg = callback_stats_msg;
	collection->callback_msg_arg = callback_arg;

	__rrr_socket_client_collection_event_setup (
			collection,
			read_step_max_size,
			read_flags_socket,
			callback_set_read_flags,
			callback_set_read_flags_arg,
			__rrr_socket_client_event_read_message,
			callback_private_data_new,
			callback_private_data_destroy,
			callback_private_data_arg
	);
}

void rrr_socket_client_collection_event_setup_raw (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		rrr_biglength read_step_max_size,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		int (*get_target_size)(RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS),
		void *get_target_size_arg,
		void (*error_callback)(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS),
		void *error_callback_arg,
		int (*complete_callback)(RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS),
		void *complete_callback_arg
) {
	collection->get_target_size = get_target_size;
	collection->get_target_size_arg = get_target_size_arg;

	collection->error_callback = error_callback;
	collection->error_callback_arg = error_callback_arg;

	collection->complete_callback = complete_callback;
	collection->complete_callback_arg = complete_callback_arg;

	__rrr_socket_client_collection_event_setup (
			collection,
			read_step_max_size,
			read_flags_socket,
			callback_set_read_flags,
			callback_set_read_flags_arg,
			__rrr_socket_client_event_read_raw,
			callback_private_data_new,
			callback_private_data_destroy,
			callback_private_data_arg
	);
}

void rrr_socket_client_collection_event_setup_array_tree (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		const struct rrr_array_tree *tree,
		int do_sync_byte_by_byte,
		rrr_biglength read_step_max_size,
		unsigned int message_max_size,
		int (*array_callback)(RRR_SOCKET_CLIENT_ARRAY_CALLBACK_ARGS),
		void *array_callback_arg,
		void (*error_callback)(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS),
		void *error_callback_arg,
		int (*accept_callback)(RRR_SOCKET_CLIENT_ACCEPT_CALLBACK_ARGS),
		void *accept_callback_arg
) {
	collection->array_do_sync_byte_by_byte = do_sync_byte_by_byte;
	collection->array_message_max_size = message_max_size;
	collection->array_tree = tree;

	collection->array_callback = array_callback;
	collection->array_callback_arg = array_callback_arg;

	collection->error_callback = error_callback;
	collection->error_callback_arg = error_callback_arg;

	collection->accept_callback = accept_callback;
	collection->accept_callback_arg = accept_callback_arg;

	__rrr_socket_client_collection_event_setup (
			collection,
			read_step_max_size,
			read_flags_socket,
			callback_set_read_flags,
			callback_set_read_flags_arg,
			__rrr_socket_client_event_read_array_tree,
			callback_private_data_new,
			callback_private_data_destroy,
			callback_private_data_arg
	);
}

void rrr_socket_client_collection_event_setup_ignore (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg
) {
	__rrr_socket_client_collection_event_setup (
			collection,
			0,
			read_flags_socket,
			callback_set_read_flags,
			callback_set_read_flags_arg,
			__rrr_socket_client_event_read_ignore,
			callback_private_data_new,
			callback_private_data_destroy,
			callback_private_data_arg
	);
}

void rrr_socket_client_collection_event_setup_write_only (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg
) {
	__rrr_socket_client_collection_event_setup (
			collection,
			0,
			0,
			NULL,
			NULL,
			NULL,
			callback_private_data_new,
			callback_private_data_destroy,
			callback_private_data_arg
	);
}
