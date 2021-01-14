/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "rrr_socket.h"
#include "rrr_socket_client.h"
#include "rrr_socket_read.h"
#include "rrr_socket_constants.h"

#include "../rrr_strerror.h"
#include "../log.h"
#include "../read.h"
#include "../util/posix.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../util/macro_utils.h"

static int __rrr_socket_client_destroy (
		struct rrr_socket_client *client
) {
	if (client->connected_fd > 0) {
		rrr_socket_close(client->connected_fd);
	}
	rrr_read_session_collection_clear(&client->read_sessions);
	if (client->private_data != NULL) {
		client->private_data_destroy(client->private_data);
	}
	free(client);
	return 0;
}

static int __rrr_socket_client_new (
		struct rrr_socket_client **result,
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len,
		int (*private_data_new)(void **target, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
) {
	int ret = 0;

	*result = NULL;

	struct rrr_socket_client *client = malloc (sizeof(*client));
	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_client_new\n");
		ret = 1;
		goto out;
	}

	memset(client, '\0', sizeof(*client));

	if (addr_len > sizeof(client->addr)) {
		RRR_BUG("Address length too long in __rrr_socket_client_new\n");
	}

	client->connected_fd = fd;
	memcpy (&client->addr, addr, addr_len);
	client->addr_len = addr_len;
	client->last_seen = rrr_time_get_64();

	if (private_data_new != NULL) {
		if (private_data_destroy == NULL) {
			RRR_BUG("BUG: A new function was defined but no destroy function in __rrr_socket_client_new\n");
		}

		if ((ret = private_data_new(&client->private_data, private_arg)) != 0) {
			RRR_MSG_0("Error while initializing private data in __rrr_socket_client_new\n");
			ret = 1;
			goto out_free;
		}

		client->private_data_destroy = private_data_destroy;
	}
	else if (private_data_destroy != NULL) {
		RRR_BUG("BUG: A destroy function was defined but no new function in __rrr_socket_client_new\n");
	}

	*result = client;
	goto out;

	out_free:
		free (client);
	out:
		return ret;
}

void rrr_socket_client_collection_clear (
		struct rrr_socket_client_collection *collection
) {
	RRR_LL_DESTROY(collection,struct rrr_socket_client,__rrr_socket_client_destroy(node));
	RRR_FREE_IF_NOT_NULL(collection->creator);
	collection->listen_fd = 0;
}

int rrr_socket_client_collection_init (
		struct rrr_socket_client_collection *collection,
		int listen_fd,
		const char *creator
) {
	memset(collection, '\0', sizeof(*collection));
	collection->creator = strdup(creator);
	if (collection->creator == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_socket_client_collection_init\n");
		return 1;
	}
	collection->listen_fd = listen_fd;
	return 0;
}

int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
) {
	return RRR_LL_COUNT(collection);
}

int rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection,
		int (*private_data_new)(void **target, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
) {
	struct rrr_socket_client temp = {0};
	temp.addr_len = sizeof(temp.addr);

	int ret = rrr_socket_accept(collection->listen_fd, (struct sockaddr *) &temp.addr, &temp.addr_len, collection->creator);
	if (ret == -1) {
		if (errno != EWOULDBLOCK) {
			RRR_MSG_0("Error while accepting connection in rrr_socket_client_collection_accept: %s\n", rrr_strerror(errno));
			return 1;
		}
		return 0;
	}

	temp.connected_fd = ret;

	struct rrr_socket_client *client_new = NULL;
	if (__rrr_socket_client_new (
			&client_new,
			temp.connected_fd,
			(struct sockaddr *) &temp.addr,
			temp.addr_len,
			private_data_new,
			private_arg,
			private_data_destroy
	) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_socket_client_collection_accept\n");
		return 1;
	}

	RRR_DBG_1("Client connection accepted into collection with fd %i\n", temp.connected_fd);

	RRR_LL_UNSHIFT(collection, client_new);

	return 0;
}

int rrr_socket_client_collection_accept_simple (
		struct rrr_socket_client_collection *collection
) {
	return rrr_socket_client_collection_accept (collection, NULL, NULL, NULL);
}

int rrr_socket_client_collection_multicast_send_ignore_full_pipe (
		struct rrr_socket_client_collection *collection,
		void *data,
		size_t size
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		RRR_DBG_3("TX to fd %i\n", node->connected_fd);
		ssize_t written_bytes_dummy = 0;
		if ((ret = rrr_socket_send_nonblock_check_retry(&written_bytes_dummy, node->connected_fd, data, size)) != 0) {
			if (ret != RRR_SOCKET_WRITE_INCOMPLETE) {
				// TODO : This error message is useless because we don't know which client has disconnected
				RRR_DBG_1("Disconnecting client in client collection following send error\n");
				RRR_LL_ITERATE_SET_DESTROY();
			}
			ret = 0;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy(node));

	return ret;
}

// TODO : Add disconnect notification callback for debug purposes

int rrr_socket_client_collection_read (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags_socket,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;
	uint64_t time_now = rrr_time_get_64();
	uint64_t timeout = rrr_time_get_64() - (RRR_SOCKET_CLIENT_TIMEOUT_S * 1000 * 1000);

	if (RRR_LL_COUNT(collection) == 0 && (read_flags_socket & RRR_SOCKET_READ_USE_TIMEOUT) != 0) {
		rrr_posix_usleep(10 * 1000);
	}

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		uint64_t bytes_read = 0;
		ret = rrr_socket_read_message_default (
				&bytes_read,
				&node->read_sessions,
				node->connected_fd,
				read_step_initial,
				read_step_max_size,
				0, // No max size
				read_flags_socket,
				get_target_size,
				get_target_size_arg,
				complete_callback,
				complete_callback_arg
		);

		if (ret == RRR_SOCKET_OK) {
			node->last_seen = time_now;
		}
		else {
			if (ret != RRR_SOCKET_READ_INCOMPLETE) {
				// Don't print error as it will be printed when a remote client disconnects
				// TODO : This error message is useless because we don't know which client has disconnected
				RRR_DBG_1("A client was disconnected when reading in rrr_socket_client_collection_read, closing connection\n");
				RRR_LL_ITERATE_SET_DESTROY();
			}
			ret = 0;
		}

		if (node->last_seen < timeout) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection,__rrr_socket_client_destroy(node));

	return ret;
}
