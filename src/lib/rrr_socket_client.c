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

#include "../global.h"
#include "linked_list.h"
#include "rrr_socket.h"
#include "rrr_socket_client.h"
#include "rrr_socket_read.h"
#include "vl_time.h"

static int __rrr_socket_client_destroy (
		struct rrr_socket_client *client
) {
	if (client->connected_fd > 0) {
		rrr_socket_close(client->connected_fd);
	}
	rrr_socket_read_session_collection_clear(&client->read_sessions);
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
		VL_MSG_ERR("Could not allocate memory in __rrr_socket_client_new\n");
		ret = 1;
		goto out;
	}

	memset(client, '\0', sizeof(*client));

	client->connected_fd = fd;
	client->addr = *addr;
	client->addr_len = addr_len;
	client->last_seen = time_get_64();

	if (private_data_new != NULL) {
		if (private_data_destroy == NULL) {
			VL_BUG("BUG: A new function was defined but no destroy function in __rrr_socket_client_new\n");
		}

		if ((ret = private_data_new(&client->private_data, private_arg)) != 0) {
			VL_MSG_ERR("Error while initializing private data in __rrr_socket_client_new\n");
			ret = 1;
			goto out_free;
		}

		client->private_data_destroy = private_data_destroy;
	}
	else if (private_data_destroy != NULL) {
		VL_BUG("BUG: A destroy function was defined but no new function in __rrr_socket_client_new\n");
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
		VL_MSG_ERR("Could not allocate memory in rrr_socket_client_collection_init\n");
		return 1;
	}
	collection->listen_fd = listen_fd;
	return 0;
}

int rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection,
		int (*private_data_new)(void **target, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
) {
	struct rrr_socket_client temp = {0};
	temp.addr_len = sizeof(temp.addr);

	int ret = rrr_socket_accept(collection->listen_fd, &temp.addr, &temp.addr_len, collection->creator);
	if (ret == -1) {
		if (errno != EWOULDBLOCK) {
			VL_MSG_ERR("Error while accepting connection in rrr_socket_client_collection_accept: %s\n", strerror(errno));
			return 1;
		}
		return 0;
	}

	temp.connected_fd = ret;

	struct rrr_socket_client *client_new = NULL;
	if (__rrr_socket_client_new (
			&client_new,
			temp.connected_fd,
			&temp.addr,
			temp.addr_len,
			private_data_new,
			private_arg,
			private_data_destroy
	) != 0) {
		VL_MSG_ERR("Could not allocate memory in rrr_socket_client_collection_accept\n");
		return 1;
	}

	RRR_LL_PUSH(collection, client_new);

	return 0;
}

int rrr_socket_client_collection_accept_simple (
		struct rrr_socket_client_collection *collection
) {
	return rrr_socket_client_collection_accept (collection, NULL, NULL, NULL);
}

int rrr_socket_client_collection_read (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;
	uint64_t time_now = time_get_64();
	uint64_t timeout = time_get_64() - (RRR_SOCKET_CLIENT_TIMEOUT * 1000 * 1000);

	if (RRR_LL_COUNT(collection) == 0 && (read_flags & RRR_SOCKET_READ_USE_TIMEOUT) != 0) {
		usleep(10 * 1000);
	}

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		ret = rrr_socket_read_message (
				&node->read_sessions,
				node->connected_fd,
				read_step_initial,
				read_step_max_size,
				read_flags,
				get_target_size,
				get_target_size_arg,
				complete_callback,
				complete_callback_arg,
				node
		);

		if (ret == RRR_SOCKET_OK) {
			node->last_seen = time_now;
		}
		else {
			if (ret != RRR_SOCKET_READ_INCOMPLETE) {
				VL_MSG_ERR("Error while reading from client in rrr_socket_client_collection_read, closing connection\n");
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
