/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <linux/un.h>

#include "linked_list.h"
#include "rrr_endian.h"
#include "../global.h"
#include "rrr_socket.h"
#include "vl_time.h"
#include "crc32.h"

/*
 * The meaning with this global tracking of sockets is to make sure that
 * forked processes can close not-needed sockets.
 *
 * The forked process will have access to this global data in the state
 * which it had when the fork was created. New sockets created in the
 * main process can be added later, but they are not visible to
 * the fork. Also, new sockets in the fork are not visible to main.
 */

struct rrr_socket_holder {
	RRR_LINKED_LIST_NODE(struct rrr_socket_holder);
	char *creator;
	char *filename;
	int fd;
};

struct rrr_socket_holder_collection {
	RRR_LINKED_LIST_HEAD(struct rrr_socket_holder);
};

struct rrr_socket_holder_collection socket_list = {0};
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;

int __rrr_socket_holder_close_and_destroy(struct rrr_socket_holder *holder) {
	int ret = 0;
	if (holder->fd > 0) {
		ret = close(holder->fd);
		if (ret != 0) {
			// A socket is sometimes closed by the other host
			if (errno != EBADF) {
				VL_MSG_ERR("Warning: Socket close of fd %i failed in rrr_socket_close: %s\n",
						holder->fd, strerror(errno));
			}
		}
	}
	if (holder->filename != NULL) {
		unlink(holder->filename);
	}
	RRR_FREE_IF_NOT_NULL(holder->filename);
	RRR_FREE_IF_NOT_NULL(holder->creator);
	free(holder);

	// Must always return 0 or linked list won' remove the node
	return 0;
}


int __rrr_socket_holder_new (
		struct rrr_socket_holder **holder,
		const char *creator,
		const char *filename,
		int fd
) {
	int ret = 0;

	*holder = NULL;

	struct rrr_socket_holder *result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_socket_holder_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if (creator == NULL || *creator == '\0') {
		VL_BUG("Creator was NULL in __rrr_socket_holder_new\n");
	}

	if (filename != NULL) {
		result->filename = strdup(filename);
		if (result->filename == NULL) {
			VL_MSG_ERR("Could not allocate memory for filename in __rrr_socket_holder_new\n");
			ret = 1;
			goto out;
		}
	}

	result->fd = fd;

	*holder = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

int rrr_socket_with_lock_do (
		int (*callback)(void *arg),
		void *arg
) {
	int ret = 0;
	pthread_mutex_lock(&socket_lock);
	ret = callback(arg);
	pthread_mutex_unlock(&socket_lock);
	return ret;
}

static void __rrr_socket_dump_unlocked (void) {
	RRR_LINKED_LIST_ITERATE_BEGIN(&socket_list,struct rrr_socket_holder);
		VL_DEBUG_MSG_7 ("fd %i pid %i creator %s\n", node->fd, getpid(), node->creator);
	RRR_LINKED_LIST_ITERATE_END(&socket_list);
	VL_DEBUG_MSG_7("---\n");
}

static int __rrr_socket_add_unlocked (
		int fd,
		const char *creator,
		const char *filename
) {
	int ret = 0;
	struct rrr_socket_holder *holder = NULL;

	if (__rrr_socket_holder_new(&holder, creator, filename, fd) != 0) {
		VL_MSG_ERR("Could not create socket holder in __rrr_socket_add_unlocked\n");
		ret = 1;
		goto out;
	}

	RRR_LINKED_LIST_PUSH(&socket_list,holder);
	holder = NULL;

	if (VL_DEBUGLEVEL_7) {
		VL_DEBUG_MSG_7("rrr_socket add fd %i pid %i, sockets are now:\n", fd, getpid());
		__rrr_socket_dump_unlocked();
	}

	out:
	RRR_FREE_IF_NOT_NULL(holder);
	return ret;
}

int rrr_socket_accept (
		int fd_in,
		struct sockaddr *addr,
		socklen_t *__restrict addr_len,
		const char *creator
) {
	int fd_out = 0;
	pthread_mutex_lock(&socket_lock);
	fd_out = accept(fd_in, addr, addr_len);
	if (fd_out != -1) {
		__rrr_socket_add_unlocked(fd_out, creator, NULL);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd_out;
}

int rrr_socket_mkstemp (
		char *filename,
		const char *creator
) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = mkstemp(filename);
	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, creator, filename);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

int rrr_socket_bind_and_listen (
		int fd,
		struct sockaddr *addr,
		socklen_t *addr_len,
		int num_clients
) {
	if (bind(fd, addr, *addr_len) != 0) {
		VL_MSG_ERR("Could not bind to socket: %s\n",strerror(errno));
		return 1;
	}
	if (listen(fd, num_clients) != 0) {
		VL_MSG_ERR("Could not listen on socket: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

int rrr_socket (
		int domain,
		int type,
		int protocol,
		const char *creator,
		const char *filename
) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = socket(domain, type, protocol);

	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, creator, filename);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

int rrr_socket_close (int fd) {
	if (fd <= 0) {
		VL_BUG("rrr_socket_close called with fd <= 0: %i\n", fd);
	}

	VL_DEBUG_MSG_7("rrr_socket_close fd %i pid %i\n", fd, getpid());

	pthread_mutex_lock(&socket_lock);

	int did_destroy = 0;

	__rrr_socket_dump_unlocked();

	RRR_LINKED_LIST_ITERATE_BEGIN(&socket_list,struct rrr_socket_holder);
		if (node->fd == fd) {
			RRR_LINKED_LIST_SET_DESTROY();
			RRR_LINKED_LIST_SET_STOP();
			did_destroy = 1;
		}
	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY(&socket_list,__rrr_socket_holder_close_and_destroy(node));

	__rrr_socket_dump_unlocked();

	pthread_mutex_unlock(&socket_lock);

	if (did_destroy != 1) {
		VL_MSG_ERR("Warning: Socket close of fd %i called but it was not registered. Attempting to close anyway.\n", fd);
		int ret = close(fd);
		if (ret != 0) {
			// A socket is sometimes closed by the other host
			if (errno != EBADF) {
				VL_MSG_ERR("Warning: Socket close of fd %i failed in rrr_socket_close: %s\n", fd, strerror(errno));
			}
		}
	}

	return 0;
}

int rrr_socket_close_all_except (int fd) {
	int ret = 0;

	if (fd < 0) {
		VL_BUG("rrr_socket_close_all_except called with fd < 0: %i\n", fd);
	}

	VL_DEBUG_MSG_7("rrr_socket_close_all_except fd %i pid %i\n", fd, getpid());

	int count = 0;
	int found = 0;

	pthread_mutex_lock(&socket_lock);

	RRR_LINKED_LIST_ITERATE_BEGIN(&socket_list,struct rrr_socket_holder);
		if (node->fd != fd) {
			RRR_LINKED_LIST_SET_DESTROY();
			count++;
		}
		else {
			if (found != 0) {
				VL_BUG("At least two equal FD %i in socket list in rrr_socket_close_all_except\n", fd);
			}
			found = 1;
		}
	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY(&socket_list,__rrr_socket_holder_close_and_destroy(node));

	if (found != 1 && fd != 0) {
		VL_MSG_ERR("Warning: rrr_socket_close_all_except called with unregistered FD %i. All sockets are now closed.\n", fd);
	}

	if (VL_DEBUGLEVEL_7) {
		__rrr_socket_dump_unlocked();
	}

	pthread_mutex_unlock(&socket_lock);

	VL_DEBUG_MSG_1("Closed %i sockets pid %i\n", count, getpid());

	return ret;
}

int rrr_socket_close_all (void) {
	return rrr_socket_close_all_except(0);
}

int rrr_socket_unix_create_bind_and_listen (
		int *fd_result,
		const char *creator,
		const char *filename,
		int num_clients,
		int nonblock
) {
	int ret = 0;

	*fd_result = 0;

	struct sockaddr_un addr = {0};
	socklen_t addr_len = sizeof(addr);
	int fd = 0;

	if (strlen(filename) > sizeof(addr.sun_path) - 1) {
		VL_MSG_ERR("Filename was too long in rrr_socket_unix_create_bind_and_listen, max is %li\n",
				sizeof(addr.sun_path) - 1);
		ret = 1;
		goto out;
	}

	if (access (filename, F_OK) != 1) {
		VL_MSG_ERR("Filename '%s' already exists while creating socket, please delete it first or use another filename\n",
				filename);
		ret = 1;
		goto out;
	}

	strcpy(addr.sun_path, filename);

	fd = rrr_socket(AF_UNIX, SOCK_SEQPACKET | (nonblock != 0 ? O_NONBLOCK : 0), 0, creator, filename);
	if (fd < 0) {
		VL_MSG_ERR("Could not create socket in rrr_socket_unix_create_bind_and_listen\n");
		ret = 1;
		goto out;
	}

	if (rrr_socket_bind_and_listen(fd, (struct sockaddr *) &addr, &addr_len, num_clients) != 0) {
		VL_MSG_ERR("Could not bind an listen to socket in rrr_socket_unix_create_bind_and_listen\n");
		ret = 1;
		goto out;
	}

	*fd_result = fd;
	fd = 0;

	out:
	if (fd > 0) {
		rrr_socket_close(fd);
	}
	return ret;
}


static int __rrr_socket_client_destroy (
		struct rrr_socket_client *client
) {
	if (client->connected_fd > 0) {
		rrr_socket_close(client->connected_fd);
	}
	rrr_socket_read_session_collection_destroy(&client->read_sessions);
	free(client);
	return 0;
}

static int __rrr_socket_client_new (
		struct rrr_socket_client **result,
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len
) {
	*result = NULL;

	struct rrr_socket_client *client = malloc (sizeof(*client));
	if (client == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_socket_client_new\n");
		return 1;
	}

	memset(client, '\0', sizeof(*client));

	client->connected_fd = fd;
	client->addr = *addr;
	client->addr_len = addr_len;
	client->last_seen = time_get_64();

	*result = client;

	return 0;
}

void rrr_socket_client_collection_destroy (
		struct rrr_socket_client_collection *collection
) {
	RRR_LINKED_LIST_DESTROY(collection,struct rrr_socket_client,__rrr_socket_client_destroy(node));
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
		struct rrr_socket_client_collection *collection
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
	if (__rrr_socket_client_new(&client_new, temp.connected_fd, &temp.addr, temp.addr_len) != 0) {
		VL_MSG_ERR("Could not allocate memory in rrr_socket_client_collection_accept\n");
		return 1;
	}

	RRR_LINKED_LIST_PUSH(collection, client_new);

	return 0;
}

int rrr_socket_client_collection_read (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;
	uint64_t time_now = time_get_64();
	uint64_t timeout = time_get_64() - (RRR_SOCKET_CLIENT_TIMEOUT * 1000 * 1000);

	RRR_LINKED_LIST_ITERATE_BEGIN(collection, struct rrr_socket_client);
		ret = rrr_socket_read_message (
				&node->read_sessions,
				node->connected_fd,
				read_step_initial,
				read_step_max_size,
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
				VL_MSG_ERR("Error while reading from client in rrr_socket_client_collection_read, closing connection\n");
				RRR_LINKED_LIST_SET_DESTROY();
			}
			ret = 0;
		}

		if (node->last_seen < timeout) {
			RRR_LINKED_LIST_SET_DESTROY();
		}
	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY(collection,__rrr_socket_client_destroy(node));

	return ret;
}
