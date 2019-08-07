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
#include <sys/types.h>
#include <sys/socket.h>

#include "../global.h"
#include "rrr_socket.h"

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
	char creator[128];
	struct rrr_socket_holder *next;
	int fd;
};

static struct rrr_socket_holder *first_socket = NULL;
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;

int rrr_socket_with_lock_do (int (*callback)(void *arg), void *arg) {
	int ret = 0;
	pthread_mutex_lock(&socket_lock);
	ret = callback(arg);
	pthread_mutex_unlock(&socket_lock);
	return ret;
}

static void __rrr_socket_dump_unlocked (void) {
	struct rrr_socket_holder *cur = first_socket;
	while (cur) {
		VL_DEBUG_MSG_7 ("fd %i pid %i creator %s\n", cur->fd, getpid(), cur->creator);
		cur = cur->next;
	}
	VL_DEBUG_MSG_7("---\n");
}

static void __rrr_socket_add_unlocked (int fd, const char *creator) {
	if (strlen(creator) > 127) {
		VL_BUG("Creator name too long in __rrr_socket_add_unlocked\n");
	}
	struct rrr_socket_holder *holder = malloc(sizeof(*holder));
	holder->fd = fd;
	holder->next = first_socket;
	strcpy(holder->creator, creator);
	first_socket = holder;

	if (VL_DEBUGLEVEL_7) {
		VL_DEBUG_MSG_7("rrr_socket add fd %i pid %i, sockets are now:\n", fd, getpid());
		__rrr_socket_dump_unlocked();
	}
}

int rrr_socket_accept (int fd_in, struct sockaddr *addr, socklen_t *__restrict addr_len, const char *creator) {
	int fd_out = 0;
	pthread_mutex_lock(&socket_lock);
	fd_out = accept(fd_in, addr, addr_len);
	if (fd_out != -1) {
		__rrr_socket_add_unlocked(fd_out, creator);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd_out;
}

int rrr_socket_mkstemp (char *filename, const char *creator) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = mkstemp(filename);
	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, creator);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

int rrr_socket (int domain, int type, int protocol, const char *creator) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = socket(domain, type, protocol);

	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, creator);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

int rrr_socket_close (int fd) {
	if (fd <= 0) {
		VL_BUG("rrr_socket_close called with fd <= 0: %i\n", fd);
	}

	VL_DEBUG_MSG_7("rrr_socket_close fd %i pid %i\n", fd, getpid());

	int ret = close(fd);

	if (ret != 0) {
		// A socket is sometimes closed by the other host
		if (errno != EBADF) {
			VL_MSG_ERR("Warning: Socket close of fd %i failed in rrr_socket_close: %s\n", fd, strerror(errno));
		}
	}

	pthread_mutex_lock(&socket_lock);

	int did_free = 0;

	__rrr_socket_dump_unlocked();

	if (first_socket != NULL && first_socket->fd == fd) {
		struct rrr_socket_holder *cur = first_socket;
		first_socket = first_socket->next;
		free(cur);
		did_free = 1;
	}
	else {
		struct rrr_socket_holder *cur = first_socket;
		while (cur) {
			struct rrr_socket_holder *next = cur->next;

			if (next->fd == fd) {
				cur->next = next->next;
				free (next);
				did_free = 1;
				break;
			}

			cur = next;
		}
	}

	__rrr_socket_dump_unlocked();

	pthread_mutex_unlock(&socket_lock);

	if (did_free == 0) {
		VL_BUG("rrr_socket_close called with fd %i which was not in the list\n", fd);
	}

	return ret;
}

int rrr_socket_close_all_except (int fd) {
	int ret = 0;

	if (fd < 0) {
		VL_BUG("rrr_socket_close_all_except called with fd < 0: %i\n", fd);
	}

	VL_DEBUG_MSG_7("rrr_socket_close_all_except fd %i pid %i\n", fd, getpid());

	int err_count = 0;
	int count = 0;

	pthread_mutex_lock(&socket_lock);

	struct rrr_socket_holder *found = NULL;

	struct rrr_socket_holder *cur = first_socket;
	while (cur) {
		struct rrr_socket_holder *next = cur->next;

		if (cur->fd == fd) {
			if (found != NULL) {
				VL_BUG("At least two equal fds found in rrr_socket_close_all_except: %i\n", fd);
			}
			found = cur;
			goto next;
		}

		ret |= close(cur->fd);
		if (ret != 0) {
			err_count++;
			VL_MSG_ERR("Warning: Socket close of fd %i failed in rrr_socket_close_all_except: %s\n", fd, strerror(errno));
		}

		free(cur);
		count++;

		next:
		cur = next;
	}

	if (found == NULL && fd != 0) {
		VL_BUG ("rrr_socket_close_all_except called with fd %i which was not in the list\n", fd);
	}

	if (found != NULL) {
		found->next = NULL;
		first_socket = found;
	}
	else {
		first_socket = NULL;
	}

	if (VL_DEBUGLEVEL_7) {
		__rrr_socket_dump_unlocked();
	}

	pthread_mutex_unlock(&socket_lock);

	VL_DEBUG_MSG_1("Closed %i sockets with %i errors pid %i\n", count, err_count, getpid());

	return ret;
}

int rrr_socket_close_all (void) {
	return rrr_socket_close_all_except(0);
}

