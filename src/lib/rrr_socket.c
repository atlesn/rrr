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

// Allow SOCK_NONBLOCK on BSD
#define __BSD_VISIBLE 1
#include <sys/socket.h>
#undef __BSD_VISIBLE

#include <stddef.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "posix.h"
#include "linked_list.h"
#include "rrr_endian.h"
#include "log.h"
#include "vl_time.h"
#include "crc32.h"
#include "rrr_strerror.h"
#include "rrr_socket.h"
#include "log.h"
#include "rrr_umask.h"

/*
 * The meaning with this global tracking of sockets is to make sure that
 * forked processes can close not-needed sockets.
 *
 * The forked process will have access to this global data in the state
 * which it had when the fork was created. New sockets created in the
 * main process can be added later, but they are not visible to
 * the fork. Also, new sockets in the fork are not visible to main.
 */

// Allow read/write from self and group (mask away others)
// (Should sockets have executable flag?)
#define RRR_SOCKET_UNIX_DEFAULT_UMASK \
	S_IROTH | S_IWOTH | S_IXOTH

struct rrr_socket_holder {
	RRR_LL_NODE(struct rrr_socket_holder);
	char *creator;
	char *filename;
	struct rrr_socket_options options;
};

struct rrr_socket_holder_collection {
	RRR_LL_HEAD(struct rrr_socket_holder);
};

struct rrr_socket_holder_collection socket_list = {0};
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;

int __rrr_socket_holder_close_and_destroy(struct rrr_socket_holder *holder, int no_unlink) {
	int ret = 0;
	if (holder->options.fd > 0) {
		ret = close(holder->options.fd);
		if (ret != 0) {
			// A socket is sometimes closed by the other host
			if (errno != EBADF) {
				RRR_MSG_0("Warning: Socket close of fd %i failed in rrr_socket_close: %s\n",
						holder->options.fd, rrr_strerror(errno));
			}
		}
	}
	if (no_unlink == 0 && holder->filename != NULL) {
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
		int fd,
		int domain,
		int type,
		int protocol
) {
	int ret = 0;

	*holder = NULL;

	struct rrr_socket_holder *result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_holder_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if (creator == NULL || *creator == '\0') {
		RRR_BUG("Creator was NULL in __rrr_socket_holder_new\n");
	}

	result->creator = strdup(creator);

	if (filename != NULL) {
		result->filename = strdup(filename);
		if (result->filename == NULL) {
			RRR_MSG_0("Could not allocate memory for filename in __rrr_socket_holder_new\n");
			ret = 1;
			goto out;
		}
	}

	result->options.fd = fd;
	result->options.domain = domain;
	result->options.type = type;
	result->options.protocol = protocol;

	*holder = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

int rrr_socket_get_filename_from_fd (
		char **result,
		int fd
) {
	*result = NULL;

	pthread_mutex_lock(&socket_lock);

	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&socket_list, struct rrr_socket_holder);
		if (node->options.fd == fd) {
			if (node->filename != NULL && *(node->filename) != '\0') {
				char *filename = strdup(node->filename);
				if (filename == NULL) {
					RRR_MSG_0("Could not allocate memory in rrr_socket_get_filename_from_fd\n");
					ret = 1;
					goto out;
				}
				*result = filename;
			}
			ret = 0;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	pthread_mutex_unlock(&socket_lock);
	return ret;
}

int rrr_socket_get_options_from_fd (
		struct rrr_socket_options *target,
		int fd
) {
	memset (target, '\0', sizeof(*target));

	int ret = 1;

	pthread_mutex_lock(&socket_lock);

	RRR_LL_ITERATE_BEGIN(&socket_list, struct rrr_socket_holder);
		if (node->options.fd == fd) {
			*target = node->options;
			ret = 0;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	pthread_mutex_unlock(&socket_lock);

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
	RRR_LL_ITERATE_BEGIN(&socket_list,struct rrr_socket_holder);
		RRR_DBG_7 ("fd %i pid %i creator %s filename %s\n", node->options.fd, getpid(), node->creator, node->filename);
	RRR_LL_ITERATE_END();
	RRR_DBG_7("---\n");
}

static int __rrr_socket_add_unlocked (
		int fd,
		int domain,
		int type,
		int protocol,
		const char *creator,
		const char *filename
) {
	int ret = 0;
	struct rrr_socket_holder *holder = NULL;

	if (__rrr_socket_holder_new(&holder, creator, filename, fd, domain, type, protocol) != 0) {
		RRR_MSG_0("Could not create socket holder in __rrr_socket_add_unlocked\n");
		ret = 1;
		goto out;
	}

	RRR_LL_UNSHIFT(&socket_list,holder);
	holder = NULL;

	if (RRR_DEBUGLEVEL_7) {
		RRR_DBG_7("rrr_socket add fd %i pid %i, sockets are now:\n", fd, getpid());
		__rrr_socket_dump_unlocked();
	}

	out:
	RRR_FREE_IF_NOT_NULL(holder);
	return ret;
}

static int __rrr_socket_add_unlocked_basic (
		int fd,
		const char *creator
) {
	return __rrr_socket_add_unlocked(fd, 0, 0, 0, creator, NULL);
}

int rrr_socket_accept (
		int fd_in,
		struct sockaddr *addr,
		socklen_t *__restrict addr_len,
		const char *creator
) {
	int fd_out = 0;

	struct rrr_socket_options options;

	if (rrr_socket_get_options_from_fd(&options, fd_in) != 0) {
		RRR_MSG_0("Could not get socket options in rrr_socket_accept\n");
		fd_out = -1;
		goto out;
	}

	pthread_mutex_lock(&socket_lock);

	socklen_t addr_len_orig = *addr_len;
	fd_out = accept(fd_in, (struct sockaddr *) addr, addr_len);
	if (fd_out != -1) {
		__rrr_socket_add_unlocked(fd_out, options.domain, options.type, options.protocol, creator, NULL);
	}
	if (*addr_len > addr_len_orig) {
		RRR_BUG("BUG: Given addr_len was to short in rrr_socket_accept\n");
	}
	pthread_mutex_unlock(&socket_lock);

	if (fd_out != -1 && (options.type & SOCK_NONBLOCK) == SOCK_NONBLOCK) {
		int flags = fcntl(fd_out, F_GETFL, 0);
		if (flags == -1) {
			RRR_MSG_0("Error while getting flags with fcntl for socket in rrr_socket_accept: %s\n", rrr_strerror(errno));
			goto out_close;
		}
		if (fcntl(fd_out, F_SETFL, flags | O_NONBLOCK) == -1) {
			RRR_MSG_0("Error while setting O_NONBLOCK on socket in rrr_socket_accept: %s\n", rrr_strerror(errno));
			goto out_close;
		}
	}

	out:
	return fd_out;

	out_close:
	rrr_socket_close(fd_out);
	return -1;
}

int rrr_socket_mkstemp (
		char *filename,
		const char *creator
) {
	int fd = 0;

	pthread_mutex_lock(&socket_lock);
	fd = mkstemp(filename);
	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, 0, 0, 0, creator, filename);
	}
	pthread_mutex_unlock(&socket_lock);

	return fd;
}

int rrr_socket_bind_and_listen (
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len,
		int sockopts,
		int num_clients
) {
	if (sockopts != 0) {
		int enable = 1;
		if (setsockopt (fd, SOL_SOCKET, sockopts, &enable, sizeof(enable)) != 0) {
			RRR_MSG_0 ("Could not set SO_REUSEADDR for socket: %s\n", rrr_strerror(errno));
			return 1;
		}
	}
	if (bind(fd, addr, addr_len) != 0) {
		RRR_MSG_0("Could not bind to socket: %s\n",rrr_strerror(errno));
		return 1;
	}
	if (listen(fd, num_clients) != 0) {
		RRR_MSG_0("Could not listen on socket: %s\n", rrr_strerror(errno));
		return 1;
	}
	return 0;
}

int rrr_socket_open (
		const char *filename,
		int flags,
		const char *creator
) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = open(filename, flags);

	if (fd != -1) {
		__rrr_socket_add_unlocked_basic(fd, creator);
	}

	pthread_mutex_unlock(&socket_lock);
	return fd;
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
		__rrr_socket_add_unlocked(fd, domain, type, protocol, creator, filename);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

static int __rrr_socket_close (int fd, int ignore_unregistered, int no_unlink) {
	if (fd <= 0) {
		RRR_BUG("rrr_socket_close called with fd <= 0: %i\n", fd);
	}

	RRR_DBG_7("rrr_socket_close fd %i pid %i no unlink %i\n", fd, getpid(), no_unlink);

	pthread_mutex_lock(&socket_lock);

	int did_destroy = 0;

	__rrr_socket_dump_unlocked();

	RRR_LL_ITERATE_BEGIN(&socket_list,struct rrr_socket_holder);
		if (node->options.fd == fd) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
			did_destroy = 1;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&socket_list,__rrr_socket_holder_close_and_destroy(node, no_unlink));

	__rrr_socket_dump_unlocked();

	pthread_mutex_unlock(&socket_lock);

	if (did_destroy != 1 && ignore_unregistered == 0) {
		RRR_MSG_0("Warning: Socket close of fd %i called but it was not registered. Attempting to close anyway.\n", fd);
		int ret = close(fd);
		if (ret != 0) {
			// A socket is sometimes closed by the other host
			if (errno != EBADF) {
				RRR_MSG_0("Warning: Socket close of fd %i failed in rrr_socket_close: %s\n", fd, rrr_strerror(errno));
			}
		}
	}

	return 0;
}

int rrr_socket_close (int fd) {
	return __rrr_socket_close (fd, 0, 0);
}

int rrr_socket_close_no_unlink (int fd) {
	return __rrr_socket_close (fd, 0, 1);
}

int rrr_socket_close_ignore_unregistered (int fd) {
	return __rrr_socket_close (fd, 1, 0);
}

static int __rrr_socket_close_all_except (int fd, int no_unlink) {
	int ret = 0;

	if (fd < 0) {
		RRR_BUG("rrr_socket_close_all_except called with fd < 0: %i\n", fd);
	}

	RRR_DBG_7("rrr_socket_close_all_except fd %i pid %i no_unlink %i\n", fd, getpid(), no_unlink);

	int count = 0;
	int found = 0;

	pthread_mutex_lock(&socket_lock);

	RRR_LL_ITERATE_BEGIN(&socket_list,struct rrr_socket_holder);
		if (node->options.fd != fd) {
			RRR_LL_ITERATE_SET_DESTROY();
			count++;
		}
		else {
			if (found != 0) {
				RRR_BUG("At least two equal FD %i in socket list in rrr_socket_close_all_except\n", fd);
			}
			found = 1;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&socket_list,__rrr_socket_holder_close_and_destroy(node, no_unlink));

	if (found != 1 && fd != 0) {
		RRR_MSG_0("Warning: rrr_socket_close_all_except called with unregistered FD %i. All sockets are now closed.\n", fd);
	}

	if (RRR_DEBUGLEVEL_7) {
		__rrr_socket_dump_unlocked();
	}

	pthread_mutex_unlock(&socket_lock);

	RRR_DBG_1("Closed %i sockets pid %i\n", count, getpid());

	return ret;
}

int rrr_socket_close_all_except (int fd) {
	return __rrr_socket_close_all_except(fd, 0);
}

int rrr_socket_close_all_except_no_unlink (int fd) {
	return __rrr_socket_close_all_except(fd, 1);
}

int rrr_socket_close_all (void) {
	return __rrr_socket_close_all_except(0, 0);
}

int rrr_socket_close_all_no_unlink (void) {
	return __rrr_socket_close_all_except(0, 1);
}

struct rrr_socket_bind_and_listen_umask_callback_data {
	int fd;
	struct sockaddr *addr;
	socklen_t addr_len;
	int num_clients;
};

static int __rrr_socket_bind_and_listen_umask_callback (void *callback_arg) {
	struct rrr_socket_bind_and_listen_umask_callback_data *data = callback_arg;

	return rrr_socket_bind_and_listen(data->fd, data->addr, data->addr_len, 0, data->num_clients);
}

int rrr_socket_unix_create_bind_and_listen (
		int *fd_result,
		const char *creator,
		const char *filename_orig,
		int num_clients,
		int nonblock,
		int do_mkstemp,
		int do_unlink_if_exists
) {
	int ret = 0;

	*fd_result = 0;

	char filename_tmp[strlen(filename_orig) + 1];
	strcpy(filename_tmp, filename_orig);

	struct sockaddr_un addr = {0};
	socklen_t addr_len = sizeof(addr);
	int fd = 0;

	if (strlen(filename_orig) > sizeof(addr.sun_path) - 1) {
		RRR_MSG_0("Filename was too long in rrr_socket_unix_create_bind_and_listen, max is %li\n",
				sizeof(addr.sun_path) - 1);
		ret = 1;
		goto out;
	}

	if (do_unlink_if_exists != 0 && do_mkstemp != 0) {
		RRR_BUG("BUG: Both do_unlink_if_exists and do_mkstemp was set in rrr_socket_unix_create_bind_and_listen\n");
	}

	if (do_mkstemp != 0) {
		fd = rrr_socket_mkstemp(filename_tmp, creator);
		if (fd < 0) {
			RRR_MSG_0("mkstemp failed in rrr_socket_unix_create_bind_and_listen: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		rrr_socket_close(fd);
	}
	else if (access (filename_tmp, F_OK) == 0) {
		if (do_unlink_if_exists != 0) {
			if ((ret = unlink(filename_tmp)) != 0) {
				RRR_MSG_0("Could not unlink file '%s' before creating socket: %s\n",
						filename_tmp, rrr_strerror(errno));
				ret = 1;
				goto out;
			}
		}
		else {
			RRR_MSG_0("Filename '%s' already exists while creating socket, please delete it first or use another filename\n",
					filename_tmp);
			ret = 1;
			goto out;
		}
	}

	strcpy(addr.sun_path, filename_tmp);
	addr.sun_family = AF_UNIX;

	fd = rrr_socket(AF_UNIX, SOCK_STREAM | (nonblock != 0 ? SOCK_NONBLOCK : 0), 0, creator, filename_tmp);

	if (fd < 0) {
		RRR_MSG_0("Could not create socket in rrr_socket_unix_create_bind_and_listen\n");
		ret = 1;
		goto out;
	}

	struct rrr_socket_bind_and_listen_umask_callback_data callback_data = {
		fd,
		(struct sockaddr *) &addr,
		addr_len,
		num_clients
	};

	// The umask wrap is overkill as the global umask should have been set already, but
	// maybe the umask needs to be configurable at a later time
	if (rrr_umask_with_umask_lock_do(RRR_SOCKET_UNIX_DEFAULT_UMASK, __rrr_socket_bind_and_listen_umask_callback, &callback_data)) {
		RRR_MSG_0("Could not bind an listen to socket in rrr_socket_unix_create_bind_and_listen\n");
		ret = 1;
		goto out;
	}

	RRR_DBG_7("rrr_socket_unix_create_bind_and_listen complete fd %i file %s pid %i clients %i umask %i\n",
			fd, addr.sun_path, getpid(), num_clients, RRR_SOCKET_UNIX_DEFAULT_UMASK);

	*fd_result = fd;
	fd = 0;

	out:
	if (fd > 0) {
		rrr_socket_close(fd);
	}
	return ret;
}

int rrr_socket_connect_nonblock_postcheck (
		int fd
) {
	int ret = RRR_SOCKET_OK;

	struct pollfd pollfd = {
		fd, POLLOUT, 0
	};

	int timeout = 5; // 5 ms

	if ((poll(&pollfd, 1, timeout) == -1) || ((pollfd.revents & (POLLERR|POLLHUP)) != 0)) {
		if ((pollfd.revents & (POLLHUP)) != 0) {
			RRR_MSG_0("Connection refused while connecting (POLLHUP)\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
		else if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		else if (errno == ECONNREFUSED) {
			RRR_MSG_0("Connection refused while connecting (ECONNREFUSED)\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		RRR_MSG_0("Error from poll() while connecting: %s\n", rrr_strerror(errno));
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}
	else if ((pollfd.revents & POLLOUT) != 0) {
		goto out;
	}
	else if ((pollfd.revents & POLLOUT) == 0) {
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else {
		int error = 0;
		socklen_t len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
			RRR_MSG_0("Error from getsockopt while connecting: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		else if (error == 0) {
			goto out;
		}
		else if (error == EINPROGRESS) {
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		else if (error == ECONNREFUSED) {
			RRR_MSG_0("Connection refused while connecting\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
		else {
			RRR_MSG_0("Unknown error while connecting: %i\n", error);
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_socket_connect_nonblock_postcheck_loop (
		int fd,
		uint64_t timeout_ms
) {
	int ret = 0;

	uint64_t time_end = rrr_time_get_64() + timeout_ms;

	while (rrr_time_get_64() < time_end) {
		if ((ret = rrr_socket_connect_nonblock_postcheck(fd)) == 0) {
			goto out;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			// Connection refused or some other error
			goto out;
		}
		else {
			// Soft error, try again
		}
		rrr_posix_usleep(10000); // 10 ms
	}

	out:
	return ret;
}

int rrr_socket_connect_nonblock (
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	if (connect(fd, addr, addr_len) == 0) {
		goto out;
	}
	else if (errno == EINPROGRESS || errno == EAGAIN) {
		ret = 0;
		goto out;
	}
	else if (errno == ECONNREFUSED) {
		RRR_MSG_0 ("Connection refused in rrr_socket_connect_nonblock\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else {
		RRR_MSG_0("Error while connecting, address family was %u: %s\n",
				addr->sa_family, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_socket_unix_create_and_connect (
		int *socket_fd_final,
		const char *creator,
		const char *filename,
		int nonblock
) {
	int ret = RRR_SOCKET_OK;
	int socket_fd = 0;
	struct sockaddr_un addr;
	socklen_t addr_len = sizeof(addr);
	memset(&addr, '\0', sizeof(addr));

	*socket_fd_final = 0;

	if (strlen(filename) > sizeof(addr.sun_path) - 1) {
		RRR_MSG_0("Socket path from config was too long in rrr_socket_unix_create_and_connect\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, filename);

	socket_fd = rrr_socket(AF_UNIX, SOCK_STREAM|(nonblock ? SOCK_NONBLOCK : 0), 0, creator, NULL);
	if (socket_fd < 0) {
		RRR_MSG_0("Error while creating socket in rrr_socket_unix_create_and_connect: %s\n", rrr_strerror(errno));
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	int connected = 0;
	for (int i = 0; i < 10 && connected == 0; i++) {
		if (rrr_socket_connect_nonblock(socket_fd, (struct sockaddr *) &addr, addr_len) != 0) {
			RRR_MSG_0("Could not connect to socket %s try %i of %i: %s\n",
					filename, i, 10, rrr_strerror(errno));
			rrr_posix_usleep(25000);
		}
		else {
			connected = 1;
			break;
		}
	}

	if (connected != 1) {
		ret = RRR_SOCKET_SOFT_ERROR;
		rrr_socket_close(socket_fd);
		goto out;
	}

	*socket_fd_final = socket_fd;

	out:
	return ret;
}

int rrr_socket_sendto_nonblock (
		ssize_t *written_bytes,
		int fd,
		const void *data,
		ssize_t size,
		struct sockaddr *addr,
		socklen_t addr_len
) {
	struct rrr_socket_options options;

	int ret = RRR_SOCKET_OK;

	*written_bytes = 0;
	ssize_t done_bytes_total = 0;

	if (rrr_socket_get_options_from_fd(&options, fd) != 0) {
		RRR_MSG_0("Could not get socket options for fd %i in rrr_socket_sendto\n", fd);
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	int flags = 0;
	if ((options.type & SOCK_SEQPACKET) == SOCK_SEQPACKET) {
		flags |= MSG_EOR;
	}
	if ((options.type & SOCK_NONBLOCK) == SOCK_NONBLOCK) {
		flags |= MSG_DONTWAIT;
	}

	int max_retries = 10;
	ssize_t done_bytes = 0;

	retry:
	if (--max_retries == 0) {
		RRR_DBG_3("Max retries reached in rrr_socket_sendto for socket %i\n", fd);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	RRR_DBG_4("Non-blocking send on fd %i starting, writing %i bytes (where of %i is complete)\n",
			fd, size, done_bytes_total);

	if (addr == NULL) {
		done_bytes = send(fd, data + done_bytes_total, size - done_bytes_total, flags);
	}
	else {
		done_bytes = sendto(fd, data + done_bytes_total, size - done_bytes_total, flags, addr, addr_len);
	}

	if (done_bytes > 0) {
		done_bytes_total += done_bytes;
	}

	if (done_bytes_total != size) {
		if (done_bytes <= 0) {
			if (done_bytes == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
				rrr_posix_usleep(10);
				goto retry;
			}
			else if (errno == EINTR) {
				rrr_posix_usleep(10);
				goto retry;
			}
			else {
				RRR_MSG_0("Error from send(to) function in rrr_socket_sendto fd %i flags %i addr ptr %p addr len %i: %s\n",
						fd,
						flags,
						addr,
						addr_len,
						rrr_strerror(errno)
				);
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}
		}
		else {
			rrr_posix_usleep(10);
			goto retry;
		}
	}
	else {
		ret = RRR_SOCKET_OK;
	}

	out:
	*written_bytes = done_bytes_total;
	return ret;
}

int rrr_socket_sendto_blocking (
		int fd,
		const void *data,
		ssize_t size,
		struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	ssize_t written_bytes = 0;
	ssize_t written_bytes_total = 0;

	while (written_bytes_total < size) {
		RRR_DBG_4("Blocking send on fd %i starting, writing %i bytes (where of %i is complete)\n",
				fd, size, written_bytes_total);
		if ((ret = rrr_socket_sendto_nonblock (
				&written_bytes,
				fd,
				data + written_bytes_total,
				size - written_bytes_total,
				addr,
				addr_len
		)) != 0) {
			if (ret != RRR_SOCKET_SOFT_ERROR) {
				RRR_MSG_0("Error from sendto in rrr_socket_sendto_blocking\n");
				goto out;
			}
		}
		written_bytes_total += written_bytes;
		RRR_DBG_4("Blocking send on fd %i, written bytes total is %i (this round was %i)\n",
				fd, written_bytes_total, written_bytes);
	}

	out:
	return ret;
}
