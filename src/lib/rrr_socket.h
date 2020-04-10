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

#ifndef RRR_SOCKET_H
#define RRR_SOCKET_H

#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>

#include "linked_list.h"
#include "rrr_socket_read.h"
#include "rrr_socket_constants.h"

struct rrr_socket_options {
	int fd;
	int domain;
	int type;
	int protocol;
};

struct rrr_read_session;
int rrr_socket_get_filename_from_fd (
		char **result,
		int fd
);
int rrr_socket_get_options_from_fd (
		struct rrr_socket_options *target,
		int fd
);
int rrr_socket_with_lock_do (
		int (*callback)(void *arg),
		void *arg
);
int rrr_socket_accept (
		int fd_in,
		struct sockaddr *addr,
		socklen_t *__restrict addr_len,
		const char *creator
);
int rrr_socket_mkstemp (
		char *filename,
		const char *creator
);
int rrr_socket_bind_and_listen (
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len,
		int sockopts,
		int num_clients
);
int rrr_socket_open (
		const char *filename,
		int flags,
		const char *creator
);
int rrr_socket (
		int domain,
		int type,
		int protocol,
		const char *creator,
		const char *filename
);
int rrr_socket_close (int fd);
int rrr_socket_close_no_unlink (int fd);
int rrr_socket_close_ignore_unregistered (int fd);
int rrr_socket_close_all_except (int fd);
int rrr_socket_close_all_except_no_unlink (int fd);
int rrr_socket_close_all (void);
int rrr_socket_unix_create_bind_and_listen (
		int *fd_result,
		const char *creator,
		const char *filename_orig,
		int num_clients,
		int nonblock,
		int do_mkstemp
);
int rrr_socket_connect_nonblock (
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_socket_unix_create_and_connect (
		int *socket_fd_final,
		const char *creator,
		const char *filename,
		int nonblock
);
int rrr_socket_sendto (
		int fd,
		void *data,
		ssize_t size,
		struct sockaddr *addr,
		socklen_t addr_len
);
static inline int rrr_socket_send (
		int fd,
		void *data,
		ssize_t size
) {
	return rrr_socket_sendto(fd, data, size, NULL, 0);
}


#endif /* RRR_SOCKET_H */
