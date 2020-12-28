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

// Allow SOCK_NONBLOCK on BSD
#define __BSD_VISIBLE 1
#include <sys/socket.h>
#undef __BSD_VISIBLE

#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>

#include "rrr_socket_read.h"
#include "rrr_socket_constants.h"

#include "../util/linked_list.h"

enum rrr_socket_private_data_class {
	RRR_SOCKET_PRIVATE_DATA_CLASS_INPUT_DEVICE
};

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
void *rrr_socket_get_private_data_from_fd (
		int fd,
		enum rrr_socket_private_data_class class,
		size_t size
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
		int mode,
		const char *creator,
		int register_for_unlink
);
int rrr_socket_open_and_read_file (
		char **result,
		ssize_t *result_bytes,
		const char *filename,
		int options,
		int mode
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
int rrr_socket_close_all_no_unlink (void);
int rrr_socket_fifo_create (
		int *fd_result,
		const char *filename,
		const char *creator,
		int do_write_mode,
		int do_nonblock,
		int unlink_if_exists
);
int rrr_socket_unix_create_bind_and_listen (
		int *fd_result,
		const char *creator,
		const char *filename_orig,
		int num_clients,
		int nonblock,
		int do_mkstemp,
		int do_unlink_if_exists
);
int rrr_socket_connect_nonblock_postcheck_loop (
		int fd,
		uint64_t timeout_ms
);
int rrr_socket_connect_nonblock (
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_socket_unix_connect (
		int *socket_fd_final,
		const char *creator,
		const char *filename,
		int nonblock
);
int rrr_socket_sendto_nonblock (
		int *err,
		ssize_t *written_bytes,
		int fd,
		const void *data,
		ssize_t size,
		const struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_socket_sendto_nonblock_check_retry (
		ssize_t *written_bytes,
		int fd,
		const void *data,
		ssize_t size,
		struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_socket_send_nonblock_check_retry (
		ssize_t *written_bytes,
		int fd,
		const void *data,
		ssize_t size
);
int rrr_socket_sendto_blocking (
		int fd,
		const void *data,
		ssize_t size,
		struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_socket_sendto_nonblock_fail_on_partial_write (
		int *err,
		int fd,
		void *data,
		ssize_t data_size,
		const struct sockaddr *sockaddr,
		socklen_t addrlen
);
int rrr_socket_send_blocking (
		int fd,
		void *data,
		ssize_t size
);
int rrr_socket_check_alive (int fd);


#endif /* RRR_SOCKET_H */
