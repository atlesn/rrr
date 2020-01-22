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

#define RRR_SOCKET_OK				0
#define RRR_SOCKET_HARD_ERROR		1
#define RRR_SOCKET_SOFT_ERROR		2
#define RRR_SOCKET_READ_INCOMPLETE	3
#define RRR_SOCKET_READ_EOF			4

#define RRR_SOCKET_READ_COMPLETE_METHOD_TARGET_LENGTH	0
#define RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE		1

#define RRR_SOCKET_CLIENT_TIMEOUT	30

#define RRR_SOCKET_READ_METHOD_READ_FILE	(1<<0)
#define RRR_SOCKET_READ_METHOD_RECVFROM		(1<<1)
#define RRR_SOCKET_READ_CHECK_EOF			(1<<2)
#define RRR_SOCKET_READ_USE_TIMEOUT			(1<<3)
#define RRR_SOCKET_READ_NO_SLEEPING			(1<<4)
#define RRR_SOCKET_READ_METHOD_RECV			(1<<5)

struct rrr_socket_options {
	int fd;
	int domain;
	int type;
	int protocol;
};

struct rrr_socket_client {
	RRR_LL_NODE(struct rrr_socket_client);
	struct rrr_socket_read_session_collection read_sessions;
	int connected_fd;
	struct sockaddr addr;
	socklen_t addr_len;
	uint64_t last_seen;
};

struct rrr_socket_client_collection {
	RRR_LL_HEAD(struct rrr_socket_client);
	int listen_fd;
	char *creator;
};

struct rrr_socket_read_session;
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
int rrr_socket_close_ignore_unregistered (int fd);
int rrr_socket_close_all_except (int fd);
int rrr_socket_close_all (void);
int rrr_socket_unix_create_bind_and_listen (
		int *fd_result,
		const char *creator,
		const char *filename,
		int num_clients,
		int nonblock
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
void rrr_socket_client_collection_destroy (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_init (
		struct rrr_socket_client_collection *collection,
		int listen_fd,
		const char *creator
);
int rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_read (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
);

#endif /* RRR_SOCKET_H */
