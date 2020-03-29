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

#ifndef RRR_SOCKET_CLIENT_H
#define RRR_SOCKET_CLIENT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>

#include "rrr_socket_read.h"
#include "linked_list.h"
#include "read.h"

struct rrr_socket_client {
	RRR_LL_NODE(struct rrr_socket_client);
	struct rrr_read_session_collection read_sessions;
	int connected_fd;
	struct sockaddr addr;
	socklen_t addr_len;
	uint64_t last_seen;
	void *private_data;
	void (*private_data_destroy)(void *private_data);
};

struct rrr_socket_client_collection {
	RRR_LL_HEAD(struct rrr_socket_client);
	int listen_fd;
	char *creator;
};

struct rrr_socket_msg;

void rrr_socket_client_collection_clear (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_init (
		struct rrr_socket_client_collection *collection,
		int listen_fd,
		const char *creator
);
int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection,
		int (*private_data_new)(void **target, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
);
int rrr_socket_client_collection_accept_simple (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_multicast_send (
		struct rrr_socket_client_collection *collection,
		void *data,
		size_t size
);
int rrr_socket_client_collection_read (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int read_flags_socket,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
);

#endif /* RRR_SOCKET_CLIENT_H */
