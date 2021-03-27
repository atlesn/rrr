/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SOCKET_SEND_CHUNK_H
#define RRR_SOCKET_SEND_CHUNK_H

#include <sys/socket.h>
#include <stdio.h>

#include "../util/linked_list.h"

struct rrr_socket_send_chunk;

struct rrr_socket_send_chunk_collection {
	RRR_LL_HEAD(struct rrr_socket_send_chunk);
};

void rrr_socket_send_chunk_collection_clear (
		struct rrr_socket_send_chunk_collection *target
);
void rrr_socket_send_chunk_collection_clear_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);
int rrr_socket_send_chunk_collection_push (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		void **data,
		ssize_t data_size
);
int rrr_socket_send_chunk_collection_push_with_private_data (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		void **data,
		ssize_t data_size,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
);
int rrr_socket_send_chunk_collection_push_const (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const void *data,
		ssize_t data_size
);
int rrr_socket_send_chunk_collection_push_const_with_private_data (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const void *data,
		ssize_t data_size,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
);
int rrr_socket_send_chunk_collection_push_const_with_address_and_private_data (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		ssize_t data_size,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
);
int rrr_socket_send_chunk_collection_send (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd
);
int rrr_socket_send_chunk_collection_send_and_notify (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd,
		void (*callback)(const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);
int rrr_socket_send_chunk_collection_send_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		int (*callback)(ssize_t *written_bytes, const struct sockaddr *addr, socklen_t addr_len, const void *data, ssize_t data_size, void *arg),
		void *callback_arg
);
void rrr_socket_send_chunk_collection_iterate (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(int *do_remove, const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);

#endif /* RRR_SOCKET_SEND_CHUNK_H */
