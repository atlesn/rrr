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

#include "../util/linked_list.h"

struct rrr_socket_send_chunk;

struct rrr_socket_send_chunk_collection {
	RRR_LL_HEAD(struct rrr_socket_send_chunk);
};

void rrr_socket_send_chunk_collection_clear (
		struct rrr_socket_send_chunk_collection *target
);
int rrr_socket_send_chunk_collection_push (
		struct rrr_socket_send_chunk_collection *target,
		void **data,
		ssize_t data_size
);
int rrr_socket_send_chunk_collection_push_const (
		struct rrr_socket_send_chunk_collection *target,
		const void *data,
		ssize_t data_size
);
int rrr_socket_send_chunk_collection_sendto (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_socket_send_chunk_collection_sendto_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		int (*callback)(ssize_t *written_bytes, const void *data, ssize_t data_size, void *arg),
		void *callback_arg
);

#endif /* RRR_SOCKET_SEND_CHUNK_H */
