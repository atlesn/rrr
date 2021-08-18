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

#include "../rrr_types.h"
#include "../util/linked_list.h"

enum rrr_socket_send_chunk_priority {
	RRR_SOCKET_SEND_CHUNK_PRIORITY_HIGH,
	RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL
};

#define RRR_SOCKET_SEND_CHUNK_PRIORITY_COUNT 2

struct rrr_socket_send_chunk_collection_list {
	RRR_LL_HEAD(struct rrr_socket_send_chunk);
};

struct rrr_socket_send_chunk_collection {
	struct rrr_socket_send_chunk_collection_list chunk_lists[RRR_SOCKET_SEND_CHUNK_PRIORITY_COUNT];
};

void rrr_socket_send_chunk_collection_clear (
		struct rrr_socket_send_chunk_collection *chunks
);
void rrr_socket_send_chunk_collection_clear_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);
rrr_length rrr_socket_send_chunk_collection_count (
		struct rrr_socket_send_chunk_collection *chunks
);
int rrr_socket_send_chunk_collection_push (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		void **data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority
);
int rrr_socket_send_chunk_collection_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		const void *data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority
);
int rrr_socket_send_chunk_collection_push_const_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		const void *data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
);
int rrr_socket_send_chunk_collection_push_const_with_address_and_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority,
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
		void (*callback)(const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);
int rrr_socket_send_chunk_collection_send_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		int (*callback)(rrr_biglength *written_bytes, const struct sockaddr *addr, socklen_t addr_len, const void *data, rrr_biglength data_size, void *arg),
		void *callback_arg
);
void rrr_socket_send_chunk_collection_iterate (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(int *do_remove, const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);

#endif /* RRR_SOCKET_SEND_CHUNK_H */
