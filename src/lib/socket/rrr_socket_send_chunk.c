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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../log.h"
#include "rrr_socket_send_chunk.h"
#include "rrr_socket.h"
#include "../util/macro_utils.h"

struct rrr_socket_send_chunk {
	RRR_LL_NODE(struct rrr_socket_send_chunk);
	void *data;
	ssize_t data_size;
	ssize_t data_pos;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	void *private_data;
	void (*private_data_destroy)(void *private_data);
};

static void __rrr_socket_send_chunk_destroy (
		struct rrr_socket_send_chunk *chunk
) {
	if (chunk->private_data) {
		chunk->private_data_destroy(chunk->private_data);
	}
	RRR_FREE_IF_NOT_NULL(chunk->data);
	free(chunk);
}

void rrr_socket_send_chunk_collection_clear (
		struct rrr_socket_send_chunk_collection *target
) {
	RRR_LL_DESTROY(target, struct rrr_socket_send_chunk, __rrr_socket_send_chunk_destroy(node));
}

void rrr_socket_send_chunk_collection_clear_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
) {
	RRR_LL_ITERATE_BEGIN(chunks, struct rrr_socket_send_chunk);
		callback(node->data, node->data_size, node->data_pos, node->private_data, callback_arg);
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(chunks, 0; __rrr_socket_send_chunk_destroy(node));
}

static int __rrr_socket_send_chunk_collection_push (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void **data,
		ssize_t data_size,
		int do_prepend,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	int ret = 0;

	if (data_size < 0) {
		RRR_BUG("BUG: Data size was < 0 in __rrr_socket_send_chunk_collection_push\n");
	}

	struct rrr_socket_send_chunk *new_chunk = NULL;

	*send_chunk_count = RRR_LL_COUNT(target);

	if ((new_chunk = malloc(sizeof(*new_chunk))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_send_chunk_collection_push\n");
		ret = 1;
		goto out;
	}

	memset(new_chunk, '\0', sizeof(*new_chunk));

	if (private_data_new) {
		private_data_new(&new_chunk->private_data, private_data_arg);
		new_chunk->private_data_destroy = private_data_destroy;
	}

	if (addr_len > 0) {
		memcpy(&new_chunk->addr, addr, addr_len);
		new_chunk->addr_len = addr_len;
	}

	new_chunk->data_size = data_size;
	new_chunk->data = *data;
	*data = NULL;

	if (do_prepend) {
		printf("Prepend\n");
		RRR_LL_UNSHIFT(target, new_chunk);
	}
	else {
		RRR_LL_APPEND(target, new_chunk);
	}

	*send_chunk_count = RRR_LL_COUNT(target);

	out:
	return ret;
}

int rrr_socket_send_chunk_collection_push (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		void **data,
		ssize_t data_size
) {
	return __rrr_socket_send_chunk_collection_push (
			send_chunk_count,
			target,
			NULL,
			0,
			data,
			data_size,
			0, // Is not urgent, append
			NULL,
			NULL,
			NULL
	);
}

int rrr_socket_send_chunk_collection_push_urgent (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		void **data,
		ssize_t data_size
) {
	return __rrr_socket_send_chunk_collection_push (
			send_chunk_count,
			target,
			NULL,
			0,
			data,
			data_size,
			1, // Is urgent, prepend
			NULL,
			NULL,
			NULL
	);
}

static int __rrr_socket_send_chunk_collection_push_const (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		ssize_t data_size,
		int do_prepend,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	int ret = 0;

	void *data_copy = malloc(data_size);
	if (data_copy == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_send_chunk_collection_push_const\n");
		ret = 1;
		goto out;
	}

	memcpy(data_copy, data, data_size);

	ret = __rrr_socket_send_chunk_collection_push (
			send_chunk_count,
			target,
			addr,
			addr_len,
			&data_copy,
			data_size,
			do_prepend,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);

	out:
	RRR_FREE_IF_NOT_NULL(data_copy);
	return ret;
}

int rrr_socket_send_chunk_collection_push_const (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const void *data,
		ssize_t data_size
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			target,
			NULL,
			0,
			data,
			data_size,
			0, // Is not urgent, append
			NULL,
			NULL,
			NULL
	);
}

int rrr_socket_send_chunk_collection_push_const_urgent (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const void *data,
		ssize_t data_size
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			target,
			NULL,
			0,
			data,
			data_size,
			1, // Is urgent, prepend
			NULL,
			NULL,
			NULL
	);
}

int rrr_socket_send_chunk_collection_push_const_with_private_data (
		int *send_chunk_count,
		struct rrr_socket_send_chunk_collection *target,
		const void *data,
		ssize_t data_size,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			target,
			NULL,
			0,
			data,
			data_size,
			0,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);
}

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
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			target,
			addr,
			addr_len,
			data,
			data_size,
			0,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);
}

static int __rrr_socket_send_chunk_collection_send (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd,
		void (*notify_callback)(const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *notify_callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(chunks, struct rrr_socket_send_chunk);
		RRR_DBG_7("Chunk non-blocking send on fd %i, pos/size %lld/%lld\n",
			fd,  (long long int) node->data_pos, (long long int) node->data_size);

		ssize_t written_bytes = 0;
		if ((ret = rrr_socket_sendto_nonblock_check_retry (
			&written_bytes,
			fd,
			node->data + node->data_pos,
			node->data_size - node->data_pos,
			(const struct sockaddr *) &node->addr,
			node->addr_len
		)) != 0) {
			if (ret == RRR_SOCKET_WRITE_INCOMPLETE) {
				node->data_pos += written_bytes;
			}
			goto out;
		}
		if (notify_callback) {
			notify_callback(node->data, node->data_size, node->data_pos, node->private_data, notify_callback_arg);
		}
		RRR_LL_ITERATE_SET_DESTROY(); // Chunk complete
	RRR_LL_ITERATE_END_CHECK_DESTROY(chunks, 0; __rrr_socket_send_chunk_destroy(node));

	out:
	return ret;
}

int rrr_socket_send_chunk_collection_send (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd
) {
	return __rrr_socket_send_chunk_collection_send (
			chunks,
			fd,
			NULL,
			NULL
	);
}

int rrr_socket_send_chunk_collection_send_and_notify (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd,
		void (*callback)(const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
) {
	return __rrr_socket_send_chunk_collection_send (
			chunks,
			fd,
			callback,
			callback_arg
	);
}

int rrr_socket_send_chunk_collection_send_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		int (*callback)(ssize_t *written_bytes, const struct sockaddr *addr, socklen_t addr_len, const void *data, ssize_t data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int max = 10;
	RRR_LL_ITERATE_BEGIN(chunks, struct rrr_socket_send_chunk);
		RRR_DBG_7("Chunk send with callback pos/size %lld/%lld\n",
			(long long int) node->data_pos, (long long int) node->data_size);

		ssize_t written_bytes = 0;

		ret = callback (
				&written_bytes,
				(const struct sockaddr *) &node->addr,
				node->addr_len,
				node->data + node->data_pos,
				node->data_size - node->data_pos,
				callback_arg
		) &~ RRR_SOCKET_WRITE_INCOMPLETE;

		node->data_pos += written_bytes;
		if (node->data_pos > node->data_size) {
			RRR_BUG("BUG: Too many bytes written in rrr_socket_send_chunk_collection_send_with_callback\n");
		}
		else if (node->data_pos == node->data_size) {
			RRR_LL_ITERATE_SET_DESTROY(); // Chunk complete
		}

		if (ret != 0 || written_bytes == 0 || max-- == 0) {
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(chunks, 0; __rrr_socket_send_chunk_destroy(node));

	return ret;
}

void rrr_socket_send_chunk_collection_iterate (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(int *do_remove, const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
) {
	RRR_LL_ITERATE_BEGIN(chunks, struct rrr_socket_send_chunk);
		int do_remove = 0;
		callback(&do_remove, node->data, node->data_size, node->data_pos, node->private_data, callback_arg);
		if (do_remove) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(chunks, 0; __rrr_socket_send_chunk_destroy(node));
}
