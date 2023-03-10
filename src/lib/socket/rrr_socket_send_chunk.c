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
#include "../allocator.h"
#include "rrr_socket_send_chunk.h"
#include "rrr_socket.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"

struct rrr_socket_send_chunk {
	RRR_LL_NODE(struct rrr_socket_send_chunk);
	void *data;
	rrr_biglength data_size;
	rrr_biglength data_pos;
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
	rrr_free(chunk);
}

#define RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN() \
	do { for (int i = 0; i < RRR_SOCKET_SEND_CHUNK_PRIORITY_COUNT; i++) { \
		struct rrr_socket_send_chunk_collection_list *list = &chunks->chunk_lists[i]

#define RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END() \
	}} while(0)

void rrr_socket_send_chunk_collection_clear (
		struct rrr_socket_send_chunk_collection *chunks
) {
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN();
		RRR_LL_DESTROY(list, struct rrr_socket_send_chunk, __rrr_socket_send_chunk_destroy(node));
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END();
}

void rrr_socket_send_chunk_collection_clear_with_callback (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
) {
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN();
		RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_send_chunk);
			callback(node->data, node->data_size, node->data_pos, node->private_data, callback_arg);
			RRR_LL_ITERATE_SET_DESTROY();
		RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; __rrr_socket_send_chunk_destroy(node));
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END();
}

rrr_length rrr_socket_send_chunk_collection_count (
		struct rrr_socket_send_chunk_collection *chunks
) {
	rrr_length count = 0;
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN();
		rrr_length_add_bug (&count, rrr_length_from_slength_bug_const(RRR_LL_COUNT(list)));
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END();
	return count;
}

static int __rrr_socket_send_chunk_collection_push (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void **data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	int ret = 0;

	struct rrr_socket_send_chunk *new_chunk = NULL;

	if ((new_chunk = rrr_allocate(sizeof(*new_chunk))) == NULL) {
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

	RRR_LL_APPEND(&chunks->chunk_lists[priority], new_chunk);

	*send_chunk_count = rrr_socket_send_chunk_collection_count(chunks);

	out:
	return ret;
}

int rrr_socket_send_chunk_collection_push (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		void **data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority
) {
	return __rrr_socket_send_chunk_collection_push (
			send_chunk_count,
			chunks,
			NULL,
			0,
			data,
			data_size,
			priority,
			NULL,
			NULL,
			NULL
	);
}

int rrr_socket_send_chunk_collection_push_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		void **data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	return __rrr_socket_send_chunk_collection_push (
			send_chunk_count,
			chunks,
			NULL,
			0,
			data,
			data_size,
			priority,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);
}

static int __rrr_socket_send_chunk_collection_push_const (
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
) {
	int ret = 0;

	void *data_copy = NULL;

	RRR_SIZE_CHECK(data_size,"While adding to send chunk collection",ret = 1; goto out);

	if ((data_copy = rrr_allocate(data_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_send_chunk_collection_push_const\n");
		ret = 1;
		goto out;
	}

	rrr_memcpy(data_copy, data, data_size);

	ret = __rrr_socket_send_chunk_collection_push (
			send_chunk_count,
			chunks,
			addr,
			addr_len,
			&data_copy,
			data_size,
			priority,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);

	out:
	RRR_FREE_IF_NOT_NULL(data_copy);
	return ret;
}

int rrr_socket_send_chunk_collection_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		const void *data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			chunks,
			NULL,
			0,
			data,
			data_size,
			priority,
			NULL,
			NULL,
			NULL
	);
}

int rrr_socket_send_chunk_collection_push_const_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_send_chunk_collection *chunks,
		const void *data,
		rrr_biglength data_size,
		enum rrr_socket_send_chunk_priority priority,
		void (*private_data_new)(void **private_data, void *arg),
		void *private_data_arg,
		void (*private_data_destroy)(void *private_data)
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			chunks,
			NULL,
			0,
			data,
			data_size,
			priority,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);
}

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
) {
	return __rrr_socket_send_chunk_collection_push_const (
			send_chunk_count,
			chunks,
			addr,
			addr_len,
			data,
			data_size,
			priority,
			private_data_new,
			private_data_arg,
			private_data_destroy
	);
}

static int __rrr_socket_send_chunk_collection_send (
		struct rrr_socket_send_chunk_collection *chunks,
		int fd,
		void (*notify_callback)(const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *notify_callback_arg
) {
	int ret = 0;

	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN();
		RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_send_chunk);
			RRR_DBG_7("Chunk non-blocking sendto on fd %i, pos/size %lld/%lld\n",
				fd,  (long long int) node->data_pos, (long long int) node->data_size);

			rrr_biglength written_bytes = 0;
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
		RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; __rrr_socket_send_chunk_destroy(node));
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END();

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
		void (*callback)(const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
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
		int (*callback)(rrr_biglength *written_bytes, const struct sockaddr *addr, socklen_t addr_len, const void *data, rrr_biglength data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int max = 10;
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN();
		RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_send_chunk);
			RRR_DBG_7("Chunk send with callback pos/size %lld/%lld\n",
				(long long int) node->data_pos, (long long int) node->data_size);

			rrr_biglength written_bytes = 0;

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
		RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; __rrr_socket_send_chunk_destroy(node));
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END();

	return ret;
}

void rrr_socket_send_chunk_collection_iterate (
		struct rrr_socket_send_chunk_collection *chunks,
		void (*callback)(int *do_remove, const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
) {
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_BEGIN();
		RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_send_chunk);
			int do_remove = 0;
			callback(&do_remove, node->data, node->data_size, node->data_pos, node->private_data, callback_arg);
			if (do_remove) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; __rrr_socket_send_chunk_destroy(node));
	RRR_SOCKET_SEND_CHUNK_LISTS_ITERATE_END();
}
