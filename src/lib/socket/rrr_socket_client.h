/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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
#include <stdio.h>

#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "rrr_socket_send_chunk.h"

#include "../read.h"
#include "../util/linked_list.h"

struct rrr_socket_client_collection;
struct rrr_event_queue;
struct rrr_read_session;
struct rrr_array;

int rrr_socket_client_collection_new (
		struct rrr_socket_client_collection **target,
		const char *creator
);
void rrr_socket_client_collection_set_connect_timeout (
		struct rrr_socket_client_collection *collection,
		uint64_t connect_timeout_us
);
void rrr_socket_client_collection_destroy (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
);
void rrr_socket_client_collection_send_chunk_iterate (
		struct rrr_socket_client_collection *collection,
		void (*callback)(int *do_remove, const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);
int rrr_socket_client_collection_send_push_const_multicast (
		struct rrr_socket_client_collection *collection,
		const void *data,
		ssize_t size
);
int rrr_socket_client_collection_send_push (
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		ssize_t data_size
);
int rrr_socket_client_collection_send_push_const (
		struct rrr_socket_client_collection *collection,
		int fd,
		const void *data,
		ssize_t data_size
);
int rrr_socket_client_collection_send_push_const_by_address_connect_as_needed (
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		ssize_t size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
);
int rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
		struct rrr_socket_client_collection *collection,
		const char *addr_string,
		const void *data,
		ssize_t size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*resolve_callback)(
				size_t *address_count,
				struct sockaddr ***addresses,
				socklen_t **address_lengths,
				void *callback_data
		),
		void *resolve_callback_data,
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
);
int rrr_socket_client_collection_sendto_push_const (
		struct rrr_socket_client_collection *collection,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		ssize_t size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
);
int rrr_socket_client_collection_listen_fd_push (
		struct rrr_socket_client_collection *collection,
		int fd
);
int rrr_socket_client_collection_connected_fd_push (
		struct rrr_socket_client_collection *collection,
		int fd
);
void rrr_socket_client_collection_send_notify_setup (
		struct rrr_socket_client_collection *collection,
		void (*callback)(int was_sent, const void *data, ssize_t data_size, ssize_t data_pos, void *chunk_private_data, void *callback_arg),
		void *callback_arg
);
void rrr_socket_client_collection_event_setup (
		struct rrr_socket_client_collection *collection,
		struct rrr_event_queue *queue,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		ssize_t read_step_max_size,
		int read_flags_socket,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
);
void rrr_socket_client_collection_event_setup_raw (
		struct rrr_socket_client_collection *collection,
		struct rrr_event_queue *queue,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		ssize_t read_step_max_size,
		int read_flags_socket,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *private_data, void *arg),
		void *complete_callback_arg
);
void rrr_socket_client_collection_event_setup_array_tree (
		struct rrr_socket_client_collection *collection,
		struct rrr_event_queue *queue,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int read_flags_socket,
		const struct rrr_array_tree *tree,
		int do_sync_byte_by_byte,
		ssize_t read_step_max_size,
		unsigned int message_max_size,
		int (*array_callback)(struct rrr_read_session *read_session, struct rrr_array *array_final, void *private_data, void *arg),
		void *array_callback_arg
);

#endif /* RRR_SOCKET_CLIENT_H */
