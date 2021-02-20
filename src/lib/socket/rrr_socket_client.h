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
#include <stdio.h>

#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "rrr_socket_send_chunk.h"

#include "../read.h"
#include "../util/linked_list.h"

struct rrr_socket_client_collection;
struct rrr_event_queue;

int rrr_socket_client_collection_new (
		struct rrr_socket_client_collection **target,
		int listen_fd,
		const char *creator
);
void rrr_socket_client_collection_destroy (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_iterate (
		struct rrr_socket_client_collection *collection,
		int (*callback)(int fd, void *private_data, void *arg),
		void *callback_arg
);
int rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection,
		int (*private_data_new)(void **target, int fd, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
);
int rrr_socket_client_collection_multicast_send_ignore_full_pipe (
		struct rrr_socket_client_collection *collection,
		void *data,
		size_t size
);
int rrr_socket_client_collection_read_raw (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags_socket,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *private_data, void *arg),
		void *complete_callback_arg
);
int rrr_socket_client_collection_read_message (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_max_size,
		int read_flags_socket,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
);
int rrr_socket_client_collection_send_push (
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		ssize_t data_size
);
void rrr_socket_client_collection_send_tick (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_dispatch (
		struct rrr_socket_client_collection *collection,
		struct rrr_event_queue *queue,
		uint64_t periodic_interval_us,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int (*callback_periodic)(void *arg),
		void *callback_periodic_arg,
		ssize_t read_step_max_size,
		int read_flags_socket,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
);
int rrr_socket_client_collection_event_setup (
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

#endif /* RRR_SOCKET_CLIENT_H */
