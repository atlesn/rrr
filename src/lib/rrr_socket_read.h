/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SOCKET_READ_H
#define RRR_SOCKET_READ_H

#include <sys/socket.h>
#include <stdio.h>
#include <inttypes.h>

#include "linked_list.h"

struct rrr_socket_read_session {
	/* A packet read action might be temporarily paused if the payload
	 * is large (exceeds step_size_limit is < 0). It will resume in the next process tick.
	 *
	 * When rx_buf_wpos reaches target_size, the retrieval is complete and the processing
	 * of the packet may begin. */

	RRR_LINKED_LIST_NODE(struct rrr_socket_read_session);

	struct sockaddr src_addr;
	socklen_t src_addr_len;
	uint64_t last_read_time;

	ssize_t target_size;

	char *rx_buf_ptr;
	ssize_t rx_buf_size;
	ssize_t rx_buf_wpos;

	char *rx_overshoot;
	ssize_t rx_overshoot_size;

	int read_complete;
};

struct rrr_socket_read_session_collection {
	RRR_LINKED_LIST_HEAD(struct rrr_socket_read_session);
};

void rrr_socket_read_session_collection_init (
		struct rrr_socket_read_session_collection *collection
);
void rrr_socket_read_session_collection_destroy (
		struct rrr_socket_read_session_collection *collection
);
int rrr_socket_read_message (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
);

#endif /* RRR_SOCKET_READ_H */
