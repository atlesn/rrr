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

#ifndef RRR_READ_SESSION_H
#define RRR_READ_SESSION_H

#include <stdint.h>
#include <stdlib.h>

#include "linked_list.h"

//struct rrr_socket_client;

struct rrr_read_session {
	/* A packet read action might be temporarily paused if the payload
	 * is large (exceeds step_size_limit is < 0). It will resume in the next process tick.
	 *
	 * When rx_buf_wpos reaches target_size, the retrieval is complete and the processing
	 * of the packet may begin. */

	RRR_LL_NODE(struct rrr_read_session);

	// These are set on every read before calling complete callback. client will be NULL
	// if client collection is not being used.
	int fd;
//	struct rrr_socket_client *client;
	uint64_t last_read_time;

	// Used to distinguish clients from each other
	struct sockaddr src_addr;
	socklen_t src_addr_len;

	/* Read untill target size is reached (default) or set to read until
	 * connection is closed. */
	int read_complete_method;
	ssize_t target_size;

	// Populated by socket read function (contain all read data)
	char *rx_buf_ptr;
	ssize_t rx_buf_size;
	ssize_t rx_buf_wpos;

	// Populated by get target length-function if bytes are to be skipped at beginning of buffer
	ssize_t rx_buf_skip;

	char *rx_overshoot;
	ssize_t rx_overshoot_size;

	int read_complete;
};

static inline int rrr_socket_read_session_cleanup (
		struct rrr_read_session *read_session
) {
	RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
	RRR_FREE_IF_NOT_NULL(read_session->rx_overshoot);
	return 0;
}

static inline int rrr_socket_read_session_destroy (
		struct rrr_read_session *read_session
) {
	rrr_socket_read_session_cleanup(read_session);
	free(read_session);
	return 0;
}

#endif /* RRR_READ_SESSION_H */
