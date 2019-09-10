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

#ifndef RRR_SOCKET_H
#define RRR_SOCKET_H

#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>

#include "linked_list.h"
#include "rrr_socket_msg.h"

#define RRR_SOCKET_OK				0
#define RRR_SOCKET_HARD_ERROR		1
#define RRR_SOCKET_SOFT_ERROR		2
#define RRR_SOCKET_READ_INCOMPLETE	3

#define RRR_SOCKET_READ_TIMEOUT		30

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

struct rrr_socket_read_session;

void rrr_socket_msg_populate_head (
		struct rrr_socket_msg *message,
		vl_u16 type,
		vl_u32 msg_size,
		vl_u64 value
);
void rrr_socket_msg_checksum_and_to_network_endian (
		struct rrr_socket_msg *message
);
void rrr_socket_msg_head_to_host (struct rrr_socket_msg *message);
int rrr_socket_msg_get_packet_target_size_and_checksum (
		ssize_t *target_size,
		struct rrr_socket_msg *socket_msg,
		ssize_t buf_size
);
int rrr_socket_msg_checksum_check (
		struct rrr_socket_msg *message,
		ssize_t data_size
);
int rrr_socket_msg_head_validate (struct rrr_socket_msg *message);
int rrr_socket_with_lock_do (
		int (*callback)(void *arg),
		void *arg
);
int rrr_socket_accept (
		int fd_in,
		struct sockaddr *addr,
		socklen_t *__restrict addr_len,
		const char *creator
);
int rrr_socket_mkstemp (
		char *filename,
		const char *creator
);
int rrr_socket (
		int domain,
		int type,
		int protocol,
		const char *creator
);
int rrr_socket_close (int fd);
int rrr_socket_close_all_except (int fd);
int rrr_socket_close_all (void);
void rrr_socket_read_session_collection_init (
		struct rrr_socket_read_session_collection *collection
);
void rrr_socket_read_session_collection_destroy (
		struct rrr_socket_read_session_collection *collection
);
int rrr_socket_read_session_get_target_length_from_message_and_checksum (
		struct rrr_socket_read_session *read_session,
		void *arg
);
int rrr_socket_read_message (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
);
#endif /* RRR_SOCKET_H */
