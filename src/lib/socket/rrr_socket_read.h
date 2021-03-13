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

#ifndef RRR_SOCKET_READ_H
#define RRR_SOCKET_READ_H

#include <stdio.h>
#include <inttypes.h>
#include <sys/socket.h>

#include "../util/linked_list.h"
#include "../messages/msg.h"

struct rrr_read_session;
struct rrr_read_session_collection;

int rrr_socket_read (
		char *buf,
		ssize_t *read_bytes,
		int fd,
		ssize_t read_step_max_size,
		struct sockaddr *src_addr,
		socklen_t *src_addr_len,
		int flags
);
int rrr_socket_read_message_default (
		uint64_t *bytes_read,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		ssize_t read_max,
		uint64_t ratelimit_interval_us,
		ssize_t ratelimit_max_bytes,
		int socket_read_flags,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
);
int rrr_socket_read_message_split_callbacks (
		uint64_t *bytes_read,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags_socket,
		uint64_t ratelimit_interval_us,
		ssize_t ratelimit_max_bytes,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg1,
		void *callback_arg2
	
);

#endif /* RRR_SOCKET_READ_H */
