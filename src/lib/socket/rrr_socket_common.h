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

#ifndef RRR_SOCKET_COMMON_H
#define RRR_SOCKET_COMMON_H

struct rrr_array;
struct rrr_array_tree;
struct rrr_msg;
struct rrr_msg_msg;
struct rrr_read_session;
struct rrr_read_session_collection;

struct rrr_socket_common_in_flight_counter {
	int in_flight_to_remote_count;
	int not_acknowledged_count;
};

int rrr_socket_common_receive_array_tree (
		uint64_t *bytes_read,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int socket_read_flags,
		struct rrr_array *array_final,
		const struct rrr_array_tree *tree,
		int do_sync_byte_by_byte,
		unsigned int message_max_size,
		int (*callback)(struct rrr_read_session *read_session, struct rrr_array *array_final, void *arg),
		void *arg
);
int rrr_socket_common_prepare_and_send_msg_blocking (
		struct rrr_msg *msg,
		int fd,
		struct rrr_socket_common_in_flight_counter *in_flight
);

#endif /* RRR_SOCKET_COMMON_H */
