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

struct rrr_socket_read_session;
struct vl_message;
struct rrr_array;

struct rrr_socket_common_receive_message_callback_data {
	int (*callback)(struct vl_message *message, void *arg);
	void *callback_arg;
};
int rrr_socket_common_receive_message_raw_callback (
		void *data,
		ssize_t data_size,
		struct rrr_socket_common_receive_message_callback_data *callback_data
);
int rrr_socket_common_receive_message_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
);
int rrr_socket_common_get_session_target_length_from_message_and_checksum_raw (
		ssize_t *result,
		void *data,
		ssize_t data_size,
		void *arg
);
int rrr_socket_common_get_session_target_length_from_message_and_checksum (
		struct rrr_socket_read_session *read_session,
		void *arg
);

struct rrr_socket_common_get_session_target_length_from_array_data {
	const struct rrr_array *definition;
};
int rrr_socket_common_get_session_target_length_from_array (
		struct rrr_socket_read_session *read_session,
		void *arg
);
int rrr_socket_common_receive_array (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		int read_method,
		const struct rrr_array *definition,
		int (*callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *arg
);
int rrr_socket_common_receive_socket_msg (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		int read_method,
		int (*callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *arg
);
#endif /* RRR_SOCKET_COMMON_H */
