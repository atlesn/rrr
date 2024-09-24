/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_LOG_SOCKET_H
#define RRR_LOG_SOCKET_H

#include "socket/rrr_socket.h"

struct rrr_event_queue *queue;
struct rrr_socket_client_collection;

struct rrr_log_socket {
	char *listen_filename;
	int listen_fd;
	int connected_fd;
	struct rrr_socket_options connected_fd_options;
	struct rrr_socket_client_collection *client_collection;
};

int rrr_log_socket_bind (
		struct rrr_log_socket *target
);
int rrr_log_socket_start (
		struct rrr_log_socket *target,
		struct rrr_event_queue *queue
);
int rrr_log_socket_after_fork (
		struct rrr_log_socket *log_socket
);
void rrr_log_socket_cleanup (
		struct rrr_log_socket *log_socket
);


#endif /* RRR_LOG_SOCKET_H */
