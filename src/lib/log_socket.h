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

int rrr_log_socket_bind (void);
int rrr_log_socket_start_listen (
		struct rrr_event_queue *queue
);
int rrr_log_socket_thread_start_say (
		struct rrr_event_queue *queue
);
int rrr_log_socket_after_fork (void);
void rrr_log_socket_cleanup (void);
int rrr_log_socket_fds_get (
		int **log_fds,
		size_t *log_fds_count
);

#endif /* RRR_LOG_SOCKET_H */
