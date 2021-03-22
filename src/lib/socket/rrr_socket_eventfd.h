/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SOCKET_EVENTFD_H
#define RRR_SOCKET_EVENTFD_H

#include <stdint.h>

struct rrr_socket_eventfd {
	int fds[2];
	uint64_t count;
	int notify_pending;
};

#define RRR_SOCKET_EVENTFD_INITIALIZED(eventfd) \
	((eventfd)->fds[0] > 0)

#define RRR_SOCKET_EVENTFD_READ_FD(eventfd) \
	((eventfd)->fds[0])

#define RRR_SOCKET_EVENTFD_WRITE_FD(eventfd) \
	((eventfd)->fds[1])

void rrr_socket_eventfd_cleanup (
		struct rrr_socket_eventfd *eventfd
);
int rrr_socket_eventfd_init (
		struct rrr_socket_eventfd *eventfd
);
int rrr_socket_eventfd_write (
		struct rrr_socket_eventfd *eventfd,
		uint64_t count
);
int rrr_socket_eventfd_read (
		uint64_t *count,
		struct rrr_socket_eventfd *eventfd
);

#endif /* RRR_SOCKET_EVENTFD_H */
