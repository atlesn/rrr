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

/*
 * IMPORTANT !
 *
 * The Linux-style eventfd is disabled due to hangs in
 * the following situation:
 *
 * - A Cmodule worker processes messages and generates one
 *   output message for each message received
 *
 * - A lot of messages arrive simultaneously filling up the
 *   mmap channels in both directions
 *
 * - If Linux eventfd is used, the amount of passes can exceed
 *   the total capacity of the mmap channels > 1024.
 *
 * - The event subsystem cannot stop processing of the current
 *   event if more of the amount is remaining thus causing hang
 *   when the cmodule tries to write to the mmap channel which
 *   is full. It will also remain full since the read from fork
 *   event is not being run.
 *
 * - With the pipe method however, amounts are only in small
 *   doses < 256 allowing all the events to be interleaved.
 *
 */
#undef RRR_HAVE_EVENTFD

#include <stdint.h>

// Debug with separate counter which is printed out
// #define RRR_SOCKET_EVENTFD_DEBUG 1

#ifdef RRR_SOCKET_EVENTFD_DEBUG
#	include <pthread.h>
#endif /* RRR_SOCKET_EVENTFD_DEBUG */

struct rrr_socket_eventfd {
#ifdef RRR_SOCKET_EVENTFD_DEBUG
	pthread_mutex_t *lock;
	int64_t *count;
#endif
#ifdef RRR_HAVE_EVENTFD
	int fd;
#else
	int fds[2];
#endif
};

#ifdef RRR_HAVE_EVENTFD
#	define RRR_SOCKET_EVENTFD_INITIALIZED(eventfd) \
		((eventfd)->fd > 0)
#	define RRR_SOCKET_EVENTFD_READ_FD(eventfd) \
		((eventfd)->fd)
#	define RRR_SOCKET_EVENTFD_WRITE_FD(eventfd) \
		((eventfd)->fd)
#else
#	define RRR_SOCKET_EVENTFD_INITIALIZED(eventfd) \
		((eventfd)->fds[0] > 0)
#	define RRR_SOCKET_EVENTFD_READ_FD(eventfd) \
		((eventfd)->fds[0])
#	define RRR_SOCKET_EVENTFD_WRITE_FD(eventfd) \
		((eventfd)->fds[1])
#endif

void rrr_socket_eventfd_cleanup (
		struct rrr_socket_eventfd *eventfd
);
int rrr_socket_eventfd_init (
		struct rrr_socket_eventfd *eventfd
);
int rrr_socket_eventfd_write (
		struct rrr_socket_eventfd *eventfd,
		uint8_t count
);
int rrr_socket_eventfd_read (
		uint64_t *count,
		struct rrr_socket_eventfd *eventfd
);
#ifdef RRR_SOCKET_EVENTFD_DEBUG
void rrr_socket_eventfd_count (
		int64_t *count,
		struct rrr_socket_eventfd *eventfd
);
#endif

#endif /* RRR_SOCKET_EVENTFD_H */
