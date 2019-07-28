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

int rrr_socket_with_lock_do (int (*callback)(void *arg), void *arg);
int rrr_socket_accept (int fd_in, struct sockaddr *addr, socklen_t *__restrict addr_len, const char *creator);
int rrr_socket_mkstemp (char *filename, const char *creator);
int rrr_socket (int domain, int type, int protocol, const char *creator);
int rrr_socket_close (int fd);
int rrr_socket_close_all_except (int fd);
int rrr_socket_close_all (void);

#endif /* RRR_SOCKET_H */
