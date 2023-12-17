/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SOCKET_GRAYLIST_H
#define RRR_SOCKET_GRAYLIST_H

#include <stdint.h>
#include <sys/socket.h>

#include "../util/linked_list.h"

struct rrr_socket_graylist;
struct rrr_socket_graylist_entry;

int rrr_socket_graylist_exists (
		struct rrr_socket_graylist *list,
		const struct sockaddr *addr,
		socklen_t len
);
int rrr_socket_graylist_push (
		struct rrr_socket_graylist *target,
		const struct sockaddr *addr,
		socklen_t len,
		uint64_t graylist_period_us
);
void rrr_socket_graylist_destroy (
		struct rrr_socket_graylist *target
);
void rrr_socket_graylist_destroy_void (
		void *target
);
int rrr_socket_graylist_new (
		struct rrr_socket_graylist **target
);

#endif /* RRR_SOCKET_GRAYLIST_H */
