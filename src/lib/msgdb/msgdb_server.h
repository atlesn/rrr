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

#ifndef RRR_MSGDB_SERVER_H
#define RRR_MSGDB_SERVER_H

#include <inttypes.h>

struct rrr_msgdb_server;

int rrr_msgdb_server_new (
		struct rrr_msgdb_server **result,
		const char *directory,
		const char *socket
);
void rrr_msgdb_server_destroy (
		struct rrr_msgdb_server *server
);
void rrr_msgdb_server_destroy_void (
		void *server
);
int rrr_msgdb_server_tick (
		struct rrr_msgdb_server *server
);
uint64_t rrr_msgdb_server_recv_count_get (
		struct rrr_msgdb_server *server
);
int rrr_msgdb_server_dispatch (
		struct rrr_msgdb_server *server,
		int (*periodic_callback)(void *arg),
		void *periodic_callback_arg
);

#endif /* RRR_MSGDB_SERVER_H */
