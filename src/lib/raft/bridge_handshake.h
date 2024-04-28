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

#ifndef RRR_RAFT_BRIDGE_HANDSHAKE_H
#define RRR_RAFT_BRIDGE_HANDSHAKE_H

#include <stdio.h>
#include <stddef.h>

ssize_t rrr_raft_bridge_handshake_read (
		raft_id *server_id,
		char **server_address,
		size_t *server_address_length,
		struct rrr_raft_bridge *bridge,
		const char *data,
		size_t data_size
);
int rrr_raft_handshake_write (
		char **handshake,
		size_t *handshake_size,
		struct rrr_raft_bridge *bridge
);

#endif /* RRR_RAFT_BRIDGE_HANDSHAKE_H */
