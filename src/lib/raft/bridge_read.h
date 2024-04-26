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

#ifndef RRR_RAFT_BRIDGE_READ_H
#define RRR_RAFT_BRIDGE_READ_H

#include <stdio.h>
#include <stddef.h>

ssize_t rrr_raft_bridge_read (
		struct rrr_raft_bridge *bridge,
		raft_id server_id,
		const char *server_address,
		const char *data,
		size_t data_size
);

#endif /* RRR_RAFT_BRIDGE_READ_H */
