/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_LUA_MESSAGE_H
#define RRR_LUA_MESSAGE_H

#include <sys/socket.h>

#include "../rrr_inttypes.h"
#include "../rrr_types.h"

struct rrr_lua;
struct rrr_lua_message;
struct rrr_array;

int rrr_lua_message_push_new (
		struct rrr_lua *target
);
int rrr_lua_message_push_new_data (
		struct rrr_lua *target,
		rrr_u64 timestamp,
		rrr_u8 type,
		const char *topic,
		rrr_length topic_len,
		const struct sockaddr *ip_addr,
		socklen_t ip_addr_len,
		uint8_t protocol,
		const char *data,
		rrr_length data_length
);
int rrr_lua_message_push_new_array (
		struct rrr_lua *target,
		rrr_u64 timestamp,
		rrr_u8 type,
		const char *topic,
		rrr_length topic_len,
		const struct sockaddr *ip_addr,
		socklen_t ip_addr_len,
		uint8_t protocol,
		struct rrr_array *array_victim
);
void rrr_lua_message_library_register (
		struct rrr_lua *target
);

#endif /* RRR_LUA_MESSAGE_H */
