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

#ifndef RRR_LUA_H
#define RRR_LUA_H

#include <stddef.h>

#include "lua_types.h"

struct rrr_lua;

int rrr_lua_new(struct rrr_lua **result);
void rrr_lua_destroy(struct rrr_lua *lua);
void rrr_lua_set_precision_loss_warnings (
		struct rrr_lua *lua,
		int enable
);
int rrr_lua_execute_snippet (
		struct rrr_lua *lua,
		const char *snippet,
		size_t size
);
void rrr_lua_pushint (
		struct rrr_lua *lua,
		rrr_lua_int i
);
int rrr_lua_call (
		struct rrr_lua *lua,
		const char *function,
		int nargs
);
void rrr_lua_assert_empty_stack (
		struct rrr_lua *lua
);
void rrr_lua_dump_and_clear_stack (
		struct rrr_lua *lua
);

#endif /* RRR_LUA_H */
