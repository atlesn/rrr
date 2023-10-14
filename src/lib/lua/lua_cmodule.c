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

#include <assert.h>

#include "lua_common.h"
#include "../cmodule/cmodule_worker.h"

void rrr_lua_cmodule_library_register (
		struct rrr_lua *target,
		struct rrr_cmodule_worker *worker
) {
	lua_State *L = target->L;

	static const luaL_Reg f[] = {
		{NULL, NULL}
	};

	lua_getglobal(L, RRR_LUA_KEY);
	assert(lua_istable(L, -1));
	lua_getmetatable(L, -1);
	assert(lua_istable(L, -1));
	lua_pushstring(L, RRR_LUA_META_KEY_CMODULE);
	lua_pushlightuserdata(L, worker);
	lua_settable(L, -3);
	lua_pop(L, 2);
}
