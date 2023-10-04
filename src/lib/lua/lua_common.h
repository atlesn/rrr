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

#ifndef RRR_LUA_HEADERS_H
#define RRR_LUA_HEADERS_H

#if defined(HAVE_LUA5_4_LUA_H)
#  include <lua5.4/lua.h>
#  include <lua5.4/lauxlib.h>
#  include <lua5.4/lualib.h>
#elif defined(HAVE_LUA5_3_LUA_H)
#  include <lua5.3/lua.h>
#  include <lua5.3/lauxlib.h>
#  include <lua5.3/lualib.h>
#else
#  error "No HAVE_LUA defined"
#endif

struct rrr_lua {
	lua_State *L;
};

#endif /* RRR_LUA_HEADERS_H */
