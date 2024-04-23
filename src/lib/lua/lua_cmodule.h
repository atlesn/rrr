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

#ifndef RRR_LUA_CMODULE_H
#define RRR_LUA_CMODULE_H

struct rrr_lua;
struct rrr_cmodule_worker;

int rrr_lua_cmodule_push_new (
		struct rrr_lua *target
);
void rrr_lua_cmodule_library_register (
		struct rrr_lua *target,
		struct rrr_cmodule_worker *cmodule
);

#endif /* RRR_LUA_CMODULE_H */
