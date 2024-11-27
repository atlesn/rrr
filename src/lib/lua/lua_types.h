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

#ifndef RRR_LUA_TYPES_H
#define RRR_LUA_TYPES_H

#include "../util/macro_utils.h"

#define PRIrrrluai RRR_QUOTE_MACRO(RRR_LUA_INTTYPE_PRI)

typedef RRR_LUA_INTTYPE rrr_lua_int;

#endif /* RRR_LUA_TYPES_H */
