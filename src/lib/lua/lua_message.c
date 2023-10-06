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

#include "lua_message.h"
#include "lua_common.h"

#include "../allocator.h"
#include "../log.h"

struct rrr_lua_message {
	int usercount;
};

int rrr_lua_message_new (struct rrr_lua_message **result) {
	int ret = 0;

	struct rrr_lua_message *message;

	if ((message = rrr_allocate_zero(sizeof(*message))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	message->usercount = 1;

	*result = message;

	out:
	return ret;
}

void rrr_lua_message_decref (struct rrr_lua_message *message) {
	if (--message->usercount > 0)
		return;
	assert(message->usercount == 0);
	rrr_free(message);
}

static int __rrr_lua_message_f_finalize(lua_State *L) {
	struct rrr_lua_message *message;

	lua_pushliteral(L, "_rrr_message");
	lua_gettable(L, -2);
	assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);

	message = lua_topointer(L, -1);
	lua_pop(L, 1);
	rrr_free(message);

	return 1;
}

static int __rrr_lua_message_f_new(lua_State *L) {
	static const luaL_Reg f_meta[] = {
		{"__gc", __rrr_lua_message_f_finalize},
		{NULL, NULL}
	};

	static const luaL_Reg f[] = {
		{NULL, NULL}
	};

	int results = 0;

	struct rrr_lua_message *message;

	if (rrr_lua_message_new(&message) != 0) {
		luaL_error(L, "Failed to create internal message in %s\n",
			__func__);
		return 0;
	}

	luaL_newlib(L, f);
	results++;

	lua_pushliteral(L, "_rrr_message");
	lua_pushlightuserdata(L, message);
	lua_settable(L, -3);

	printf("new %p\n", message);

	luaL_newlib(L, f_meta);
	lua_setmetatable(L, -2);

	lua_pushliteral(L, "data");
	lua_pushliteral(L, "");
	lua_settable(L, -3);

	return results;
}

void rrr_lua_message_library_register (
		struct rrr_lua *target
) {
	static const luaL_Reg f[] = {
		{"new", __rrr_lua_message_f_new},
		{NULL, NULL}
	};

	lua_getglobal(target->L, "RRR");
	assert(lua_type(target->L, -1) == LUA_TTABLE);

	lua_pushliteral(target->L, "Message");
	luaL_newlib(target->L, f);
	lua_settable(target->L, -3);

	lua_pop(target->L, 1);
}
