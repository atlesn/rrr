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

#include "lua.h"
#include "lua_common.h"

#include "../allocator.h"
#include "../log.h"

static void *__rrr_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
	struct rrr_lua *lua = ud;
	(void)(lua);

	if (nsize == 0) {
		rrr_free(ptr);
		return NULL;
	}

	return rrr_reallocate(ptr, osize, nsize);
}

int rrr_lua_new(struct rrr_lua **result) {
	int ret = 0;

	struct rrr_lua *lua;

	if ((lua = rrr_allocate_zero(sizeof(*lua))) == NULL) {
		RRR_MSG_0("Failed to allocate memroy in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((lua->L = lua_newstate(__rrr_lua_alloc, lua)) == NULL) {
		RRR_MSG_0("Failed to open Lua in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	luaL_openlibs(lua->L);

	lua_newtable(lua->L);

	lua_newtable(lua->L);
	lua_pushstring(lua->L, RRR_LUA_META_KEY_LUA);
	lua_pushlightuserdata(lua->L, lua);
	lua_settable(lua->L, -3);
	lua_setmetatable(lua->L, -2);

	lua_setglobal(lua->L, RRR_LUA_KEY);

	*result = lua;

	// iterate and print keys of RRR metadata
	lua_getglobal(lua->L, RRR_LUA_KEY);
	assert(lua_istable(lua->L, -1));
	lua_getmetatable(lua->L, -1);
	assert(lua_istable(lua->L, -1));
	lua_getfield(lua->L, -1, RRR_LUA_META_KEY_LUA);
	assert(lua_islightuserdata(lua->L, -1));
	assert(lua_touserdata(lua->L, -1) == lua);
	lua_pop(lua->L, 1);
	lua_pushnil(lua->L);
	while (lua_next(lua->L, -2) != 0) {
		RRR_DBG_3("RRR metadata key: %s\n", lua_tostring(lua->L, -2));
		lua_pop(lua->L, 1);
	}
	lua_pop(lua->L, 2);

	goto out;
//	out_close_lua:
//		lua_close(lua->L);
	out_free:
		rrr_free(lua);
	out:
		return ret;
}

void rrr_lua_destroy(struct rrr_lua *lua) {
	lua_close(lua->L);
	rrr_free(lua);
}

static void __rrr_lua_error_with_location (
		struct rrr_lua *lua,
		const char *fmt,
		...
) {
	va_list argp;
	va_start(argp, fmt);

	// TODO : Location is not being printed

	luaL_where(lua->L, 1);
	// RRR_MSG_0("At %s:\n", lua_tostring(lua->L, -1));
	lua_pop(lua->L, 1);

	RRR_MSG_0_V(fmt, argp);

	va_end(argp);
}

void rrr_lua_set_precision_loss_warnings (
		struct rrr_lua *lua,
		int enable
) {
	lua->precision_loss_warnings = enable;
}

int rrr_lua_execute_snippet (
		struct rrr_lua *lua,
		const char *snippet,
		size_t size
) {
	int ret = 0;

	const int stack_count = lua_gettop(lua->L);

	if (luaL_loadbuffer(lua->L, snippet, size, "snippet") != 0) {
		goto error;
	}

	if (lua_pcall(lua->L, 0, 1 /* At most 1 result */, 0) != 0) {
		goto error;
	}

	RRR_DBG_3("Top of stack after executing Lua snippet: %s type is %s\n",
		lua_isboolean(lua->L, -1)
			? (lua_toboolean(lua->L, -1) ? "true" : "false")
			: lua_tostring(lua->L, -1),
		lua_typename(lua->L, lua_type(lua->L, -1))
	);

	const int stack_diff = lua_gettop(lua->L) - stack_count;
	assert(stack_diff >= 0);
	lua_pop(lua->L, stack_diff);
	goto out;
	error:
		RRR_MSG_0("Error from Lua while executing snippet: %s\n",
			lua_tostring(lua->L, -1));
		lua_pop(lua->L, 1);
		ret = 1;
	out:
		return ret;
}

void rrr_lua_pushint (
		struct rrr_lua *lua,
		rrr_lua_int i
) {
	RRR_ASSERT(sizeof(i) == sizeof(lua_Integer),size_of_lua_integer_is_correct);
	lua_pushinteger(lua->L, i);
}

void rrr_lua_pushstr (
		struct rrr_lua *lua,
		const char *str
) {
	lua_pushstring(lua->L, str);
}

int rrr_lua_call (
		struct rrr_lua *lua,
		const char *function,
		int nargs
) {
	int ret = 0;

	int type;
	int status;

	assert(lua_gettop(lua->L) == nargs);

	switch (type = lua_getglobal(lua->L, function)) {
		case LUA_TFUNCTION:
			// OK
			break;
		case LUA_TNIL:
			RRR_MSG_0("Could not find Lua function '%s'\n",
				function);
			ret = 1;
			goto out;
		case LUA_TNUMBER:
		case LUA_TBOOLEAN:
		case LUA_TSTRING:
		case LUA_TTABLE:
		case LUA_TUSERDATA:
		case LUA_TTHREAD:
		case LUA_TLIGHTUSERDATA:
		default:
			RRR_MSG_0("Lua global '%s' is not a function but '%s'\n",
				function, lua_typename(lua->L, type));
			ret = 1;
			goto out;
	};

	// Function must be before arguments, rotate the stack
	lua_rotate(lua->L, -1 - nargs, 1);

	if ((status = lua_pcall(lua->L, nargs, 1 /* One result */, 0)) != LUA_OK) {
		__rrr_lua_error_with_location (lua, "Failed to call global Lua function '%s': %s\n",
			function, lua_tostring(lua->L, -1));
		ret = 1;
		goto out;
	}

	RRR_DBG_3("Top of stack after executing Lua function: %s type is %s\n",
		lua_isboolean(lua->L, -1)
			? (lua_toboolean(lua->L, -1) ? "true" : "false")
			: lua_tostring(lua->L, -1),
		lua_typename(lua->L, lua_type(lua->L, -1))
	);

	if (!lua_isboolean(lua->L, -1)) {
		RRR_MSG_0("Returned value from global Lua function '%s' was not a boolean, the value is '%s'\n",
			function, lua_tostring(lua->L, -1));
		ret = 1;
		goto out;
	}

	if (lua_toboolean(lua->L, -1) != 1) {
		RRR_MSG_0("False return value from global Lua function '%s'\n",
			function);
		ret = 1;
		goto out;
	}

	out:
	lua_pop(lua->L, 1);
	return ret;
}

void rrr_lua_assert_empty_stack (
		struct rrr_lua *lua
) {
	assert(lua_gettop(lua->L) == 0);
}

void rrr_lua_dump_and_clear_stack (
		struct rrr_lua *lua
) {
	/*
	 * NOTE : The tostring method may change type of values which
	 *        is why this function clears the stack.
	 */

	if (!RRR_DEBUGLEVEL_2)
		return;

	RRR_MSG_2("Dumping Lua stack in %s, there are %i elements to dump...\n",
		__func__, lua_gettop(lua->L));

	for (int i = 1; i <= lua_gettop(lua->L); i++) {
		const char *str = lua_tostring(lua->L, i);
		if (str != NULL) {
			RRR_MSG_2("- [%i] [%s] %s\n",
				i, luaL_typename(lua->L, i), str);
		}
		else {
			RRR_MSG_2("- [%i] [%s]\n",
				i, luaL_typename(lua->L, i));
		}
	}
	lua_pop(lua->L, lua_gettop(lua->L));
}
