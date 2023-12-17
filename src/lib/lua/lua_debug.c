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

#include "lua_debug.h"
#include "lua_common.h"
#include "lua_types.h"

#include "../log.h"
#include "../allocator.h"

struct rrr_lua_debug {
	int usercount;
};

static int __rrr_lua_debug_new (
		struct rrr_lua_debug **result
) {
	int ret = 0;

	struct rrr_lua_debug *debug;

	if ((debug = rrr_allocate_zero(sizeof(*debug))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	debug->usercount = 1;

	*result = debug;

	out:
	return ret;
}

static void __rrr_lua_debug_decref (struct rrr_lua_debug *debug) {
	if (--debug->usercount > 0)
		return;
	assert(debug->usercount == 0);
	rrr_free(debug);
}

#define WITH_DEBUG_META(code) \
  RRR_LUA_WITH_SELF_META(debug, RRR_LUA_META_KEY_RRR_DEBUG, code)

static int __rrr_lua_debug_f_finalize(lua_State *L) {
	WITH_DEBUG_META (
		__rrr_lua_debug_decref(debug);
	);

	return 1;
}

static void __rrr_lua_debug_prepare_with_level (
		uint8_t *level,
		const char **message,
		int *message_len_int,
		lua_State *L,
		const char *func_name
) {
	int isnum;
	size_t message_len;
	int level_tmp;

	level_tmp = lua_tointegerx(L, -2, &isnum);
	if (!isnum) {
		luaL_error(L, "Invalid debug level in %s, it was not convertible to number\n", func_name);
	}

	if (level_tmp < 0 || level_tmp > 255) {
		luaL_error(L, "Invalid debug level %d in %s\n",
			level_tmp, func_name);
	}
	*level = (uint8_t) level_tmp;

	if (!RRR_DEBUGLEVEL_OK(*level)) {
		luaL_error(L, "Invalid debug level %d in %s\n",
			*level, func_name);
	}

	*message = lua_tolstring(L, -1, &message_len);
	if (*message == NULL) {
		luaL_error(L, "Invalid message in %s, it was not convertible to string\n", func_name);
	}

	if (rrr_int_from_biglength_err(message_len_int, message_len) != 0) {
		luaL_error(L, "Invalid message length in %s\n", func_name);
	}
}

static int __rrr_lua_debug_f_msg(lua_State *L) {
	uint8_t level;
	const char *message;
	int message_len_int;

	__rrr_lua_debug_prepare_with_level (
			&level,
			&message,
			&message_len_int,
			L,
			"msg"
	);

	RRR_MSG_X(level, "%.*s", message_len_int, message);

	return 0;
}

static int __rrr_lua_debug_f_dbg(lua_State *L) {
	uint8_t level;
	const char *message;
	int message_len_int;

	__rrr_lua_debug_prepare_with_level (
			&level,
			&message,
			&message_len_int,
			L,
			"dbg"
	);

	RRR_DBG_X(level, "%.*s", message_len_int, message);

	return 0;
}

static int __rrr_lua_debug_f_err(lua_State *L) {
	uint8_t level;
	const char *message;
	int message_len_int;

	// Dummy level value
	lua_pushinteger(L, 1);
	lua_rotate(L, -2, 1);

	__rrr_lua_debug_prepare_with_level (
			&level,
			&message,
			&message_len_int,
			L,
			"err"
	);

	lua_rotate(L, -2, -1);
	lua_pop(L, 1);

	RRR_MSG_ERR("%.*s", message_len_int, message);

	return 0;
}

static int __rrr_lua_debug_construct (
		lua_State *L,
		struct rrr_lua_debug *debug
) {
	int results = 0;

	static const luaL_Reg f_meta[] = {
		{"__gc", __rrr_lua_debug_f_finalize},
		{NULL, NULL}
	};
	static const luaL_Reg f[] = {
		{"msg", __rrr_lua_debug_f_msg},
		{"dbg", __rrr_lua_debug_f_dbg},
		{"err", __rrr_lua_debug_f_err},
		{NULL, NULL}
	};

	luaL_newlib(L, f);
	results++;

	luaL_newlib(L, f_meta);

	RRR_LUA_PUSH_SET_USERDATA(RRR_LUA_META_KEY_RRR_DEBUG, debug);

	lua_setmetatable(L, -2);

	return results;
}

static int __rrr_lua_debug_f_new(lua_State *L) {
	int results = 0;

	struct rrr_lua_debug *debug = NULL;

	if (__rrr_lua_debug_new(&debug) != 0) {
		luaL_error(L, "Failed to create internal debug in %s\n",
			__func__);
	}

	results = __rrr_lua_debug_construct(L, debug);
	assert(results == 1);

	return 1;
}

void rrr_lua_debug_library_register (
		struct rrr_lua *target
) {
	lua_State *L = target->L;

	static const luaL_Reg f[] = {
		{"new", __rrr_lua_debug_f_new},
		{NULL, NULL}
	};

	lua_getglobal(L, RRR_LUA_KEY);
	assert(lua_type(L, -1) == LUA_TTABLE);

	lua_pushliteral(L, RRR_LUA_KEY_DEBUG);
	luaL_newlib(L, f);

	lua_settable(L, -3);

	lua_pop(L, 1);
}


