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
#include "lua_types.h"

#include "../array.h"
#include "../allocator.h"
#include "../log.h"

struct rrr_lua_message {
	int usercount;
	struct rrr_array array;
	char ip_addr[128];
	uint16_t ip_port;
};

static int __rrr_lua_message_new (
		struct rrr_lua_message **result
) {
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

static void __rrr_lua_message_decref (struct rrr_lua_message *message) {
	if (--message->usercount > 0)
		return;
	assert(message->usercount == 0);
	rrr_array_clear(&message->array);
	rrr_free(message);
}

#define VERIFY_MSG(nargs,func_name)

#define WITH_MSG_META(code)                                    \
  do {int test; struct rrr_lua_message *message;               \
  test = lua_getmetatable(L, -1);                              \
  assert(test == 1);                                           \
  lua_pushliteral(L, "_rrr_message");                          \
  lua_gettable(L, -2);                                         \
  assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);               \
  message = lua_touserdata(L, -1);                             \
  lua_pop(L, 2);                                               \
  code                                                         \
  } while(0)

#define WITH_MSG(nargs,func_name,code)                         \
  do {int test; struct rrr_lua_message *message;               \
  if ((test = lua_getmetatable(L, -1 - nargs)) != 1) {         \
    luaL_error(L, "Possible incorrect number of arguments to function " #func_name ", verify that the number of arguments is " #nargs " and that : is used when calling.\n"); \
    break;                                                     \
  }                                                            \
  lua_pushliteral(L, "_rrr_message");                          \
  lua_gettable(L, -2);                                         \
  if (lua_type(L, -1) != LUA_TLIGHTUSERDATA) {                 \
    luaL_error(L, "Userdata _rrr_message not found in metatable while calling " #func_name "\n"); \
    lua_pop(L, 2);                                             \
    break;                                                     \
  }                                                            \
  message = lua_touserdata(L, -1);                             \
  lua_pop(L, 2);                                               \
  code                                                         \
  } while(0)

static int __rrr_lua_message_f_finalize(lua_State *L) {
	WITH_MSG_META (
		__rrr_lua_message_decref(message);
	);

	return 1;
}

static int __rrr_lua_message_f_ip_set(lua_State *L) {
	WITH_MSG (2,ip_set,
		const char *ip = lua_tostring(L, -2);
		rrr_lua_int port = lua_tointeger(L, -1);

		assert(sizeof(message->ip_port) == sizeof(uint16_t));

		if (strlen(ip) > sizeof(message->ip_addr) - 1) {
			luaL_error(L, "IP address length exceeds maximum (%I>%I)\n",
				(lua_Integer) strlen(ip), (lua_Integer) sizeof(message->ip_addr) - 1);
			return 0;
		}

		strcpy(message->ip_addr, ip);

		if (*ip != '\0') {
			if (port < 1 || port > 65535) {
				luaL_error(L, "IP port out of range. Value is %I while valid range is 1-65535\n",
					(lua_Integer) port);
				return 0;
			}
			message->ip_port = rrr_u16_from_slength_bug_const(port);
		}
		else {
			message->ip_port = 0;
		}
	);

	return 0;
}

static int __rrr_lua_message_f_ip_get(lua_State *L) {
	WITH_MSG (0,ip_get,
		assert(sizeof(message->ip_port) == sizeof(uint16_t));
		lua_pushstring(L, message->ip_addr);
		lua_pushinteger(L, message->ip_port);
	);

	return 2;
}

static int __rrr_lua_message_f_ip_clear(lua_State *L) {
	WITH_MSG (0,ip_clear,
		*message->ip_addr = '\0';
		message->ip_port = 0;
	);

	return 0;
}

#define PUSH_SET_STR(k,v)                                      \
  lua_pushliteral(L, k);                                       \
  lua_pushliteral(L, v);                                       \
  lua_settable(L, -3)

#define PUSH_SET_INT(k,v)                                      \
  lua_pushliteral(L, k);                                       \
  lua_pushinteger(L, v);                                       \
  lua_settable(L, -3)

#define PUSH_SET_USERDATA(k,v)                                 \
  lua_pushliteral(L, k);                                       \
  lua_pushlightuserdata(L, v);                                 \
  lua_settable(L, -3)

static int __rrr_lua_message_construct (
		lua_State *L,
		struct rrr_lua_message *message
) {
	int results = 0;

	static const luaL_Reg f_meta[] = {
		{"__gc", __rrr_lua_message_f_finalize},
		{NULL, NULL}
	};
	static const luaL_Reg f[] = {
		{"ip_set", __rrr_lua_message_f_ip_set},
		{"ip_get", __rrr_lua_message_f_ip_get},
		{"ip_clear", __rrr_lua_message_f_ip_clear},
		{NULL, NULL}
	};

	luaL_newlib(L, f);
	results++;

	luaL_newlib(L, f_meta);

	PUSH_SET_USERDATA("_rrr_message", message);

	lua_setmetatable(L, -2);

	return results;
}

static int __rrr_lua_message_f_new(lua_State *L) {
	int results = 0;

	struct rrr_lua_message *message;

	if (__rrr_lua_message_new(&message) != 0) {
		luaL_error(L, "Failed to create internal message in %s\n",
			__func__);
		return 0;
	}

	results = __rrr_lua_message_construct(L, message);
	assert(results == 1);

	return 1;
}

int rrr_lua_message_push_new (
		struct rrr_lua *target
) {
	int ret = 0;

	struct rrr_lua_message *message;
	int results = 0;

	if ((ret = __rrr_lua_message_new(&message)) != 0) {
		RRR_MSG_0("Failed to create internal message in %s\n",
			__func__);
		goto out;
	}

	results = __rrr_lua_message_construct(target->L, message);
	assert(results == 1);

	out:
	return ret;
	
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


