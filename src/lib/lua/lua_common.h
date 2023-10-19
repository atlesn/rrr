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

#include "../util/macro_utils.h"

#if defined(HAVE_LUA5_4_LUA_H)
#  include <lua5.4/lua.h>
#  include <lua5.4/lauxlib.h>
#  include <lua5.4/lualib.h>
#elif defined(HAVE_LUA5_3_LUA_H)
#  include <lua5.3/lua.h>
#  include <lua5.3/lauxlib.h>
#  include <lua5.3/lualib.h>
#elif defined(HAVE_LUA_H)
#  include <lua.h>
#  include <lauxlib.h>
#  include <lualib.h>
#else
#  error "No HAVE_LUA defined"
#endif

// Global object name
#define RRR_LUA_KEY              "RRR"

// Keys in table of RRR global object
#define RRR_LUA_KEY_MESSAGE      "Message"
#define RRR_LUA_KEY_DEBUG        "Debug"

// Keys in metatable of RRR global object
#define RRR_LUA_META_KEY_LUA     "_rrr_lua"
#define RRR_LUA_META_KEY_CMODULE "_rrr_cmodule"

// Keys in instantiated objects
#define RRR_LUA_META_KEY_RRR_MESSAGE "_rrr_message"
#define RRR_LUA_META_KEY_RRR_CONFIG "_rrr_config"
#define RRR_LUA_META_KEY_RRR_DEBUG "_rrr_debug"

// Set global Lua object
#define RRR_WITH_LUA_GLOBAL(code)                              \
  do{struct rrr_lua *lua;do{                                   \
  lua_getglobal(L, RRR_LUA_KEY);                               \
  assert(lua_type(L, -1) == LUA_TTABLE);                       \
  lua_getmetatable(L, -1);                                     \
  assert(lua_type(L, -1) == LUA_TTABLE);                       \
  lua_getfield(L, -1, RRR_LUA_META_KEY_LUA);                   \
  assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);               \
  lua = lua_touserdata(L, -1);                                 \
  lua_pop(L, 3);} while(0); code } while(0)

// Get string argument to a function
#define RRR_LUA_SET_STR(k,nargs)                               \
  const char *k = lua_tostring(L, -nargs);                     \
  do {if (k == NULL) {                                         \
    luaL_error(L, "Failed in function %s, argument was not convertible to string (type is %s)\n", \
        __func__, luaL_typename(L, -nargs));                   \
  }} while (0)

// Helper macros to set self in functions
#define RRR_LUA_SET_SELF(obj,meta_key,nargs,func_name)         \
  struct RRR_PASTE(rrr_lua_,obj) *obj;                         \
  {int test; if ((test = lua_getmetatable(L, -1 - nargs)) != 1) { \
    luaL_error(L, "Possible incorrect number of arguments to function " #func_name ", verify that the number of arguments is " #nargs " and that : is used when calling.\n"); \
  }}                                                           \
  lua_pushliteral(L, meta_key);                                \
  lua_gettable(L, -2);                                         \
  if (lua_type(L, -1) != LUA_TLIGHTUSERDATA) {                 \
    luaL_error(L, "Userdata " #meta_key " not found in metatable while calling " #func_name "\n"); \
  }                                                            \
  obj = lua_touserdata(L, -1);                                 \
  lua_pop(L, 2);                                               \

#define RRR_LUA_WITH_SELF(obj,meta_key,nargs,func_name,code)   \
  do {RRR_LUA_SET_SELF(obj,meta_key,nargs,func_name);          \
  code                                                         \
  } while(0)

#define RRR_LUA_WITH_SELF_META(obj,meta_key,code)              \
  do {int test; struct RRR_PASTE(rrr_lua_,obj) *obj;           \
  test = lua_getmetatable(L, -1);                              \
  assert(test == 1);                                           \
  lua_pushliteral(L, meta_key);                                \
  lua_gettable(L, -2);                                         \
  assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);               \
  obj = lua_touserdata(L, -1);                                 \
  lua_pop(L, 2);                                               \
  code                                                         \
  } while(0)

struct rrr_lua {
	lua_State *L;
	int precision_loss_warnings;
};

#endif /* RRR_LUA_HEADERS_H */
