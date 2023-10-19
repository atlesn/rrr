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

#include "lua_config.h"
#include "lua_common.h"
#include "lua_types.h"

#include "../log.h"
#include "../allocator.h"
#include "../instance_config.h"

struct rrr_lua_config {
	const struct rrr_lua *lua;
	int usercount;
	struct rrr_instance_config_data *config;
};

static int __rrr_lua_config_new (
		struct rrr_lua_config **result
) {
	int ret = 0;

	struct rrr_lua_config *config;

	if ((config = rrr_allocate_zero(sizeof(*config))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	config->usercount = 1;

	*result = config;

	out:
	return ret;
}

static void __rrr_lua_config_decref (struct rrr_lua_config *config) {
	if (--config->usercount > 0)
		return;
	assert(config->usercount == 0);
	rrr_free(config);
}

#define WITH_CONFIG_META(code) \
  RRR_LUA_WITH_SELF_META(config, RRR_LUA_META_KEY_RRR_CONFIG, code)

#define WITH_CONFIG(nargs, func_name, code) \
  RRR_LUA_WITH_SELF(config, RRR_LUA_META_KEY_RRR_CONFIG, nargs, func_name, code)

static int __rrr_lua_config_f_finalize(lua_State *L) {
	WITH_CONFIG_META (
		__rrr_lua_config_decref(config);
	);

	return 1;
}

static int __rrr_lua_config_f_set(lua_State *L) {
	WITH_CONFIG (2,set,
		RRR_LUA_SET_STR(key,2);
		RRR_LUA_SET_STR(value,1);

		if (rrr_instance_config_replace_string(config->config, key, value) != 0) {
			luaL_error(L, "Failed to set config value\n");
		}
	);

	return 0;
}

static int __rrr_lua_config_f_get(lua_State *L) {
	WITH_CONFIG (1,get,
		char *str;
		int ret_tmp;
		RRR_LUA_SET_STR(key,1);
		if (!rrr_instance_config_setting_exists(config->config, key)) {
			lua_pushnil(L);
			return 1;
		}
		if ((ret_tmp = rrr_instance_config_get_string_noconvert (
				&str,
				config->config,
				key
		)) != 0) {
			luaL_error(L, "Failed to get config value, return was %d\n",
				(lua_Integer) ret_tmp);
		}
		lua_pushstring(L, str);
		rrr_free(str);
	);

	return 1;
}

#define PUSH_SET_USERDATA(k,v)                                 \
  lua_pushliteral(L, k);                                       \
  lua_pushlightuserdata(L, v);                                 \
  lua_settable(L, -3)

static int __rrr_lua_config_construct (
		lua_State *L,
		struct rrr_lua_config *config
) {
	int results = 0;

	static const luaL_Reg f_meta[] = {
		{"__gc", __rrr_lua_config_f_finalize},
		{NULL, NULL}
	};
	static const luaL_Reg f[] = {
		{"get", __rrr_lua_config_f_get},
		{"set", __rrr_lua_config_f_set},
		{NULL, NULL}
	};

	luaL_newlib(L, f);
	results++;

	luaL_newlib(L, f_meta);

	PUSH_SET_USERDATA(RRR_LUA_META_KEY_RRR_CONFIG, config);

	lua_setmetatable(L, -2);

	return results;
}

int rrr_lua_config_push_new (
		struct rrr_lua *target,
		struct rrr_instance_config_data *instance_config
) {
	int ret = 0;

	struct rrr_lua_config *config;
	int results = 0;

	if ((ret = __rrr_lua_config_new(&config)) != 0) {
		RRR_MSG_0("Failed to create internal config in %s\n",
			__func__);
		goto out;
	}

	config->lua = target;
	config->config = instance_config;

	results = __rrr_lua_config_construct(target->L, config);
	assert(results == 1);

	goto out;
//	out_decref:
//		__rrr_lua_config_decref(config);
	out:
		return ret;
}
