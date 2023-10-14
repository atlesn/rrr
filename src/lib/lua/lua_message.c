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

#include <stdlib.h>
#include <assert.h>
#include <float.h>
#include <errno.h>

#include "lua_message.h"
#include "lua_common.h"
#include "lua_types.h"

#include "../array.h"
#include "../allocator.h"
#include "../log.h"
#include "../fixed_point.h"
#include "../ip/ip_defines.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../cmodule/cmodule_worker.h"

struct rrr_lua_message {
	struct rrr_lua *lua;
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
  lua_pushliteral(L, RRR_LUA_META_KEY_RRR_MESSAGE);            \
  lua_gettable(L, -2);                                         \
  assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);               \
  message = lua_touserdata(L, -1);                             \
  lua_pop(L, 2);                                               \
  code                                                         \
  } while(0)

#define SET_MSG(nargs,func_name)                               \
  struct rrr_lua_message *message;                             \
  {int test; if ((test = lua_getmetatable(L, -1 - nargs)) != 1) { \
    luaL_error(L, "Possible incorrect number of arguments to function " #func_name ", verify that the number of arguments is " #nargs " and that : is used when calling.\n"); \
  }}                                                           \
  lua_pushliteral(L, RRR_LUA_META_KEY_RRR_MESSAGE);            \
  lua_gettable(L, -2);                                         \
  if (lua_type(L, -1) != LUA_TLIGHTUSERDATA) {                 \
    luaL_error(L, "Userdata " RRR_LUA_META_KEY_RRR_MESSAGE " not found in metatable while calling " #func_name "\n"); \
  }                                                            \
  message = lua_touserdata(L, -1);                             \
  lua_pop(L, 2);                                               \

#define WITH_MSG(nargs,func_name,code)                         \
  do {SET_MSG(nargs,func_name);                                \
  code                                                         \
  } while(0)

#define SET_KEY(k)                                             \
  const char *k = lua_tostring(L, -2);                         \
  do {if (k == NULL) {                                         \
    luaL_error(L, "Failed to push value in %s, key was not convertible to string (type is %s)\n", \
        __func__, luaL_typename(L, -2));                       \
  }} while (0)

#define WITH_LUA(code)                                         \
  do{struct rrr_lua *lua;do{                                   \
  lua_getglobal(L, RRR_LUA_KEY);                               \
  assert(lua_type(L, -1) == LUA_TTABLE);                       \
  lua_getmetatable(L, -1);                                     \
  assert(lua_type(L, -1) == LUA_TTABLE);                       \
  lua_getfield(L, -1, RRR_LUA_META_KEY_LUA);                   \
  assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);               \
  lua = lua_touserdata(L, -1);                                 \
  lua_pop(L, 3);} while(0); code } while(0)

#define WITH_CMODULE(code)                                     \
  do {struct rrr_cmodule_worker *cmodule_worker;do{            \
  lua_getglobal(L, RRR_LUA_KEY);                               \
  assert(lua_type(L, -1) == LUA_TTABLE);                       \
  lua_getmetatable(L, -1);                                     \
  assert(lua_type(L, -1) == LUA_TTABLE);                       \
  lua_getfield(L, -1, RRR_LUA_META_KEY_CMODULE);               \
  assert(lua_type(L, -1) == LUA_TLIGHTUSERDATA);               \
  cmodule_worker = lua_touserdata(L, -1);                      \
  lua_pop(L, 3);} while(0); code } while(0)
  

/*
 * NOTE : Error handling in the push functions is done by Lua which
 *        performs longjmp back to Lua in the luaL_error call.
 */

static void __rrr_lua_message_push_integer (
		struct rrr_lua_message *message,
		lua_State *L,
		const char *k,
		rrr_lua_int i
) {
	if ((i < 0
		? rrr_array_push_value_i64_with_tag(&message->array, k, (int64_t) i)
		: rrr_array_push_value_u64_with_tag(&message->array, k, (uint64_t) i)
	) != 0) {
		luaL_error(L, "Failed to push integer value to array in %s\n", __func__);
	}
}

static void __rrr_lua_message_push_ld (
		struct rrr_lua_message *message,
		lua_State *L,
		const char *k,
		long double n
) {
	rrr_fixp fixp;
	long double n_test;
	int buf_len;
	char buf[128];

	if (rrr_fixp_from_ldouble(&fixp, n) != 0) {
		luaL_error(L, "Could not convert floating point number '%s' to RRR fixed point while pusing to array\n",
			lua_tostring(L, -2));
	}

	if (rrr_fixp_to_ldouble(&n_test, fixp) != 0) {
		luaL_error(L, "Failed to convert floating point number '%s' to RRR fixed point while pushing to array\n",
			lua_tostring(L, -2));
	}

	if (n_test != n) {
		RRR_MSG_0("Warning: Precision loss while converting lua Number '%Lf' to fixed point " \
		          "while pushing array value with key '%s'. Passing as string instead.\n",
			n, k);
		buf_len = sprintf(buf, "%Lf", (long double) n);
		if (rrr_array_push_value_str_with_tag_with_size(&message->array, k, buf, buf_len) != 0) {
			luaL_error(L, "Failed to push string value in %s\n",
				__func__);
		}
	}
	else {
		if (rrr_array_push_value_fixp_with_tag(&message->array, k, fixp) != 0) {
			luaL_error(L, "Failed to push fixp value in %s\n",
				__func__);
		}
	}
}

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

static int __rrr_lua_message_f_clear_array(lua_State *L) {
	WITH_MSG(0,clear_array,
		rrr_array_clear(&message->array);
	);
	return 0;
}

static int __rrr_lua_message_f_clear_tag(lua_State *L) {
	WITH_MSG(1,clear_tag,
		rrr_array_clear_by_tag(&message->array, lua_tostring(L, -1));
	);
	return 0;
}

static int __rrr_lua_message_f_push_tag_blob(lua_State *L) {
	WITH_MSG(2,push_tag_blob,
		SET_KEY(k);
		size_t str_len;
		const char *v = lua_tolstring(L, -1, &str_len);
		if (v == NULL) {
			luaL_error(L, "Failed to push value in %s, value was not convertible to string (type is %s)\n",
				__func__, luaL_typename(L, -1));
			return 0;
		}
		if (rrr_array_push_value_blob_with_tag_with_size(&message->array, k, v, str_len) != 0) {
			luaL_error(L, "Failed to push blob value in %s\n", __func__);
			return 0;
		}
	);
	return 0;
}

static int __rrr_lua_message_f_push_tag_str(lua_State *L) {
	WITH_MSG(2,push_tag_str,
		SET_KEY(k);
		size_t str_len;
		const char *v = lua_tolstring(L, -1, &str_len);
		if (v == NULL) {
			luaL_error(L, "Failed to push value in %s, value was not convertible to string (type is %s)\n",
				__func__, luaL_typename(L, -1));
			return 0;
		}
		if (rrr_array_push_value_str_with_tag_with_size(&message->array, k, v, str_len) != 0) {
			luaL_error(L, "Failed to push string value in %s\n", __func__);
			return 0;
		}
	);
	return 0;
}

static int __rrr_lua_message_f_push_tag_h(lua_State *L) {
	WITH_MSG(2,push_tag_h,
		SET_KEY(k);
		int isnum;
		int i;
		long long int lli;
		long long unsigned int llu;
		const char *str;
		size_t str_len;
		const char *endptr;

		i = lua_tointegerx(L, -1, &isnum);
		if (isnum) {
			__rrr_lua_message_push_integer (message, L, k, i);
			goto done;
		}

		// Try string
		if ((str = lua_tolstring(L, -1, &str_len)) == NULL) {
			luaL_error(L, "Failed to push value with key %s to array, value was not convertible to string (type is %s)\n",
				k, luaL_typename(L, -1));
		}
		if (str_len == 0) {
			luaL_error(L, "Failed to push value with key %s to array, string was empty\n", k);
		}

		errno = 0;

		if (*str == '-') {
			lli = strtoll(str, (char **) &endptr, 10);
			if (errno == ERANGE) {
				luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, value out of range\n", k);
			}
			if (str + str_len != endptr) {
				if (*endptr != '.') {
					luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, string was not fully converted\n", k);
				}
			}
			if (rrr_array_push_value_i64_with_tag(&message->array, k, (int64_t) lli) != 0) {
				luaL_error(L, "Failed to push integer value to array in %s\n", __func__);
			}
		}
		else {
			llu = strtoull(str, (char **) &endptr, 10);
			if (errno == ERANGE) {
				luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, value out of range\n", k);
			}
			if (str + str_len != endptr) {
				if (*endptr != '.') {
					luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, string was not fully converted\n", k);
				}
			}
			if (rrr_array_push_value_u64_with_tag(&message->array, k, (uint64_t) llu) != 0) {
				luaL_error(L, "Failed to push integer value to array in %s\n", __func__);
			}
		}

		done:
	);
	return 0;
}

static int __rrr_lua_message_f_push_tag_fixp(lua_State *L) {
	WITH_MSG(2,push_tag_fixp,
		SET_KEY(k);
		lua_Number n;
		int isnum;
		const char *str;
		size_t str_len;
		const char *endptr;
		rrr_fixp fixp;

		n = lua_tonumberx(L, -1, &isnum);
		if (isnum) {
			__rrr_lua_message_push_ld (message, L, k, n);
		}
		else {
			if ((str = lua_tolstring(L, -1, &str_len)) == NULL) {
				luaL_error(L, "Failed to push value with key %s to array, value was not convertible to string (type is %s)\n",
					k, luaL_typename(L, -1));
			}
			if (str_len == 0) {
				luaL_error(L, "Failed to push value with key %s to array, string was empty\n", k);
			}
			if (rrr_fixp_str_to_fixp(&fixp, str, rrr_length_from_size_t_bug_const(str_len), &endptr) != 0) {
				luaL_error(L, "Failed to convert string to fixed point number while pushing value with key %s to array\n", k);
			}
			if (endptr != str + str_len) {
				luaL_error(L, "Failed to convert string to fixed point number while pushing value with key %s to array, string was not fully converted\n", k);
			}
			if (rrr_array_push_value_fixp_with_tag(&message->array, k, fixp) != 0) {
				luaL_error(L, "Failed to push fixp value in %s\n", __func__);
			}
		}
	);
	return 0;
}

static int __rrr_lua_message_f_push_tag(lua_State *L) {
	WITH_MSG(2,push_tag,
		SET_KEY(k);
		switch(lua_type(L, -1)) {
			case LUA_TNIL: {
				if (rrr_array_push_value_vain_with_tag(&message->array, k) != 0) {
					luaL_error(L, "Failed to push vain value to array in %s\n",
						__func__);
				}
			} break;
			case LUA_TNUMBER: {
				int isnum = 0;
				rrr_lua_int i;
				long double n;

				// Try integer
				i = lua_tointegerx(L, -1, &isnum);
				if (isnum) {
					__rrr_lua_message_push_integer (message, L, k, i);
					break;
				}

				// Try double
				n = lua_tonumberx(L, -1, &isnum);
				if (isnum) {
					__rrr_lua_message_push_ld (message, L, k, n);
					break;
				}
				luaL_error(L, "Failed to convert number '%s' to integer or fixed point while pusing value to array\n", lua_tostring(L, -2));
			} break;
			case LUA_TBOOLEAN: {
				assert(0 && "Blocked, test must be written");
			} break;
			case LUA_TSTRING: {
				const char *v = lua_tostring(L, -1);
				assert(v != NULL);
				if (rrr_array_push_value_str_with_tag(&message->array, k, v) != 0) {
					luaL_error(L, "Failed to push string value in %s\n",
						__func__);
				}
			} break;
			case LUA_TTABLE:
			case LUA_TFUNCTION:
			case LUA_TUSERDATA:
			case LUA_TTHREAD:
			case LUA_TLIGHTUSERDATA:
			default:
				luaL_error(L, "Cannot push value of type %s to array\n", lua_type(L, -1));
				return 1;
		};
	);
	return 0;
}

static int __rrr_lua_message_f_set_tag(lua_State *L) {
	SET_MSG(2,set_tag);
	SET_KEY(k);
	rrr_array_clear_by_tag(&message->array, k);
	return __rrr_lua_message_f_push_tag(L);
}

// Implementations of all type specific set functions 
static int __rrr_lua_message_f_set_tag_blob(lua_State *L) {
	SET_MSG(2,set_tag_blob);
	SET_KEY(k);
	rrr_array_clear_by_tag(&message->array, k);
	return __rrr_lua_message_f_push_tag_blob(L);
}

static int __rrr_lua_message_f_set_tag_str(lua_State *L) {
	SET_MSG(2,set_tag_str);
	SET_KEY(k);
	rrr_array_clear_by_tag(&message->array, k);
	return __rrr_lua_message_f_push_tag_str(L);
}

static int __rrr_lua_message_f_set_tag_h(lua_State *L) {
	SET_MSG(2,set_tag_h);
	SET_KEY(k);
	rrr_array_clear_by_tag(&message->array, k);
	return __rrr_lua_message_f_push_tag_h(L);
}

static int __rrr_lua_message_f_set_tag_fixp(lua_State *L) {
	SET_MSG(2,set_tag_fixp);
	SET_KEY(k);
	rrr_array_clear_by_tag(&message->array, k);
	return __rrr_lua_message_f_push_tag_fixp(L);
}

static void __rrr_lua_message_array_value_to_lua (
		lua_State *L,
		const struct rrr_type_value *value
) {
	char buf[128];
	int buf_len;
	const rrr_length len = value->total_stored_length / value->element_count;

	switch (value->definition->type) {
		case RRR_TYPE_MSG:
		RRR_TYPE_CASE_BLOB:
		RRR_TYPE_CASE_STR: {
			for (rrr_length i = 0; i < value->total_stored_length; i += len) {
				lua_pushlstring(L, value->data + i, len);
			}
		} break;
		case RRR_TYPE_H: {
			assert(len == sizeof(int64_t));
			RRR_ASSERT(LDBL_MANT_DIG >= 64,long_double_can_hold_64_bits);
			RRR_ASSERT(sizeof(lua_Number) >= sizeof(double),double_fits_in_lua_number);
			if (RRR_TYPE_FLAG_IS_SIGNED(value->flags)) {
				for (rrr_length i = 0; i < value->total_stored_length; i += len) {
					int64_t    x = *((int64_t *) (value->data + i));
					lua_Number n = (lua_Number) x;
					if (n != x) {
						RRR_MSG_0("Warning: Precision loss while converting signed value '%" PRIi64 "' to Lua number. Passing as string instead.\n",
							x);
						buf_len = sprintf(buf, "%" PRIi64, x);
						lua_pushlstring(L, buf, (size_t) buf_len);
					}
					else {
						lua_pushinteger(L, (lua_Number) x);
					}
				}
			}
			else {
				for (rrr_length i = 0; i < value->total_stored_length; i += len) {
					uint64_t   x = *((uint64_t *) (value->data + i));
					lua_Number n = (lua_Number) x;
					if (n != x) {
						RRR_MSG_0("Warning: Precision loss while converting unsigned value '%" PRIu64 "' to Lua number. Passing as string instead.\n",
							x);
						buf_len = sprintf(buf, "%" PRIu64, x);
						lua_pushlstring(L, buf, (size_t) buf_len);
					}
					else {
						lua_pushinteger(L, (lua_Number) x);
					}
				}
			}
		} break;
		case RRR_TYPE_FIXP:
			for (rrr_length i = 0; i < value->total_stored_length; i += len) {
				rrr_fixp fixp = *((rrr_fixp *) (value->data + i));
				long double number;
				rrr_fixp fixp_test;
				if (rrr_fixp_to_ldouble(&number, fixp) != 0) {
					luaL_error(L, "Failed to convert fixed point number to Lua number while pushing value to array\n");
				}
				if (rrr_fixp_from_ldouble(&fixp_test, number) != 0) {
					luaL_error(L, "Failed to convert Lua number to fixed point number while pushing value to array\n");
				}
				if (fixp_test != fixp) {
					RRR_MSG_0("Warning: Precision loss while converting fixed point value to Lua number. Passing as string instead.\n");
					buf_len = sprintf(buf, "%Lf", (long double) number);
					lua_pushlstring(L, buf, (size_t) buf_len);
				}
				else {
					lua_pushnumber(L, number);
				}
			}
			break;
		case RRR_TYPE_VAIN:
			lua_pushnil(L);
			break;
		case RRR_TYPE_LE:
		case RRR_TYPE_BE:
		case RRR_TYPE_USTR:
		case RRR_TYPE_ISTR:
		case RRR_TYPE_ERR:
		default:
			assert(0 && "Type not supported");
	};
}

static int __rrr_lua_message_f_get_tag_all(lua_State *L) {
	int results = 0;

	WITH_MSG(1,get_tag_all,
		const char *key = lua_tostring(L, -1);

		int wpos = 1;

		lua_newtable(L);
		results++;

		RRR_LL_ITERATE_BEGIN(&message->array, struct rrr_type_value);
			if (!rrr_type_value_is_tag(node, key)) {
				RRR_LL_ITERATE_NEXT();
			}

			lua_pushinteger(L, wpos++);

			__rrr_lua_message_array_value_to_lua(L, node);

			lua_settable(L, -3);
		RRR_LL_ITERATE_END();
	);

	return results;
}
/*
-- Retrieve the value at the specified position. Returns a list with one or more values or nil.
message:get_position(position_number)

-- Count the number of positions in the array.
message:count_positions()

-- Get all tag names from the array. Returns a list with zero or more values.
-- Always returns the same number of element as count_positions(). An empty string is used for positions without a tag.
message:get_tag_names()

-- Get the value count at each position of the message. Returns a list with zero or more values.
-- Always returns the same number of element as count_positions().
message:get_tag_counts()


*/

static int __rrr_lua_message_f_get_position(lua_State *L) {
	WITH_MSG(1,get_position,
		lua_Integer pos = lua_tointeger(L, -1);
		if (pos < 1 || pos > RRR_LL_COUNT(&message->array)) {
			luaL_error(L, "Position out of range. Value is %I while valid range is 1-%I\n",
				(lua_Integer) pos, (lua_Integer) RRR_LL_COUNT(&message->array));
		}

		// Lua is 1-based, RRR is 0-based
		pos--;

		int i = 0;
		RRR_LL_ITERATE_BEGIN(&message->array, struct rrr_type_value);
			if (i == pos) {
				__rrr_lua_message_array_value_to_lua(L, node);
				RRR_LL_ITERATE_BREAK();
			}
			i++;
		RRR_LL_ITERATE_END();

		assert(i == pos);
	);
	return 1;
}

static int __rrr_lua_message_f_count_positions(lua_State *L) {
	WITH_MSG(0,count_positions,
		lua_pushinteger(L, (lua_Integer) RRR_LL_COUNT(&message->array));
	);
	return 1;
}

static int __rrr_lua_message_f_get_tag_names(lua_State *L) {
	WITH_MSG(0,get_tag_names,
		int wpos = 1;

		lua_newtable(L);

		RRR_LL_ITERATE_BEGIN(&message->array, struct rrr_type_value);
			lua_pushinteger(L, wpos++);

			if (node->tag == NULL) {
				lua_pushstring(L, "");
			}
			else {
				lua_pushstring(L, node->tag);
			}

			lua_settable(L, -3);
		RRR_LL_ITERATE_END();
	);
	return 1;
}

static int __rrr_lua_message_f_get_tag_counts(lua_State *L) {
	WITH_MSG(0,get_tag_counts,
		int wpos = 1;

		lua_newtable(L);

		RRR_LL_ITERATE_BEGIN(&message->array, struct rrr_type_value);
			lua_pushinteger(L, wpos++);

			lua_pushinteger(L, (lua_Integer) node->element_count);

			lua_settable(L, -3);
		RRR_LL_ITERATE_END();
	);
	return 1;
}

static int __rrr_lua_message_f_send(lua_State *L) {
	struct rrr_msg_msg *msg = NULL;
	struct rrr_msg_addr msg_addr = {0};

	const char *topic;
	size_t topic_len;
	const char *data;
	size_t data_len;
	const char *ip_so_type;
	size_t ip_so_type_len;

	rrr_msg_addr_init(&msg_addr);

	WITH_MSG(0,send,
		// Topic
		lua_pushstring(L, "topic");
		lua_gettable(L, -2);
		if (lua_type(L, -1) != LUA_TSTRING) {
			luaL_error(L, "Failed to get message topic in %s, value was not of string type (type is %s)\n",
				__func__, luaL_typename(L, -1));
		}
		topic = lua_tolstring(L, -1, &topic_len);
		lua_pop(L, 1);

		if (topic_len > RRR_MSG_TOPIC_MAX) {
			luaL_error(L, "Topic length exceeds maximum (%I>%I)\n",
				(lua_Integer) topic_len, (lua_Integer) RRR_MSG_TOPIC_MAX);
		}

		// IP socket type
		lua_pushstring(L, "ip_so_type");
		lua_gettable(L, -2);
		if (lua_type(L, -1) != LUA_TSTRING) {
			luaL_error(L, "Failed to get message ip_so_type in %s, value was not of string type (type is %s)\n",
				__func__, luaL_typename(L, -1));
		}
		ip_so_type = lua_tolstring(L, -1, &ip_so_type_len);
		lua_pop(L, 1);

		if (ip_so_type_len != 0 && ip_so_type_len != 3) {
			luaL_error(L, "IP socket type must be either empty or 3 characters long (set to 'tcp' or 'udp')\n");
		}

		msg_addr.protocol = RRR_IP_AUTO;

		if (rrr_posix_strncasecmp("udp", ip_so_type, ip_so_type_len) == 0) {
			msg_addr.protocol = RRR_IP_UDP;
		}
		else if (rrr_posix_strncasecmp("tcp", ip_so_type, ip_so_type_len) == 0) {
			msg_addr.protocol = RRR_IP_TCP;
		}
		else if (ip_so_type_len != 0) {
			luaL_error(L, "IP socket type must be either empty, set to 'tcp' or 'udp')\n");
		}

		if (RRR_LL_COUNT(&message->array) > 0) {
			if (rrr_array_new_message_from_array (
					&msg,
					&message->array,
					rrr_time_get_i64(),
					topic,
					rrr_length_from_size_t_bug_const(topic_len)
			) != 0) {
				luaL_error(L, "Failed to create array message in %s\n", __func__);
			}
		}
		else {
			lua_pushstring(L, "data");
			lua_gettable(L, -2);
			if (lua_type(L, -1) != LUA_TSTRING) {
				luaL_error(L, "Failed to get message data in %s, value was not of string type (type is %s)\n",
					__func__, luaL_typename(L, -1));
			}
			data = lua_tolstring(L, -1, &data_len);

			if (data_len > RRR_MSG_DATA_MAX) {
				luaL_error(L, "Data length exceeds maximum (%I>%I)\n",
					(lua_Integer) data_len, (lua_Integer) RRR_MSG_DATA_MAX);
			}

			if (rrr_msg_msg_new_with_data (
					&msg,
					MSG_TYPE_MSG,
					MSG_CLASS_DATA,
					rrr_time_get_64(),
					topic,
					rrr_length_from_size_t_bug_const(topic_len),
					data,
					rrr_length_from_size_t_bug_const(data_len)
			) != 0) {
				luaL_error(L, "Failed to create data message in %s\n", __func__);
			}
		}
		WITH_CMODULE(
			if (rrr_cmodule_worker_send_message_and_address_to_parent (
					cmodule_worker,
					msg,
					&msg_addr
			) != 0) {
				luaL_error(L, "Failed to send message in %s\n", __func__);
			}
		);
	);

	RRR_FREE_IF_NOT_NULL(msg);
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
		{"clear_array", __rrr_lua_message_f_clear_array},
		{"clear_tag", __rrr_lua_message_f_clear_tag},
		{"push_tag_blob", __rrr_lua_message_f_push_tag_blob},
		{"push_tag_str", __rrr_lua_message_f_push_tag_str},
		{"push_tag_h", __rrr_lua_message_f_push_tag_h},
		{"push_tag_fixp", __rrr_lua_message_f_push_tag_fixp},
		{"push_tag", __rrr_lua_message_f_push_tag},
		{"set_tag", __rrr_lua_message_f_set_tag},
		{"set_tag_blob", __rrr_lua_message_f_set_tag_blob},
		{"set_tag_str", __rrr_lua_message_f_set_tag_str},
		{"set_tag_h", __rrr_lua_message_f_set_tag_h},
		{"set_tag_fixp", __rrr_lua_message_f_set_tag_fixp},
		{"get_tag_all", __rrr_lua_message_f_get_tag_all},
		{"get_position", __rrr_lua_message_f_get_position},
		{"count_positions", __rrr_lua_message_f_count_positions},
		{"get_tag_names", __rrr_lua_message_f_get_tag_names},
		{"get_tag_counts", __rrr_lua_message_f_get_tag_counts},
		{"send", __rrr_lua_message_f_send},
		{NULL, NULL}
	};

	luaL_newlib(L, f);
	results++;

	PUSH_SET_STR("ip_so_type", "");
	PUSH_SET_STR("topic", "");
	PUSH_SET_STR("data", "");
	PUSH_SET_INT("type", MSG_TYPE_MSG);
	PUSH_SET_INT("class", MSG_CLASS_DATA);

	if (sizeof(lua_Integer) >= 8) {
		PUSH_SET_INT("timestamp", (lua_Integer) rrr_time_get_i64());
	}

	luaL_newlib(L, f_meta);

	PUSH_SET_USERDATA(RRR_LUA_META_KEY_RRR_MESSAGE, message);

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
	lua_State *L = target->L;

	static const luaL_Reg f[] = {
		{"new", __rrr_lua_message_f_new},
		{NULL, NULL}
	};

	lua_getglobal(L, RRR_LUA_KEY);
	assert(lua_type(L, -1) == LUA_TTABLE);

	lua_pushliteral(L, RRR_LUA_KEY_MESSAGE);
	luaL_newlib(L, f);

	PUSH_SET_INT("MSG_TYPE_MSG", MSG_TYPE_MSG);
	PUSH_SET_INT("MSG_TYPE_TAG", MSG_TYPE_TAG);
	PUSH_SET_INT("MSG_TYPE_GET", MSG_TYPE_GET);
	PUSH_SET_INT("MSG_TYPE_PUT", MSG_TYPE_PUT);
	PUSH_SET_INT("MSG_TYPE_DEL", MSG_TYPE_DEL);
	PUSH_SET_INT("MSG_CLASS_DATA", MSG_CLASS_DATA);
	PUSH_SET_INT("MSG_CLASS_ARRAY", MSG_CLASS_ARRAY);

	lua_settable(L, -3);

	lua_pop(L, 1);
}


