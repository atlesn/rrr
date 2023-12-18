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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "lua_message.h"
#include "lua_common.h"
#include "lua_types.h"

#include "../array.h"
#include "../allocator.h"
#include "../log.h"
#include "../fixed_point.h"
#include "../helpers/string_builder.h"
#include "../ip/ip_defines.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../cmodule/cmodule_worker.h"

struct rrr_lua_message {
	const struct rrr_lua *lua;
	int usercount;
	struct rrr_array array;
	struct sockaddr_storage ip_addr;
	socklen_t ip_addr_len;
};

static int __rrr_lua_message_new (
		struct rrr_lua_message **result,
		const struct rrr_lua *lua
) {
	int ret = 0;

	struct rrr_lua_message *message;

	if ((message = rrr_allocate_zero(sizeof(*message))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	message->lua = lua;
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

static int __rrr_lua_message_set_ip_from_str (
		struct rrr_lua_message *target,
		const char *ip,
		rrr_slength port,
		void (*error_callback)(const char *msg, void *arg),
		void *error_callback_arg
) {
	int ret = 0;

	char err[128];
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} addr;
	socklen_t ip_addr_len = 0;

	memset(&addr, 0, sizeof(addr));

	if (strlen(ip) == 0) {
		goto write;
	}

	if (port < 1 || port > 65535) {
		snprintf(err, sizeof(err), "Failed to set IP in %s, port out of range (%" PRIrrrsl ")\n", __func__, port);
		error_callback(err, error_callback_arg);
		ret = 1;
		goto out;
	}

	if (strchr(ip, ':') != NULL) {
		// IPv6
		ip_addr_len = sizeof(addr.in6);
		addr.in6.sin6_family = AF_INET6;
		addr.in6.sin6_port = htons(port);
		if (inet_pton(AF_INET6, ip, &addr.in6.sin6_addr) != 1) {
			snprintf(err, sizeof(err), "Failed to set IP in %s, invalid IPv6 address (%s)\n", __func__, ip);
			error_callback(err, error_callback_arg);
			ret = 1;
			goto out;
		}
	}
	else {
		// IPv4
		ip_addr_len = sizeof(addr.in);
		addr.in.sin_family = AF_INET;
		addr.in.sin_port = htons(port);
		if (inet_pton(AF_INET, ip, &addr.in.sin_addr) != 1) {
			snprintf(err, sizeof(err), "Failed to set IP in %s, invalid IPv4 address (%s)\n", __func__, ip);
			error_callback(err, error_callback_arg);
			ret = 1;
			goto out;
		}
	}

	write:
	memcpy(&target->ip_addr, &addr, ip_addr_len);
	target->ip_addr_len = ip_addr_len;

	out:
	return ret;
}

static void __rrr_lua_message_error_callback (
		const char *msg,
		void *arg
) {
	lua_State *L = arg;
	luaL_error(L, "%s", msg);
}

#define WITH_MSG_META(code) \
  RRR_LUA_WITH_SELF_META(message,RRR_LUA_META_KEY_RRR_MESSAGE,code)
 
#define SET_MSG(nargs,func_name) \
  RRR_LUA_SET_SELF(message,RRR_LUA_META_KEY_RRR_MESSAGE,nargs,func_name)

#define WITH_MSG(nargs,func_name,code) \
  RRR_LUA_WITH_SELF(message,RRR_LUA_META_KEY_RRR_MESSAGE,nargs,func_name,code)

#define SET_KEY(k) \
  RRR_LUA_SET_STR(k,2)

/*
 * NOTE : Error handling in the push functions is done by Lua which
 *        performs longjmp back to Lua in the luaL_error call.
 */

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
		__rrr_lua_message_set_ip_from_str(message, ip, port, __rrr_lua_message_error_callback, L);
	);

	return 0;
}

static int __rrr_lua_message_f_ip_get(lua_State *L) {
	char buf[INET6_ADDRSTRLEN];

	WITH_MSG (0,ip_get,
		if (message->ip_addr_len == 0) {
			lua_pushliteral(L, "");
			lua_pushinteger(L, 0);
		}
		else {
			if (getnameinfo((struct sockaddr *) &message->ip_addr, message->ip_addr_len, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) != 0) {
				luaL_error(L, "Failed to get IP in %s, getnameinfo failed\n", __func__);
			}
			lua_pushstring(L, buf);
			lua_pushinteger(L, ntohs(((struct sockaddr_in *) &message->ip_addr)->sin_port));
		}
	);

	return 2;
}

static int __rrr_lua_message_f_ip_clear(lua_State *L) {
	WITH_MSG (0,ip_clear,
		memset(&message->ip_addr, 0, sizeof(message->ip_addr));
		message->ip_addr_len = 0;
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

// This function is extraction of the inner function below taking blob/str type argument but otherwise being the same
// It checks if top stack element is table or not
static void __rrr_lua_message_push_tag_blob_str (
		lua_State *L,
		const struct rrr_type_definition *definition
) {
	struct rrr_string_builder acc = {0};
	char err[128];
	struct rrr_type_value *value;
	rrr_length element_count = 0;
	size_t str_len, str_len2;
	const char *v;
	lua_Integer len, i;

	WITH_MSG(2,push_tag_str,
		SET_KEY(k);

		if (lua_type(L, -1) == LUA_TTABLE) {
			if ((len = lua_rawlen(L, -1)) < 1) {
				snprintf(err, sizeof(err), "Failed to push value in %s, table was empty\n", __func__);
				goto err;
			}
			for (i = 1; i <= len; i++) {
				lua_geti(L, -1, i);
				if ((v = lua_tolstring(L, -1, &str_len)) == NULL) {
					snprintf(err, sizeof(err), "Failed to push value in %s, value was not convertible to string (type is %s)\n",
						__func__, luaL_typename(L, -1));
					goto err;
				}

				if (i == 1) {
					if (str_len == 0) {
						snprintf(err, sizeof(err), "Failed to push value in %s, string was empty\n", __func__);
						goto err;
					}
					str_len2 = str_len;
				}
				else if (str_len != str_len2) {
					snprintf(err, sizeof(err), "Failed to push value in %s, table contained strings of different length\n", __func__);
					goto err;
				}

				if (rrr_string_builder_append_raw(&acc, v, str_len) != 0) {
					snprintf(err, sizeof(err), "Failed to push value in %s, failed to append string to string builder\n", __func__);
					goto err;
				}
				element_count++;

				lua_pop(L, 1);
			}
		}
		else {
			if ((v = lua_tolstring(L, -1, &str_len)) == NULL) {
				snprintf(err, sizeof(err), "Failed to push value in %s, value was not convertible to string (type is %s)\n",
					__func__, luaL_typename(L, -1));
				goto err;
			}
			if (rrr_string_builder_append_raw(&acc, v, str_len) != 0) {
				snprintf(err, sizeof(err), "Failed to push value in %s, failed to append string to string builder\n", __func__);
				goto err;
			}
			element_count++;
		}

		if (rrr_string_builder_length(&acc) > RRR_LENGTH_MAX) {
			snprintf(err, sizeof(err), "Failed to push value in %s, string length exceeds maximum (%llu>%llu)\n",
				__func__, (unsigned long long) rrr_string_builder_length(&acc), (unsigned long long) RRR_LENGTH_MAX);
			goto err;
		}

		if (rrr_type_value_new (
				&value,
				definition,
				0,
				rrr_length_from_size_t_bug_const(strlen(k)),
				k,
				0,
				NULL,
				element_count,
				NULL,
				rrr_length_from_biglength_bug_const(rrr_string_builder_length(&acc))
		) != 0) {
			snprintf(err, sizeof(err), "Failed to push value in %s, failed to create type value\n", __func__);
			goto err;
		}

		memcpy(value->data, rrr_string_builder_buf(&acc), rrr_size_from_biglength_bug_const(rrr_string_builder_length(&acc)));

		RRR_LL_APPEND(&message->array, value);
	);

	goto out;
	err:
		rrr_string_builder_clear(&acc);
		luaL_error(L, "%s", err);
		assert(0 && "Unreachable");
	out:
		rrr_string_builder_clear(&acc);
}

static int __rrr_lua_message_f_push_tag_blob(lua_State *L) {
	__rrr_lua_message_push_tag_blob_str(L, &rrr_type_definition_blob);
	return 0;
}

static int __rrr_lua_message_f_push_tag_str(lua_State *L) {
	__rrr_lua_message_push_tag_blob_str(L, &rrr_type_definition_str);
	return 0;
}

static void __rrr_lua_message_push_tag_h_convert (
		int64_t *result,
		rrr_type_flags *result_flags,
		lua_State *L,
		const char *debug_k
) {
	int isnum;
	lua_Integer i;
	long long int lli;
	long long unsigned int llu;
	const char *str;
	size_t str_len;
	const char *endptr;

	i = lua_tointegerx(L, -1, &isnum);
	if (isnum) {
		*result = i;
		*result_flags = (i < 0 ? RRR_TYPE_FLAG_SIGNED : 0);
		return;
	}

	if ((str = lua_tolstring(L, -1, &str_len)) == NULL) {
		luaL_error(L, "Failed to push value with key %s to array, value was not convertible to string (type is %s)\n",
			debug_k, luaL_typename(L, -1));
	}
	if (str_len == 0) {
		luaL_error(L, "Failed to push value with key %s to array, string was empty\n", debug_k);
	}

	errno = 0;

	if (*str == '-') {
		lli = strtoll(str, (char **) &endptr, 10);
		if (errno == ERANGE) {
			luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, value out of range\n", debug_k);
		}
		if (str + str_len != endptr) {
			if (*endptr != '.') {
				luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, string was not fully converted\n", debug_k);
			}
		}
		*result = lli;
		*result_flags = RRR_TYPE_FLAG_SIGNED;
	}
	else {
		llu = strtoull(str, (char **) &endptr, 10);
		if (errno == ERANGE) {
			luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, value out of range\n", debug_k);
		}
		if (str + str_len != endptr) {
			if (*endptr != '.') {
				luaL_error(L, "Failed to convert string to integer while pushing value with key %s to array, string was not fully converted\n", debug_k);
			}
		}
		*result = (int64_t) llu;
		*result_flags = 0;
	}
}

static void __rrr_lua_message_push_tag_64_get_stored_length_and_count (
		lua_State *L,
		rrr_length *result_stored_length,
		rrr_length *result_count
) {
	rrr_length stored_length, element_count;

	if (lua_type(L, -1) == LUA_TTABLE) {
		if ((element_count = lua_rawlen(L, -1)) < 1) {
			luaL_error(L, "Failed to push value in %s, table was empty\n", __func__);
		}
		stored_length = element_count;
		rrr_length_mul_bug(&stored_length, (rrr_length) sizeof(int64_t));
	}
	else {
		element_count = 1;
		stored_length = (rrr_length) sizeof(int64_t);
	}

	*result_count = element_count;
	*result_stored_length = stored_length;
}

// Function for creating value for 64 types, used by push_tag_h and push_tag_fixp
static void __rrr_lua_message_push_tag_64_create_value (
		struct rrr_type_value **result,
		lua_State *L,
		const char *k,
		rrr_length stored_length,
		rrr_length element_count,
		const struct rrr_type_definition *definition
) {
	if (rrr_type_value_new (
			result,
			definition,
			0,
			rrr_length_from_size_t_bug_const(strlen(k)),
			k,
			0,
			NULL,
			element_count,
			NULL,
			stored_length
	) != 0) {
		luaL_error(L, "Failed to push value in %s, failed to create type value\n", __func__);
	}
}

static void __rrr_lua_message_push_tag_h(lua_State *L) {
	struct rrr_type_value *value;
	rrr_length stored_length, element_count;

	WITH_MSG(2,push_tag_h,
		SET_KEY(k);

		__rrr_lua_message_push_tag_64_get_stored_length_and_count(L, &stored_length, &element_count);
		__rrr_lua_message_push_tag_64_create_value(&value, L, k, stored_length, element_count, &rrr_type_definition_h);

		if (element_count == 1) {
			__rrr_lua_message_push_tag_h_convert (
					(int64_t *) value->data,
					&value->flags,
					L,
					k
			);
		}
		else {
			int force_unsigned = 0;
			int force_signed = 0;
			int wpos = 0;

			for (rrr_length i = 1; i <= element_count; i++) {
				union {
					int64_t lli;
					uint64_t llu;
				} ll;
				rrr_type_flags flags = 0;

				lua_geti(L, -1, i);
				__rrr_lua_message_push_tag_h_convert(&ll.lli, &flags, L, k);
				lua_pop(L, 1);

				if (RRR_TYPE_FLAG_IS_SIGNED(flags)) {
					assert(ll.lli < 0);
					if (force_unsigned) {
						luaL_error(L, "Failed to convert integer while pushing value with key %s to array, string was negative while unsigned conversion was forced due to another large unsigned integer\n", k);
					}
					force_signed = 1;
				}
				else if (ll.llu > INT64_MAX) {
					if (force_signed) {
						luaL_error(L, "Failed to convert integer while pushing value with key %s to array, unsigned value out of range due to another negative integer\n", k);
					}
					force_unsigned = 1;
				}

				memcpy((int64_t *) value->data + (wpos++), &ll.lli, sizeof(ll.lli));
				value->flags |= flags;
			}
		}

		RRR_LL_APPEND(&message->array, value);
	);
}

static void __rrr_lua_message_push_tag_fixp_convert_ld (
		rrr_fixp *result,
		lua_State *L,
		long double n,
		const char *debug_k,
		int precision_loss_warnings
) {
	rrr_fixp fixp;
	long double n_test;

	if (rrr_fixp_from_ldouble(&fixp, n) != 0) {
		luaL_error(L, "Could not convert floating point number '%s' to RRR fixed point while pusing to array\n",
			lua_tostring(L, -2));
	}

	if (rrr_fixp_to_ldouble(&n_test, fixp) != 0) {
		luaL_error(L, "Failed to convert floating point number '%s' to RRR fixed point while pushing to array\n",
			lua_tostring(L, -2));
	}

	if (precision_loss_warnings && n_test != n) {
		RRR_MSG_0("Warning: Precision loss while converting lua Number '%Lf' to fixed point " \
		          "while pushing array value with key '%s'. Consider passing as string instead.\n",
			n, debug_k);
	}

	*result = fixp;
}

static void __rrr_lua_message_push_tag_fixp_convert_str (
		rrr_fixp *result,
		lua_State *L,
		const char *debug_k
) {
	const char *str;
	size_t str_len;
	const char *endptr;
	rrr_fixp fixp;

	if ((str = lua_tolstring(L, -1, &str_len)) == NULL) {
		luaL_error(L, "Failed to push value with key %s to array, value was not convertible to string (type is %s)\n",
			debug_k, luaL_typename(L, -1));
	}
	if (str_len == 0) {
		luaL_error(L, "Failed to push value with key %s to array, string was empty\n", debug_k);
	}
	if (rrr_fixp_str_to_fixp(&fixp, str, rrr_length_from_size_t_bug_const(str_len), &endptr) != 0) {
		luaL_error(L, "Failed to convert string to fixed point number while pushing value with key %s to array\n", debug_k);
	}
	if (endptr != str + str_len) {
		luaL_error(L, "Failed to convert string to fixed point number while pushing value with key %s to array, string was not fully converted\n", debug_k);
	}

	*result = fixp;
}

static void __rrr_lua_message_push_tag_fixp_convert (
		rrr_fixp *result,
		lua_State *L,
		const char *debug_k,
		int precision_loss_warnings
) {
	lua_Number n;
	int isnum;

	n = lua_tonumberx(L, -1, &isnum);
	if (isnum) {
		__rrr_lua_message_push_tag_fixp_convert_ld (result, L, n, debug_k, precision_loss_warnings);
	}
	else {
		__rrr_lua_message_push_tag_fixp_convert_str (result, L, debug_k);
	}
}

static int __rrr_lua_message_push_tag_fixp(lua_State *L) {
	struct rrr_type_value *value;
	rrr_length stored_length, element_count;

	WITH_MSG(2,push_tag_fixp,
		SET_KEY(k);

		__rrr_lua_message_push_tag_64_get_stored_length_and_count(L, &stored_length, &element_count);
		__rrr_lua_message_push_tag_64_create_value(&value, L, k, stored_length, element_count, &rrr_type_definition_fixp);

		if (element_count == 1) {
			__rrr_lua_message_push_tag_fixp_convert (
					(rrr_fixp *) value->data,
					L,
					k,
					message->lua->precision_loss_warnings
			);
		}
		else {
			for (rrr_length i = 1; i <= element_count; i++) {
				lua_geti(L, -1, i);
				__rrr_lua_message_push_tag_fixp_convert (
						(rrr_fixp *) value->data + (i - 1),
						L,
						k,
						message->lua->precision_loss_warnings
				);
				lua_pop(L, 1);
			}
		}

		RRR_LL_APPEND(&message->array, value);
	);
	
	return 0;
}

static void __rrr_lua_message_push_tag_boolean(lua_State *L) {
	struct rrr_type_value *value;
	rrr_length stored_length, element_count;

	WITH_MSG(2,push_tag_boolean,
		SET_KEY(k);

		// Use h type for storage but convert using toboolean

		__rrr_lua_message_push_tag_64_get_stored_length_and_count(L, &stored_length, &element_count);
		__rrr_lua_message_push_tag_64_create_value(&value, L, k, stored_length, element_count, &rrr_type_definition_h);

		if (element_count == 1) {
			*((int64_t *) value->data) = lua_toboolean(L, -1);
		}
		else {
			for (rrr_length i = 1; i <= element_count; i++) {
				lua_geti(L, -1, i);
				*((int64_t *) value->data + (i - 1)) = lua_toboolean(L, -1);
				lua_pop(L, 1);
			}
		}

		RRR_LL_APPEND(&message->array, value);
	);
}

static void __rrr_lua_message_push_tag_vain(lua_State *L) {
	WITH_MSG(2,push_tag_vain,
		SET_KEY(k);
		if (lua_type(L, -1) == LUA_TTABLE) {
			luaL_error(L, "Failed to push value in %s, cannot push multiple nil/vain values\n", __func__);
		}
		if (rrr_array_push_value_vain_with_tag(&message->array, k) != 0) {
			luaL_error(L, "Failed to push vain value to array in %s\n",
				__func__);
		}
	);
}

static int __rrr_lua_message_f_push_tag_h(lua_State *L) {
	__rrr_lua_message_push_tag_h(L);
	return 0;
}

static int __rrr_lua_message_f_push_tag_fixp(lua_State *L) {
	__rrr_lua_message_push_tag_fixp(L);
	return 0;
}

static int __rrr_lua_message_f_push_tag(lua_State *L) {
	int type;

	WITH_MSG(2,push_tag,
		(void)(message);

		SET_KEY(k);

		if (lua_type(L, -1) == LUA_TTABLE) {
			if (lua_rawlen(L, -1) < 1) {
				luaL_error(L, "Failed to push value in %s, table was empty\n", __func__);
			}
			type = lua_geti(L, -1, 1);
		}
		else {
			type = lua_type(L, -1);
			lua_pushvalue(L, -1);
		}

		switch(type) {
			case LUA_TNIL: {
				lua_pop(L, 1);
				__rrr_lua_message_push_tag_vain(L);
			} break;
			case LUA_TNUMBER: {
				int isnum = 0;

				// Try integer
				lua_tointegerx(L, -1, &isnum);
				if (isnum) {
					lua_pop(L, 1);
					__rrr_lua_message_push_tag_h(L);
					break;
				}

				// Try double
				lua_tonumberx(L, -1, &isnum);
				if (isnum) {
					lua_pop(L, 1);
					__rrr_lua_message_push_tag_fixp(L);
					break;
				}

				luaL_error(L, "Failed to convert number '%s' to integer or fixed point while pusing value to array\n", lua_tostring(L, -1));
			} break;
			case LUA_TBOOLEAN: {
				lua_pop(L, 1);
				__rrr_lua_message_push_tag_boolean(L);
			} break;
			case LUA_TSTRING: {
				lua_pop(L, 1);
				__rrr_lua_message_push_tag_blob_str(L, &rrr_type_definition_str);
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
	__rrr_lua_message_push_tag_blob_str(L, &rrr_type_definition_blob);
	return 0;
}

static int __rrr_lua_message_f_set_tag_str(lua_State *L) {
	SET_MSG(2,set_tag_str);
	SET_KEY(k);
	rrr_array_clear_by_tag(&message->array, k);
	__rrr_lua_message_push_tag_blob_str(L, &rrr_type_definition_str);
	return 0;
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
		const struct rrr_type_value *value,
		int *wpos,
		int precision_loss_warnings
) {
	char buf[128];
	int buf_len;
	const rrr_length len = value->total_stored_length / value->element_count;

	// Assume a table is already pushed

	switch (value->definition->type) {
		case RRR_TYPE_MSG:
		RRR_TYPE_CASE_BLOB:
			if (len == 0) {
				luaL_error(L, "Failed to convert value to Lua, blob length was zero. This is probably a bug.\n");
			}
			/* Fallthrough */
		RRR_TYPE_CASE_STR: {
			if (len == 0) {
				lua_pushlstring(L, "", 0);
				lua_seti(L, -2, (*wpos)++);
				break;
			}
			for (rrr_length i = 0; i < value->total_stored_length; i += len) {
				lua_pushlstring(L, value->data + i, len);
				lua_seti(L, -2, (*wpos)++);
			}
		} break;
		case RRR_TYPE_H: {
			assert(len == sizeof(int64_t));
			RRR_ASSERT(LDBL_MANT_DIG >= 64,long_double_can_hold_64_bits);
			RRR_ASSERT(sizeof(lua_Number) >= sizeof(double),double_fits_in_lua_number);
			RRR_ASSERT(sizeof(uint64_t) >= sizeof(strtoull),uint64_t_can_hold_strtoull_result);
			if (RRR_TYPE_FLAG_IS_SIGNED(value->flags)) {
				for (rrr_length i = 0; i < value->total_stored_length; i += len) {
					int64_t    x = *((int64_t *) (value->data + i));
					lua_Number n = (lua_Number) x;
					if ((int64_t) n != x) {
						if (precision_loss_warnings) {
							RRR_MSG_0("Warning: Precision loss while converting signed value '%" PRIi64 "' to Lua number. Passing as string instead.\n",
								x);
						}
						buf_len = sprintf(buf, "%" PRIi64, x);
						lua_pushlstring(L, buf, (size_t) buf_len);
						lua_seti(L, -2, (*wpos)++);
					}
					else {
						lua_pushinteger(L, (lua_Number) x);
						lua_seti(L, -2, (*wpos)++);
					}
				}
			}
			else {
				for (rrr_length i = 0; i < value->total_stored_length; i += len) {
					uint64_t   x = *((uint64_t *) (value->data + i));
					lua_Number n = (lua_Number) x;
					char *end;
					sprintf(buf, "%Lf", (long double) n);
					errno = 0;
					strtoull(buf, &end, 10);
					if (errno || (uint64_t) n != x) {
						if (precision_loss_warnings) {
							RRR_MSG_0("Warning: Precision loss while converting unsigned value '%" PRIu64 "' to Lua number. Passing as string instead.\n",
								x);
						}
						buf_len = sprintf(buf, "%" PRIu64, x);
						lua_pushlstring(L, buf, (size_t) buf_len);
						lua_seti(L, -2, (*wpos)++);
					}
					else {
						lua_pushinteger(L, (lua_Number) x);
						lua_seti(L, -2, (*wpos)++);
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
					if (precision_loss_warnings) {
						RRR_MSG_0("Warning: Precision loss while converting fixed point value to Lua number. Passing as string instead.\n");
					}
					buf_len = sprintf(buf, "%Lf", (long double) number);
					lua_pushlstring(L, buf, (size_t) buf_len);
					lua_seti(L, -2, (*wpos)++);
				}
				else {
					lua_pushnumber(L, number);
					lua_seti(L, -2, (*wpos)++);
				}
			}
			break;
		case RRR_TYPE_VAIN:
			lua_pushnil(L);
			lua_seti(L, -2, (*wpos)++);
			break;
		case RRR_TYPE_LE:
		case RRR_TYPE_BE:
		case RRR_TYPE_USTR:
		case RRR_TYPE_ISTR:
		case RRR_TYPE_ERR:
		default:
			RRR_BUG("Type %i/%s not implemented\n", value->definition->type, value->definition->identifier);
	};
}

static int __rrr_lua_message_f_get_tag_all(lua_State *L) {
	int results = 0;

	WITH_MSG(1,get_tag_all,
		const char *key = lua_tostring(L, -1);

		lua_newtable(L);
		results++;

		int wpos = 1;
		RRR_LL_ITERATE_BEGIN(&message->array, struct rrr_type_value);
			if (!rrr_type_value_is_tag(node, key)) {
				RRR_LL_ITERATE_NEXT();
			}
			__rrr_lua_message_array_value_to_lua(
					L,
					node,
					&wpos,
					message->lua->precision_loss_warnings
			);
		RRR_LL_ITERATE_END();
	);

	return results;
}

static int __rrr_lua_message_f_get_position(lua_State *L) {
	int results = 0;

	WITH_MSG(1,get_position,
		lua_Integer pos = lua_tointeger(L, -1);
		if (pos < 1) {
			luaL_error(L, "Position must be greater than 0\n");
		}

		if (pos > RRR_LL_COUNT(&message->array)) {
			lua_pushnil(L);
			results++;
			return results;
		}

		lua_newtable(L);
		results++;

		// Lua is 1-based, RRR is 0-based
		pos--;

		int wpos = 1;
		int i = 0;
		RRR_LL_ITERATE_BEGIN(&message->array, struct rrr_type_value);
			if (i == pos) {
				__rrr_lua_message_array_value_to_lua (
						L,
						node,
						&wpos,
						message->lua->precision_loss_warnings
				);
				RRR_LL_ITERATE_BREAK();
			}
			i++;
		RRR_LL_ITERATE_END();

		assert(i == pos);
	);

	return results;
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
		RRR_LUA_WITH_CMODULE (
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

	RRR_LUA_PUSH_SET_STR("ip_so_type", "");
	RRR_LUA_PUSH_SET_STR("topic", "");
	RRR_LUA_PUSH_SET_STR("data", "");
	RRR_LUA_PUSH_SET_INT("type", MSG_TYPE_MSG);
	RRR_LUA_PUSH_SET_INT("class", MSG_CLASS_DATA);

	if (sizeof(lua_Integer) >= 8) {
		RRR_LUA_PUSH_SET_INT("timestamp", (lua_Integer) rrr_time_get_i64());
	}

	luaL_newlib(L, f_meta);

	RRR_LUA_PUSH_SET_USERDATA(RRR_LUA_META_KEY_RRR_MESSAGE, message);

	lua_setmetatable(L, -2);

	return results;
}

static int __rrr_lua_message_f_new(lua_State *L) {
	int results = 0;

	struct rrr_lua_message *message = NULL;

	RRR_LUA_WITH_LUA_GLOBAL (
		if (__rrr_lua_message_new(&message, lua) != 0) {
			luaL_error(L, "Failed to create internal message in %s\n",
				__func__);
		}
	);

	results = __rrr_lua_message_construct(L, message);
	assert(results == 1);

	return 1;
}

static int __rrr_lua_message_set_meta (
		struct rrr_lua *target,
		rrr_u64 timestamp,
		rrr_u8 type,
		rrr_u8 class,
		const char *topic,
		rrr_u16 topic_len,
		uint8_t protocol
) {
	lua_State *L = target->L;

	int ret = 0;

	if (timestamp > INT64_MAX) {
		RRR_MSG_0("Timestamp exceeds maximum value in message to Lua module (%" PRIu64 ">%" PRIi64 ")\n",
			timestamp, INT64_MAX);
		ret = 1;
		goto out;
	}

	RRR_ASSERT(sizeof(lua_Integer) >= 8, lua_integer_is_at_least_64_bits);

	lua_pushstring(L, "timestamp");
	lua_pushinteger(L, (lua_Integer) timestamp);
	lua_settable(L, -3);

	lua_pushstring(L, "type");
	lua_pushinteger(L, (lua_Integer) type);
	lua_settable(L, -3);

	lua_pushstring(L, "class");
	lua_pushinteger(L, (lua_Integer) class);
	lua_settable(L, -3);

	if (topic_len > 0) {
		assert(topic != NULL);

		lua_pushstring(L, "topic");
		lua_pushlstring(L, topic, topic_len);
		lua_settable(L, -3);
	}

	lua_pushstring(L, "ip_so_type");
	switch (protocol) {
		case RRR_IP_AUTO:
			lua_pushliteral(L, "");
			break;
		case RRR_IP_UDP:
			lua_pushliteral(L, "udp");
			break;
		case RRR_IP_TCP:
			lua_pushliteral(L, "tcp");
			break;
		default:
			assert(0 && "Unknown protocol");
	};
	lua_settable(L, -3);

	out:
	return ret;
}

static int __rrr_lua_message_push_new_populated (
		struct rrr_lua *target,
		rrr_u64 timestamp,
		rrr_u8 type,
		rrr_u8 class,
		const char *topic,
		rrr_length topic_len,
		const struct sockaddr *ip_addr,
		socklen_t ip_addr_len,
		uint8_t protocol,
		struct rrr_array *array_victim
) {
	int ret = 0;

	struct rrr_lua_message *message = NULL;
	int results = 0;

	if ((ret = __rrr_lua_message_new(&message, target)) != 0) {
		RRR_MSG_0("Failed to create internal message in %s\n",
			__func__);
		goto out;
	}

	results = __rrr_lua_message_construct(target->L, message);
	assert(results == 1);

	if (ip_addr_len > 0) {
		assert(ip_addr != NULL);
		memcpy(&message->ip_addr, ip_addr, ip_addr_len);
		message->ip_addr_len = ip_addr_len;
	}

	if ((ret = __rrr_lua_message_set_meta (
			target,
			timestamp,
			type,
			class,
			topic,
			topic_len,
			protocol
	)) != 0) {
		goto out_decref;
	}

	if (array_victim != NULL) {
		assert(class == MSG_CLASS_ARRAY);
		RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&message->array, array_victim);
	}
	else {
		assert(class == MSG_CLASS_DATA);
	}

	goto out;
	out_decref:
		__rrr_lua_message_decref(message);
	out:
		return ret;
}

int rrr_lua_message_push_new (
		struct rrr_lua *target
) {
	return __rrr_lua_message_push_new_populated (
			target,
			rrr_time_get_64(),
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			NULL,
			0,
			NULL,
			0,
			RRR_IP_AUTO,
			NULL
	);
}

int rrr_lua_message_push_new_data (
		struct rrr_lua *target,
		rrr_u64 timestamp,
		rrr_u8 type,
		const char *topic,
		rrr_length topic_len,
		const struct sockaddr *ip_addr,
		socklen_t ip_addr_len,
		uint8_t protocol,
		const char *data,
		rrr_length data_length
) {
	int ret = 0;

	if ((ret = __rrr_lua_message_push_new_populated (
			target,
			timestamp,
			type,
			MSG_CLASS_DATA,
			topic,
			topic_len,
			ip_addr,
			ip_addr_len,
			protocol,
			NULL
	)) != 0) {
		goto out;
	}

	lua_pushstring(target->L, "data");
	lua_pushlstring(target->L, data, data_length);
	lua_settable(target->L, -3);

	out:
	return ret;
}

int rrr_lua_message_push_new_array (
		struct rrr_lua *target,
		rrr_u64 timestamp,
		rrr_u8 type,
		const char *topic,
		rrr_length topic_len,
		const struct sockaddr *ip_addr,
		socklen_t ip_addr_len,
		uint8_t protocol,
		struct rrr_array *array_victim
) {
	return __rrr_lua_message_push_new_populated (
			target,
			timestamp,
			type,
			MSG_CLASS_ARRAY,
			topic,
			topic_len,
			ip_addr,
			ip_addr_len,
			protocol,
			array_victim
	);
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

	RRR_LUA_PUSH_SET_INT("MSG_TYPE_MSG", MSG_TYPE_MSG);
	RRR_LUA_PUSH_SET_INT("MSG_TYPE_TAG", MSG_TYPE_TAG);
	RRR_LUA_PUSH_SET_INT("MSG_TYPE_GET", MSG_TYPE_GET);
	RRR_LUA_PUSH_SET_INT("MSG_TYPE_PUT", MSG_TYPE_PUT);
	RRR_LUA_PUSH_SET_INT("MSG_TYPE_DEL", MSG_TYPE_DEL);
	RRR_LUA_PUSH_SET_INT("MSG_CLASS_DATA", MSG_CLASS_DATA);
	RRR_LUA_PUSH_SET_INT("MSG_CLASS_ARRAY", MSG_CLASS_ARRAY);

	lua_settable(L, -3);

	lua_pop(L, 1);
}


