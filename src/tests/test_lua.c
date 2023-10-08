/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "test.h"
#include "test_lua.h"
#include "../lib/lua/lua.h"
#include "../lib/lua/lua_message.h"
#include "../lib/util/macro_utils.h"

static int __rrr_test_lua_execute_snippet (
		struct rrr_lua *lua,
		const char *snippet,
		int expect_ret
) {
	int ret = 0;

	TEST_MSG("\n");
	TEST_MSG(" ===================== \n");
	TEST_MSG(" === Execute snippet...\n");

	if ((ret = rrr_lua_execute_snippet(lua, snippet, strlen(snippet))) != expect_ret) {
		TEST_MSG(" === Test FAILED, unexpected return %i from Lua snippet '%s' (expected %i)\n",
			ret, snippet, expect_ret);
		ret = 1;
	}
	else {
		TEST_MSG(" === Test successful, return value was %i as expected\n", ret);
		ret = 0;
	}

	rrr_lua_assert_empty_stack(lua);

	return ret;
}

static int __rrr_test_lua_call (
		struct rrr_lua *lua,
		const char *function,
		int a,
		int b,
		int expect_ret
) {
	int ret = 0;

	TEST_MSG("\n");
	TEST_MSG(" ===================== \n");
	TEST_MSG(" === Call...\n");

	rrr_lua_pushint(lua, a);
	rrr_lua_pushint(lua, b);

	if ((ret = rrr_lua_call(lua, function, 2)) != expect_ret) {
		TEST_MSG(" === Test FAILED, unexpected return %i while calling function '%s' (expected %i)\n",
			ret, function, expect_ret);
		ret = 1;
	}
	else {
		TEST_MSG(" === Test successful, return value was %i as expected\n", ret);
		ret = 0;
	}

	rrr_lua_assert_empty_stack(lua);

	return ret;
}

int rrr_test_lua(void) {
	int ret = 0;

	struct rrr_lua *lua;

	if ((ret = rrr_lua_new(&lua)) != 0) {
		TEST_MSG("Failed to craete Lua in %s\n", __func__);
		goto out;
	}

	// Use this function for debugging the test as needed
	// rrr_lua_dump_and_clear_stack(lua);

	rrr_lua_message_library_register(lua);

	TEST_MSG("\n+++ Execute Lua snippet...\n");
	ret |= __rrr_test_lua_execute_snippet(lua, "a = 1 - 1\nreturn a", 0);

	TEST_MSG("\n+++ Iterate RRR table...\n");
	ret |= __rrr_test_lua_execute_snippet(lua,
		"for k, v in pairs(RRR) do\n" \
		"  print(k, \"=>\", v)\n"     \
		"end"
	, 0);

	TEST_MSG("\n+++ Make RRR Message...\n");
	ret |= __rrr_test_lua_execute_snippet(lua,
		"msg = RRR.Message:new()\n"   \
		"for k, v in pairs(msg) do\n" \
		"  print(k, \"=>\", v)\n"     \
		"end"
	, 0);

	/*
	 * Only error conditions raising errors are tested here
	 * as they cannot be tested in the full scale test without
	 * fatal error
	 */
	TEST_MSG("\n+++ Push invalid values to message...\n");
	// One valid push to verify that everything works
	ret |= __rrr_test_lua_execute_snippet (lua,
		"msg = RRR.Message:new()\n"                        \
		"msg:push_tag_str(\"key\", \"value\")\n"           \
		"assert(msg:get_tag_all(\"key\")[1] == \"value\")"
	, 0);
	// Key is invalid type
	ret |= __rrr_test_lua_execute_snippet (lua,
		"msg = RRR.Message:new()\n"   \
		"msg:push_tag_str({}, \"value\")"
	, 1);

	// Value is invalid value
	ret |= __rrr_test_lua_execute_snippet (lua,
		"msg = RRR.Message:new()\n"   \
		"msg:push_tag_str(\"key\", {})"
	, 1);

	TEST_MSG("\n+++ Create and call function (failing, arguments are swapped around)...\n");
	ret |= __rrr_test_lua_execute_snippet(lua,
		"function f(a,b)\n"   \
		"  assert(a==1)\n"    \
		"  assert(b==2)\n"    \
		"  return true\n"     \
		"end"
	, 0);
	ret |= __rrr_test_lua_call (lua, "f", 2, 1, 1);

	TEST_MSG("\n+++ Call function (succeeding)...\n");
	ret |= __rrr_test_lua_execute_snippet(lua,
		"function f(a,b)\n"   \
		"  assert(a==1)\n"    \
		"  assert(b==2)\n"    \
		"  return true\n"     \
		"end"
	, 0);
	ret |= __rrr_test_lua_call (lua, "f", 1, 2, 0);

	goto out_destroy;
	out_destroy:
		rrr_lua_destroy(lua);
	out:
		return ret;
}
