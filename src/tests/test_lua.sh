#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_LUA" != 'xno'; then
	do_test_socket test_lua.conf
else
	echo "Skipped test_lua.conf as Lua support is missing"
fi
