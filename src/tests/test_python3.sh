#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_PYTHON3" != 'xno'; then
	do_test_socket test_python3.conf
else
	echo "Skipped test_python3.conf as Python3 support is missing"
fi
