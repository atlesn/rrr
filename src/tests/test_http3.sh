#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_HTTP3" != 'xno'; then
	do_test_socket test_http3.conf
else
	echo "Skipped test_http3.conf as HTTP3 support is missing"
fi
