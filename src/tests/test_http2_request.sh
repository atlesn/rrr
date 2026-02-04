#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_NGHTTP2" != 'xno'; then
	do_test_simple test_http2_request.conf
else
	echo "Skipped test_http2_request.conf as HTTP2 support is missing"
fi
