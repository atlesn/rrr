#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_NGHTTP2" != 'xno'; then
	do_test_socket test_http2.conf
else
	echo "Skipped test_http2.conf as HTTP2 support is missing"
fi
