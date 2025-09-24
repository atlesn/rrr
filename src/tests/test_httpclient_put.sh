#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_PERL5" != 'xno'; then
	rm -rf /tmp/rrr-test-httpclient-put

	do_test_simple test_httpclient_put.conf

	rm -rf /tmp/rrr-test-httpclient-put
else
	echo "Skipped test_httpclient_put.conf as Perl5 support is missing"
fi
