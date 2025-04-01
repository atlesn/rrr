#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_PERL5" != 'xno'; then
	rm -rf /tmp/rrr-test-msgdb-id
	rm -rf /tmp/rrr-test-msgdb-put

	do_test_simple test_incrementer.conf

	rm -rf /tmp/rrr-test-msgdb-id
	rm -rf /tmp/rrr-test-msgdb-put
else
	echo "Skipped test_incrementer.conf as Perl5 support is missing"
fi
