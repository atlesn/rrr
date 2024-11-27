#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_PERL5" != 'xno'; then
	do_test_simple test_http_tag_ignore.conf
else
	echo "Skipped test_http_tag_ignore.conf as Perl5 support is missing"
fi
