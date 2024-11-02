#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_PERL5" != 'xno'; then
	do_test_socket test_perl5.conf
else
	echo "Skipped test_perl5.conf as Perl5 support is missing"
fi
