#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_MYSQL" != 'xno'; then
	do_test_socket test_mysql.conf
else
	echo "Skipped test_mysql.conf as MySQL support is missing"
fi
