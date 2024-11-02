#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

rm -rf /tmp/rrr-test-msgdb-cacher

do_test_simple test_cacher_1.conf
do_test_simple test_cacher_2.conf
do_test_simple test_cacher_3.conf
do_test_simple test_cacher_4.conf

rm -rf /tmp/rrr-test-msgdb-cacher

