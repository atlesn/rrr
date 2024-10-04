#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

mkdir /tmp/rrr-test-file-dir
do_test_simple test_file.conf
rmdir /tmp/rrr-test-file-dir || exit 1
