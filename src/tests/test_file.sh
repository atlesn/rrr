#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

rm -rf /tmp/rrr-test-file-dir
mkdir /tmp/rrr-test-file-dir

ensure_test_data
test_data_file_name_prefix=`get_test_data_file_name | sed 's/....$//'`
ensure_config test_file.conf file_prefix $test_data_file_name_prefix

do_test_simple test_file.conf

# Dir should now be empty, otherwise fail
rmdir /tmp/rrr-test-file-dir
