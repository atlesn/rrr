#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

ensure_test_data
test_data_directory=`get_test_data_file_name | sed 's/....$//'`
ensure_config test_directory.conf directory_prefix $test_data_file_name_prefix

do_test_simple test_directory.conf
