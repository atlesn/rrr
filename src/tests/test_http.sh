#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

rm -rf msgdb_directory=/tmp/rrr-test-msgdb-http

do_test_socket test_http.conf

rm -rf msgdb_directory=/tmp/rrr-test-msgdb-http
