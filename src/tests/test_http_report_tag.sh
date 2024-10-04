#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

do_test_simple test_http_report_tag.conf
