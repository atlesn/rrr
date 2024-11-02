#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

do_test_socket test_socket.conf
