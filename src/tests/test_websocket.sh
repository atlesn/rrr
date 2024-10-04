#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

do_test_websocket test_websocket.conf
