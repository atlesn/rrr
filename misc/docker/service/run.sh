#!/bin/bash

set -e

export LOG_SOCKET=/tmp/rrr-logd-delivery.sock

# Setup for valgrind memory debug (must install valgrind package from Dockerfile)
# ulimit -n 4096
# valgrind rrr -d 1 -r /var/run/rrr -l conf/

# Start services
echo "Preparing S6 environment..."
cp -rfva services.d /var/run/s6
cd /var/run/s6

echo "Starting S6 service scanner..."
s6-svscan services.d/

