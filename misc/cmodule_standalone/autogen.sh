#!/bin/sh

./generate_am.sh || true
autoreconf -i --force
./configure
