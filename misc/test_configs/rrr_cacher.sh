#!/bin/bash

# Do 100 requests with different topic

for i in {1..100}; do
    echo | ./src/.libs/rrr_post /tmp/rrr-socket.sock -c 1 -a sep1#request -t "topic/$i" -f - &
done
