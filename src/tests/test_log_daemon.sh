#!/bin/bash

# Must disable auto bail
set +e

#../rrr_logd

####################################################
# Verify that logd terminates neatly
####################################################

valgrind ../.libs/rrr_logd -s /tmp/rrr-logd-socket &
PID=$!
sleep 2
kill -SIGUSR1 $PID || exit $?
wait $PID
RET=$?
if [ $RET -ne 0 ]; then
	echo "Unexpected return value $RET"
	exit 1
fi


