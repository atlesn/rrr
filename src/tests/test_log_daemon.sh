#!/bin/bash

# Must disable auto bail
set +e

VALGRIND=valgrind
SOCKET=/tmp/rrr-logd-socket.sock

#../rrr_logd

function wait_and_verify() {
	EXPECTED_RET=$1

	wait $PID
	RET=$?

	if [ $RET -ne $EXPECTED_RET ]; then
		echo "Unexpected return value $RET, expected $EXPECTED_RET"
		exit 1
	fi

	return $RET
}

####################################################
# Verify that logd terminates neatly
####################################################

rm -f $SOCKET || exit 1

$VALGRIND ../.libs/rrr_logd -s $SOCKET &
PID=$!

sleep 2

if ! [ -S $SOCKET ]; then
	kill -SIGKILL $PID
	echo "Socket $SOCKET did not exist"
	exit 1
fi

kill -SIGUSR1 $PID || exit $?
wait_and_verify 0
RET=$?

if [ -e $SOCKET ]; then
	echo "Socket $SOCKET still existed"
	exit 1
fi

####################################################
# Verify that incorrect fd produces error
####################################################

#$VALGRIND ../.libs/rrr_logd -s $SOCKET &
PID=$!
