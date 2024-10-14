#!/bin/bash

# Must disable auto bail
set +e

# VALGRIND=valgrind
# LOGD=../.libs/rrr_logd
# POST=../.libs/rrr_post
# RRR=../.libs/rrr

VALGRIND=
LOGD=../rrr_logd
POST=../rrr_post
RRR=../rrr

PID=
SOCKET=/tmp/rrr-logd-socket.sock
TMP=/tmp/rrr-logd-output
LOG_MSG="DEADBEEF"
LOG_PREFIX="test"
LOG_LEVEL="4"
LOG_OUT_4="<4> <$LOG_PREFIX> $LOG_MSG"
LOG_OUT_7="<7> <rrr_post> $LOG_MSG"
LOG_IN="$LOG_LEVEL	$LOG_PREFIX	$LOG_MSG	"
LOG_DEF="ustr#log_level_translated,sep1,nsep#log_prefix,sep1,nsep#log_message,sep1"

if [ "x$VALGRIND" != "x" ]; then
	SLEEP=2
else
	SLEEP=0.2
fi

rm -f $SOCKET || exit 1

bail() {
	MSG=$1
	echo $MSG
	exit 1
}

sigkill_and_bail() {
	MSG=$1
	kill -SIGKILL $PID
	bail "$MSG"
}

function wait_and_verify() {
	EXPECTED_RET=$1

	wait $PID
	RET=$?

	if [ $RET -ne $EXPECTED_RET ]; then
		echo "Unexpected return value $RET, expected $EXPECTED_RET"
		exit 1
	fi

	return 0
}

function verify_socket_deleted() {
	if [ -e $SOCKET ]; then
		sigkill_and_bail $PID "Socket $SOCKET still existed"
	fi

	return 0
}

function verify_socket_exists() {
	if ! [ -S $SOCKET ]; then
		sigkill_and_bail $PID "Socket $SOCKET did not exist"
	fi

	return 0
}

function logd_start() {
	ARGS=$1
	$VALGRIND $LOGD -p $ARGS -s $SOCKET -n > $TMP &
	PID=$!
	sleep $SLEEP
}

function logd_stop() {
	EXPECTED_RET=$1
	kill -SIGUSR1 $PID || exit $?
	wait_and_verify $EXPECTED_RET
	PID=
	verify_socket_deleted
}

function logd_output() {
	OUTPUT=`cat $TMP`
	rm -f $TMP
	echo "$OUTPUT"
}

function logd_start_stop() {
	ARGS=$1
	EXPECTED_RET=$2
	logd_start "$ARGS"
	if [ $EXPECTED_RET -eq 0 ]; then
		verify_socket_exists
		logd_stop $EXPECTED_RET
	else
		if kill -SIGKILL $PID 2>/dev/null; then
			bail "Process did not terminate early although expected"
		fi
	fi
}

function log_delivery() {
	IN=$1
	POST_ARGS=$2
	OUT=$3
	LOGD_ARGS=$4

	logd_start $LOGD_ARGS
	verify_socket_exists

	# Test using specified array definition
	if ! echo "$IN" | $VALGRIND $POST $SOCKET $POST_ARGS -c 1 -f -; then
		sigkill_and_bail "Failed to post log messages"
		exit 1
	fi

	sleep $SLEEP

	logd_stop 0

	OUTPUT=`logd_output`

	if [ "x$OUTPUT" != "x$OUT" ]; then
		echo "Unexpected output '$OUTPUT' expected '$OUT'"
		rm -f $TMP
		exit 1
	fi

	rm -f $TMP
}

function log_delivery_from_rrr() {
	RRR_ARGS=$1
	RRR_OUTPUT=$2
	LOGD_ARGS=$3

	logd_start "$LOGD_ARGS"
	verify_socket_exists

	RRR_OUT=`$VALGRIND $RRR $RRR_ARGS -L $SOCKET`
	RET=$?

	if [ $RET -ne 0 ]; then
		sigkill_and_bail "Unexpected return $RET from rrr"
	fi

	if [ "x$RRR_OUT" != "x" ]; then
		sigkill_and_bail "Unexpected output '$RRR_OUT' from rrr, should be delivered to socket only"
	fi

	logd_stop 0

	OUTPUT=`logd_output`
	if ! echo "$OUTPUT" | grep "$RRR_OUTPUT" > /dev/null; then
		bail "Expected string '$RRR_OUTPUT' not found in output from log daemon"
	fi
}

####################################################
# Verify that logd terminates neatly
####################################################

logd_start_stop "" 0

####################################################
# Verify that incorrect fd produces error
####################################################

logd_start_stop "-f 666" 1

####################################################
# Verify array log message delivery on socket
####################################################

log_delivery "$LOG_IN" "-a $LOG_DEF" "$LOG_OUT_4" 

####################################################
# Verify native log message delivery on socket
####################################################

log_delivery "$LOG_MSG" "-L" "$LOG_OUT_7" 

####################################################
# Verify message only print
####################################################

log_delivery "$LOG_MSG" "-L" "$LOG_MSG" "-m"

####################################################
# Verify log message delivery from main process
####################################################

log_delivery_from_rrr -v "<0> <rrr> Read Route Record"

####################################################
# Verify log level translation
####################################################

log_delivery_from_rrr -v "<3> <rrr> Read Route Record" -l

