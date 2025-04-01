#!/usr/bin/env bash

set -e

SUFFIX=`echo $0 | tr './' '__'`
TEST="./test -e test_env.conf $1 $2 $3 $4"
TEST_DATA_GENERATOR=./make_test_data
TEST_DATA_ARRAY_DEFINITION=be4#int1,be3#int2,be2s#int3,be1#int4,sep1@1#sep1,le4@1#aaa,le3#bbb,le2s@1#ccc,le1#ddd,sep2#sep2,blob8@2#blob,msg#msg,str#emptystr,vain
TEST_DATA_FILE_DIR=/tmp
TEST_DATA_FILE_PREFIX=rrr-test-data.tmp
TEST_DATA_FILE_NAME=rrr-test-data.tmp.$SUFFIX
TEST_DATA_FILE=$TEST_DATA_FILE_DIR/$TEST_DATA_FILE_NAME

rm -f $TEST_DATA_FILE

RRR_MSGDB_SOCKET=/tmp/rrr-test-msgdb.sock.$SUFFIX

RRR_POST_SOCKET=/tmp/rrr-test.sock.$SUFFIX
RRR_POST=../rrr_post
RRR_POST_ARGS="$RRR_POST_SOCKET -d 8 -f - -c 1 -a $TEST_DATA_ARRAY_DEFINITION"

SEND_FIFO=./send_fifo
SEND_FIFO_FILENAME=/tmp/rrr-test-fifo.sock.$SUFFIX

# NOTE : Only one IP test at a time is allowed
SEND_IP=./send_ip
SEND_IP_PORT=2222

# NOTE : Only one websocket test at a time is allowed
SEND_WEBSOCKET="../rrr_http_client"
SEND_WEBSOCKET_ARGS="-r /tmp -a $TEST_DATA_ARRAY_DEFINITION -s localhost -p 8880 -e /test/x -w"

fail() {
	echo "Test $1 failed" 1>&2
	exit 1
}

ensure_test_data() {
	if test -f $TEST_DATA_FILE; then
		return
	fi
	$TEST_DATA_GENERATOR $TEST_DATA_FILE
	if test $? -ne 0; then
		fail "data generation"
	fi
}

get_test_data_file_name() {
	echo $TEST_DATA_FILE_NAME
}

ensure_config() {
	CONF=$1
	NAME=$2
	VALUE=$3

	CONF_TMP=$CONF.tmp
	CONF_LINE=$NAME=$VALUE

	if ! grep $CONF_LINE $CONF > /dev/null; then
		sed "s|$NAME=.*|$CONF_LINE|" < $CONF > $CONF_TMP
		mv -f $CONF_TMP $CONF
	fi
}

print_test_header () {
	echo "============================================="
	echo "== Test $1 $2"
	echo "============================================="
}

do_test_simple () {
	conf=$1
	print_test_header SIMPLE $conf
	echo \$ $TEST $conf
	$TEST $conf
	if test $? -ne 0; then
		fail $conf
	fi
}

do_websocket_send() {
	ensure_test_data
	sleep 1
	echo \$ $SEND_WEBSOCKET $SEND_WEBSOCKET_ARGS \< $TEST_DATA_FILE
	$SEND_WEBSOCKET $SEND_WEBSOCKET_ARGS < $TEST_DATA_FILE
}

do_rrr_post() {
	ensure_test_data
	sleep 1
	echo \$ $RRR_POST $RRR_POST_ARGS \< $TEST_DATA_FILE
	sleep 0.3
	$RRR_POST $RRR_POST_ARGS < $TEST_DATA_FILE
}

do_send_ip() {
	ensure_test_data
	sleep 1
	echo \$ $SEND_IP $SEND_IP_PORT \< $TEST_DATA_FILE
	sleep 0.3
	$SEND_IP $SEND_IP_PORT < $TEST_DATA_FILE
}

do_send_fifo() {
	ensure_test_data
	echo \$ $SEND_FIFO $SEND_FIFO_FILENAME \< $TEST_DATA_FILE
	$SEND_FIFO $SEND_FIFO_FILENAME < $TEST_DATA_FILE
}

do_test_websocket() {
	conf=$1
	print_test_header WEBSOCKET $conf
 	do_websocket_send &
	echo \$ $TEST $conf
	$TEST $conf
	if test $? -ne 0; then
		fail $conf
	fi
}

do_test_socket() {
	conf=$1
	ensure_config $conf socket_path $RRR_POST_SOCKET
	print_test_header SOCKET $conf
 	do_rrr_post &
	echo \$ $TEST $conf
	$TEST $conf
	if test $? -ne 0; then
		fail $conf
	fi
}

do_test_ip() {
	conf=$1
	print_test_header IP $conf
 	do_send_ip &
	echo \$ $TEST $conf
	$TEST $conf
	if test $? -ne 0; then
		fail $conf 
	fi
}

do_test_fifo() {
	conf=$1
	print_test_header FIFO $conf
 	do_send_fifo &
	echo \$ $TEST $conf
	$TEST $conf
	if test $? -ne 0; then
		fail $conf 
	fi
}
