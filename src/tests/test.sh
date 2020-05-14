#!/bin/sh

TEST="./test $1 $2 $3 $4"
TEST_SOCKET=.rrr_test.sock
TEST_DATA_FILE=.test_data.tmp
TEST_DATA_GENERATOR=./make_test_data

RRR_POST=../rrr_post
RRR_POST_ARGS="$TEST_SOCKET -d 8 -f - -c 1 -a be4#int1,be3#int2,be2s#int3,be1#int4,sep1@1#sep1,le4@1#aaa,le3#bbb,le2s@1#ccc,le1#ddd,sep2#sep2,blob8@2#blob,msg#msg"

SEND_IP=./send_ip
SEND_IP_PORT=2222

fail () {
	echo "Test $1 failed" 1>&2
	exit 1
}

do_rrr_post() {
	echo \$ $RRR_POST $RRR_POST_ARGS \< $TEST_DATA_FILE
	sleep 0.3
	$RRR_POST $RRR_POST_ARGS < $TEST_DATA_FILE
}

do_send_ip() {
	echo \$ $SEND_IP $SEND_IP_PORT \< $TEST_DATA_FILE
	sleep 0.3
	$SEND_IP $SEND_IP_PORT < $TEST_DATA_FILE
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

do_test_socket() {
	conf=$1
	print_test_header SOCKET $conf
	rm $TEST_SOCKET
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

$TEST_DATA_GENERATOR $TEST_DATA_FILE
if test $? -ne 0; then
	fail "data generation"
fi

do_test_simple test_dummy.conf
do_test_simple test_averager.conf

do_test_ip test_ip.conf

do_test_socket test_socket.conf
do_test_socket test_ipclient.conf
do_test_socket test_mysql.conf
do_test_socket test_mqtt.conf
do_test_socket test_perl5.conf
do_test_socket test_python3.conf

echo "Tests complete\n"
