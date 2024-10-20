#!/bin/sh

FUZZ_PACKET=fuzz_packet.tmp
FUZZ_ASSEMBLE_LOG=fuzz_assemble.log
FUZZ_PARSE_LOG=fuzz_parse.log

function fuzz() {
	TYPE=$1

	echo "Fuzz $TYPE: "

	./.libs/mqtt_assemble $TYPE -m > $FUZZ_PACKET 2>>$FUZZ_ASSEMBLE_LOG || exit 1
	./mqtt_parse < $FUZZ_PACKET >> $FUZZ_PARSE_LOG 2>&1
	RET=$?

	if [ $RET -eq 0 ] || [ $RET -eq 1 ]; then
		# OK, not crash
		echo "= $RET"
		true
	else
		echo "= Crash with return value $RET"
		exit $RET
	fi
}

echo > $FUZZ_ASSEMBLE_LOG
echo > $FUZZ_PARSE_LOG

while true; do
	fuzz connect
	fuzz connack
	fuzz publish
	fuzz puback
	fuzz pubrec
	fuzz pubrel
	fuzz pubcomp
	fuzz subscribe
	fuzz suback
	fuzz unsubscribe
	fuzz unsuback
	fuzz pingreq
	fuzz pingresp
	fuzz disconnect
done
