#!/bin/sh

FUZZ_PACKET=fuzz_packet.tmp
FUZZ_ASSEMBLE_LOG=fuzz_assemble.log
FUZZ_PARSE_LOG=fuzz_parse.log

while true; do
	./.libs/mqtt_assemble publish -s > $FUZZ_PACKET 2>>$FUZZ_ASSEMBLE_LOG || exit 1
	./mqtt_parse < $FUZZ_PACKET >> $FUZZ_PARSE_LOG 2>&1
	RET=$?

	if [ $RET -eq 0 ] || [ $RET -eq 1 ]; then
		# OK, not crash
		echo "OK with return value $RET"
		true
	else
		echo "Crash with return value $RET"
		exit $RET
	fi
done
