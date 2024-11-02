#!/bin/sh

PREFIX=packet-
SUFFIX=-valid

function assemble() {
	TYPE=$1
	PACKET=$PREFIX$TYPE$SUFFIX
	./.libs/mqtt_assemble $TYPE > $PACKET || exit 1
	./mqtt_parse < $PACKET || exit 1
}

assemble connect
assemble connack
assemble publish
assemble puback
assemble pubrec
assemble pubrel
assemble pubcomp
assemble subscribe
assemble suback
assemble unsubscribe
assemble unsuback
assemble pingreq
assemble pingresp
assemble disconnect
