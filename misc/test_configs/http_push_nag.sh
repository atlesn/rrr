#!/bin/sh

i=0

step() {
	echo $1
	while sleep `shuf -i 1-5 -n 1`; do echo $1; mosquitto_pub -t push/$1 -m "`date`"; done &
	if [ $i -gt 3 ]; then
		while sleep 0.1; do curl -s "http://127.0.0.1:8000/?handle=$1"; done &
	fi
}

while true; do
	let i=i+1
	step $i &
	if [ $i -gt 80 ]; then
		exit 0
	fi
	sleep 0.1
done
