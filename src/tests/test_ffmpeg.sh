#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

do_test_simple test_ffmpeg.conf

OUTFILES="/tmp/out-0000.mp4 /tmp/out-0001.mp4"

for OUTFILE in $OUTFILES; do
	if ! [ -f $OUTFILE ]; then
		echo "Could not find expected output file $OUTFILE"
		exit 1
	else
		rm -f $OUTFILE
	fi
done
