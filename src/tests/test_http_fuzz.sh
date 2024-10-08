#!/bin/sh

set -e

RUN="../rrr_http_server $1 $2 $3 $4"
#RUN="valgrind ./../.libs/rrr_http_server $1 $2 $3 $4"

for file in `ls data/*`; do
	echo "==================================================="
	echo "Fuzzing HTTP server using $file..."
	echo
	cat $file
	echo "==================================================="
	$RUN -p 8886 -R $file
done
