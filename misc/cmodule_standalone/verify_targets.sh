#!/bin/sh

OUTFILE=Makefile.am
CFILES=`ls *.c | sed 's/\.[^.]*$//'`

ERR=0

for file in $CFILES; do
	echo -n "Verifying cmodule target for '$file'..."
	FIND="${file}_la_LDFLAGS"
	grep $FIND $OUTFILE > /dev/null
	if [ $? = "0" ]; then
		echo "OK"
	else
		echo "NOT FOUND"
		echo "$0: error: No target found for cmodule '$file'" > /dev/stderr
		ERR=1
	fi
done

if [ "x$ERR" != "x0" ]; then
	echo "$0: error: cmodule target verifications failed. Please update Makefile.am by running generate_am.sh from directory /src/cmodules/" > /dev/stderr
fi

exit $ERR
