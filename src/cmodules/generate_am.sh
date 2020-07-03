#!/bin/sh

INFILE=Makefile.am.tmpl
OUTFILE=Makefile.am
CFILES=`ls *.c | sed 's/\.[^.]*$//'`

if [ ! -f $INFILE ]; then
	echo "Could not find input file $INFILE. Note that this script must be run from /src/cmodules/."
	exit 1
fi

cat $INFILE > $OUTFILE

for file in $CFILES; do
	echo "Adding $file..."
	echo >> $OUTFILE
	echo "${file}_la_CFLAGS = \${cmodule_cflags}" >> $OUTFILE
	echo "${file}_la_LDFLAGS = \${cmodule_ldflags}" >> $OUTFILE
	echo "${file}_la_SOURCES = ${file}.c" >> $OUTFILE
done

echo -n "lib_LTLIBRARIES =" >> $OUTFILE

for file in $CFILES; do
	echo -n " ${file}.la" >> $OUTFILE
done

echo >> $OUTFILE

exit 0
