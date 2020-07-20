#!/bin/sh

INFILE=Makefile.am.tmpl
OUTFILE=Makefile.am
CFILES=`ls *.c | sed 's/\.[^.]*$//'`

if [ ! -f $INFILE ]; then
	echo "Could not find input file $INFILE. Note that this script must be run from /src/cmodules/."
	exit 1
fi

cat $INFILE > $OUTFILE

append_file_contents() {
	FILE=$1
	OUTFILE=$2
	if [ -f "$FILE" ]; then
		echo "- Found extra arguments in file $FILE"
		echo -n " " >> $OUTFILE
		cat "$FILE" >> $OUTFILE
	fi
	echo >> $OUTFILE
}

for file in $CFILES; do
	echo "Adding $file..."

	echo >> $OUTFILE
	echo -n "${file}_la_CFLAGS = \${cmodule_cflags}" >> $OUTFILE
	append_file_contents "$file.cflags" $OUTFILE

	echo -n "${file}_la_LDFLAGS = \${cmodule_ldflags}" >> $OUTFILE
	append_file_contents "$file.ldflags" $OUTFILE

	echo -n "${file}_la_SOURCES = ${file}.c" >> $OUTFILE
	append_file_contents "$file.sources" $OUTFILE
done

echo -n "lib_LTLIBRARIES =" >> $OUTFILE

for file in $CFILES; do
	echo -n " ${file}.la" >> $OUTFILE
done

echo >> $OUTFILE

exit 0
