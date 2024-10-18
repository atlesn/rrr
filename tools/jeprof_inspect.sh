#!/bin/sh

for file in `ls jeprof*`; do
	jeprof --pdf ./src/.libs/rrr $file > prof.pdf && mupdf prof.pdf
done

rm -f prof.pdf
