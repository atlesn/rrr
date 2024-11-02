#!/bin/sh

export LD_LIBRARY_PATH=src/lib/.libs

valgrind --tool=memcheck --suppressions=valgrind-python.supp \
	./src/.libs/rrr config=rrr_test.conf debuglevel=7
