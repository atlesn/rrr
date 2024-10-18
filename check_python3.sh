#!/bin/sh

CC="$1"
PYTHON3_CONFIG="$2"
PYTHON3_CFLAGS=`$2 --cflags`

mkdir -p config_test
cd config_test

cat << EOF > python_test.c

#include <Python.h>

int main (int argc, const char **argv) {
	return 0;
}

EOF

rm -f python_test
$CC -o python_test $PYTHON3_CFLAGS python_test.c
./python_test
PYTHON3_RESULT=$?

rm -f python_test.c 
rm -f python_test 

cd ..

rmdir config_test

exit $PYTHON3_RESULT
