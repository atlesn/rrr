#!/bin/sh
clang -o test -g -std=c++17 -lstdc++ -lnode -I/usr/include/node test.cc $1 $2 $3 $4
