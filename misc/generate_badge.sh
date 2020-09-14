#!/bin/sh

PASS=Fail
PASS_COLOUR=#cc1111ff
BRANCH=master

if test "x$1" != "x"; then
	BRANCH=$1
fi

if test "x$2" = "xpass"; then
	PASS=Pass
	PASS_COLOUR=#44cc11ff
fi

sed --expression="s/%pass%/$PASS/g; s/%pass_colour%/$PASS_COLOUR/g; s/%branch%/$BRANCH/" - < build.svg.tmpl  > build-$BRANCH.svg
