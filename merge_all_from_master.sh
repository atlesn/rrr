#!/bin/sh

git checkout master || exit 1
git pull || exit 1
git push || exit 1

merge() {
	echo "Checkout, pull and merge $1"
	git checkout $1 || exit 1
	git pull || exit 1
	git merge master || exit 1
	git push || exit 1
}

merge websocket
merge bugfix
merge development
merge development-freebsd
merge development-voidlinux
merge freebsd
merge voidlinux
merge ubuntu
merge debian-testing
merge rrr-mysql-5.7
merge rrr-mysql-8.0
merge junction
merge snmp

