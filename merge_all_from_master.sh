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

merge bugfix
merge development
merge development-freebsd
merge freebsd
merge voidlinux
merge archlinux
merge ubuntu
merge debian-testing
