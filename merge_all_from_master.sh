#!/bin/sh

git checkout master || exit 1
git pull || exit 1
git push || exit 1

merge() {
	echo "Checkout, pull and merge $1 with $2"
	git checkout $1 || exit 1
	git pull || exit 1
	git merge $2 || exit 1
	git push || exit 1
}

merge_development() {
	merge $1 development
}

merge_master() {
	merge $1 master
}

merge_master bugfix
merge_master testing
merge_master freebsd
merge_master voidlinux
merge_master debian-testing
merge_master alpine
merge_master development
merge_development ubuntu-development
merge_development development-freebsd
merge_development development-voidlinux

git checkout master || exit 1

echo "The following branches need manual merging to adapt debian packaging:"
echo "ubuntu, debian-buster, ubuntu-hirsute"
# merge_master ubuntu
# merge_master debian-buster
# merge_master ubuntu-hirsute
