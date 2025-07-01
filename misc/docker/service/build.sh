#!/bin/sh

set -e

if [ "x$1" = "x" ]; then
	echo "Usage: $0 {WORKDIR}"
	exit 1
fi

cd "$1"

if [ -d rrr ]; then
	echo "Build files exist, trying to clean up..."
	cd rrr
	git reset --hard
	git clean -fxd
else
	echo "Build files do not exist, trying to clone..."
	git clone --depth 1 --branch v1.36-15 http://github.com/atlesn/rrr
	cd rrr
fi

autoreconf -i
./configure --without-nghttp2 \
	--without-http3 \
	--without-mysql \
	--without-lua \
	--without-python3 \
	--without-libressl \
	--without-systemd

make V=1 -j$(nproc)
if ! make V=1 -j$(nproc) check; then
	echo "Checks failed, dumping logs:"
	for f in `find src/tests -name "*.log"`; do
		echo "------------------------------------------------"
		echo "- File $f:"
		echo "------------------------------------------------"
		cat $f
	done
	echo "RRR checks failed! See log above"
	exit 1;
fi

# Delete SSL certificates
rm -rf misc/ssl
