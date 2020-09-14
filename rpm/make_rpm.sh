#!/bin/sh

TMPDIR=~
VERSION=`cat version`
TGZ=rrr-$VERSION.tar.gz
SPEC=rrr.spec
SIGN=

if test "x$1" = "xsign"; then
	SIGN="--sign"
fi

BUILD="rpmbuild -ba $SIGN rpmbuild/SPECS/$SPEC"

mkdir -p $TMPDIR || exit 1

rm -rf $TMPDIR/rpmbuild || exit 1
rm -f $TMPDIR/$TGZ || exit 1
rm -f $TMPDIR/$SPEC || exit 1

cp $SPEC $TMPDIR || exit 1

cd ../ || exit 1
TRANSFORM=s,^,rrr-$VERSION/,
tar --transform $TRANSFORM -chzf $TMPDIR/$TGZ *

cd $TMPDIR && rpmdev-setuptree && mv $SPEC rpmbuild/SPECS/ && mv $TGZ rpmbuild/SOURCES/ || exit 1

echo \$ $BUILD
$BUILD || exit 1

echo "RPM build tree complete in $TMPDIR"
