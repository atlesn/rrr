#!/bin/sh

TMPDIR=~
VERSION=`cat version`
TGZ=rrr-$VERSION.tar.gz
SPEC=rrr.spec

mkdir -p $TMPDIR || exit 1

rm -rf $TMPDIR/rpmbuild || exit 1
rm -f $TMPDIR/$TGZ || exit 1
rm -f $TMPDIR/$SPEC || exit 1

cp $SPEC $TMPDIR || exit 1

cd ../ || exit 1
TRANSFORM=s,^,rrr-$VERSION/,
tar --transform $TRANSFORM -chzf $TMPDIR/$TGZ *

cd $TMPDIR && rpmdev-setuptree && mv $SPEC rpmbuild/SPECS/ && mv $TGZ rpmbuild/SOURCES/ || exit 1

rpmbuild -ba rpmbuild/SPECS/$SPEC || exit 1

echo "RPM build tree complete in $TMPDIR"
