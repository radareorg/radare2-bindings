#!/bin/sh
HOST_ARCH=`uname -m`
case "${HOST_ARCH}" in
*86)
	GO_N=8
	GOARCH=386
	;;
*64*)
	GO_N=6
	GOARCH=amd64
	GO_FLAGS=-D_64BIT
	;;
*arm*)
	GO_N=5
	GOARCH=arm
	;;
esac

GOC=${GO_N}g
GOL=${GO_N}l
GOCC=${GO_N}c
GOOS=`uname | tr 'A-Z' 'a-z'`
if ! "$GOROOT"; then
	echo "Warning, setting \$GOROOT to '/usr/lib/go', but this should probably be set elsewhere";
	GOROOT=/usr/lib/go;
else
	GOROOT="$GOROOT";
fi
export GOC GOL GOARCH GO_FLAGS GOOS GO_N GOROOT
