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
	;;
*arm*)
	GO_N=5
	GOARCH=arm
	;;
esac

GOC="go tool ${GO_N}g"
GOL="go tool ${GO_N}l"
GOCC="go tool ${GO_N}c"
GOPACK="go tool pack"
GOOS=`uname | tr 'A-Z' 'a-z'`
if [[ -z "$GOROOT" || ! -d "$GOROOT" ]]; then
	echo "Warning, setting \$GOROOT to '/usr/lib/go', but this should probably be set elsewhere";
	if [ -d "/usr/lib/go" ]; then
		GOROOT=/usr/lib/go;
	fi
	if [ -d "/usr/lib64/go" ]; then
		GOROOT=/usr/lib64/go;
	fi
else
	GOROOT="$GOROOT";
fi
export GOC GOL GOARCH GO_FLAGS GOOS GO_N GOROOT
