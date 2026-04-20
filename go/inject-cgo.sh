#!/bin/sh
# inject-cgo.sh <file.go> <module>
# Insert `#cgo CXXFLAGS` and `#cgo LDFLAGS` directives at the top of the
# SWIG-generated cgo preamble so that `go build` knows which radare2
# libraries to link against.

FILE=$1
MOD=$2

if [ -z "$FILE" ] || [ -z "$MOD" ]; then
  echo "Usage: $0 <file.go> <module>" >&2
  exit 1
fi

CFLAGS=$(pkg-config --cflags "$MOD")
LDFLAGS=$(pkg-config --libs "$MOD")

if grep -q '#cgo LDFLAGS' "$FILE"; then
  exit 0
fi

awk -v cflags="$CFLAGS" -v ldflags="$LDFLAGS" '
  BEGIN { inserted = 0 }
  /^\/\*$/ && !inserted {
    print
    print "#cgo CXXFLAGS: " cflags " -fpermissive -Wno-unused-function -Wno-format-security"
    print "#cgo LDFLAGS: " ldflags
    inserted = 1
    next
  }
  { print }
' "$FILE" > "$FILE.tmp" && mv -f "$FILE.tmp" "$FILE"
