#!/bin/sh
# Compile the Urados policy module. Output artifacts are written to
# selinux/build/; this script never loads policy.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SELINUX_DIR=$(CDPATH= cd -- "$HERE/.." && pwd)
OUT="$SELINUX_DIR/build"
DEVEL_MAKEFILE=/usr/share/selinux/devel/Makefile
TMP=$(mktemp -d "${TMPDIR:-/tmp}/urados-policy-build.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM

for tool in make checkmodule semodule_package; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "policy build: required command not found: $tool" >&2
        exit 1
    }
done
[ -f "$DEVEL_MAKEFILE" ] || {
    echo "policy build: SELinux development Makefile not found at $DEVEL_MAKEFILE" >&2
    exit 1
}
mkdir -p "$OUT"
cp "$SELINUX_DIR/urados.te" "$SELINUX_DIR/urados.fc" "$TMP/"
(
    cd "$TMP"
    make -f "$DEVEL_MAKEFILE" urados.pp
)
cp "$TMP/urados.pp" "$OUT/urados.pp"
printf 'Built %s\n' "$OUT/urados.pp"
