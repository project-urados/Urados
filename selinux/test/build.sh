#!/bin/sh
# Build urados.pp against the Debian reference policy (selinux-policy-dev).
# Output goes to selinux/build/ inside the repo (gitignored).
# Usage: sh selinux/test/build.sh
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
B="$HERE/build"
mkdir -p "$B"
cp "$HERE/urados.te" "$HERE/urados.fc" "$B/"
cp "$HERE/test/device_stub.te" "$B/urados_device_stub.te"
cd "$B"
make -f /usr/share/selinux/devel/Makefile urados.pp urados_device_stub.pp
echo "BUILD OK"
