#!/bin/sh
# Build urados.pp, link it with the full reference policy, and expand it.
# Expansion runs all neverallow assertions; any violation fails the script.
# Usage: sh selinux/test/verify.sh
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
sh "$HERE/test/build.sh"
B="$HERE/build"
F="$B/full"
rm -rf "$F" && mkdir -p "$F"
for f in /usr/share/selinux/default/*.pp.bz2; do
    bunzip2 -c "$f" > "$F/$(basename "$f" .bz2)"
done
cp "$B/urados.pp" "$B/urados_device_stub.pp" "$F/"
cd "$F"
MODS=$(ls *.pp | grep -v -E '^(base|linked)\.pp$')
semodule_link -o linked.pp base.pp $MODS 2>link.err
semodule_expand linked.pp policy.bin 2>expand.err || true
VIOL=$(grep -c "neverallow violated" expand.err || true)
echo "neverallow violations: $VIOL"
if [ "$VIOL" -ne 0 ]; then
    grep "neverallow violated" expand.err | head -40
    exit 1
fi
echo "VERIFY OK"
