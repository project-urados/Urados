#!/bin/sh
# Build urados.pp, link it with the full reference policy, and expand it.
# Expansion runs all neverallow assertions; any violation fails the script.
# Usage: sh selinux/test/verify.sh
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
command -v bunzip2 >/dev/null 2>&1 || { echo "verify: bunzip2 is required" >&2; exit 2; }
command -v semodule_link >/dev/null 2>&1 || { echo "verify: semodule_link is required" >&2; exit 2; }
set -- /usr/share/selinux/default/*.pp.bz2
[ -e "$1" ] || {
    echo "verify: SELinux reference modules are missing at /usr/share/selinux/default" >&2
    echo "verify: install selinux-policy-default or provide a prepared policy set" >&2
    exit 2
}
sh "$HERE/test/build.sh"
B="$HERE/build"
F="$B/full"
rm -rf "$F" && mkdir -p "$F"
for f in "$@"; do
    bunzip2 -c "$f" > "$F/$(basename "$f" .bz2)"
done
cp "$B/urados.pp" "$F/"
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
