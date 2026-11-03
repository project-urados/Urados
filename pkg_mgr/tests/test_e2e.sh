#!/bin/sh
# End-to-end test for urpkg and urdev.
#
# install and start need root. They run through passwordless sudo against a
# staging root at pkg_mgr/build/test/root, so no real account or /data path is
# touched. Everything the suite creates is inside the repository.
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
B="$HERE/build"
T="$B/test"
ROOT="$T/root"
URPKG="$B/urpkg"
URDEV="$B/urdev"
APPRESTORECON="$B/apprestorecon"
PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }

# expect_ok DESC CMD...: the command must succeed.
expect_ok() {
    desc=$1; shift
    if "$@" >"$T/last.log" 2>&1; then ok "$desc"; else bad "$desc"; sed 's/^/          /' "$T/last.log"; fi
}
# expect_fail DESC CMD...: the command must fail.
expect_fail() {
    desc=$1; shift
    if "$@" >"$T/last.log" 2>&1; then bad "$desc (it succeeded)"; sed 's/^/          /' "$T/last.log"; else ok "$desc"; fi
}
# expect_eq DESC WANT GOT
expect_eq() {
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi
}
stat_of()   { sudo -n stat -c '%u:%g %a' "$1"; }
immutable() { sudo -n python3 "$HERE/tests/lockflag.py" get "$1"; }

echo "== build"
make -C "$HERE" all >/dev/null
sudo -n true

echo "== prepare"
# A previous run may have left system_cache immutable; clear the flag first.
if [ -d "$ROOT/data/app" ]; then
    sudo -n find "$ROOT/data/app" -name system_cache -type d -exec python3 "$HERE/tests/lockflag.py" clear {} \;
fi
# A failed run may have left the staged SELinux store locked; unlock it.
if [ -d "$ROOT/var/lib/selinux/default/active" ]; then
    sudo -n python3 "$HERE/tests/lockflag.py" clear "$ROOT/var/lib/selinux/default/active"
fi
sudo -n rm -rf "$T"
mkdir -p "$T"
# Host SELinux store checksums, to prove that the suite never writes to it.
sudo -n md5sum /var/lib/selinux/default/active/seusers /var/lib/selinux/default/active/users_extra | sort >"$T/host-sel.md5"
"$URDEV" keygen "$T/dev.pem" "$T/dev.pub" --no-passphrase >/dev/null
"$URDEV" keygen "$T/rogue.pem" "$T/rogue.pub" --no-passphrase >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/root.key" -out "$T/root.crt" \
    -days 3650 -subj "/CN=Urados Test Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/company.key" >/dev/null 2>&1
expect_ok "urdev creates a publisher CSR" "$URDEV" csr "$T/company.key" "$T/company.csr" "Test Company Publisher"
expect_ok "publisher CSR signature is valid" openssl req -in "$T/company.csr" -verify -noout
cat > "$T/codesign.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$T/company.csr" -CA "$T/root.crt" -CAkey "$T/root.key" \
    -CAcreateserial -out "$T/company.crt" -days 365 -sha256 \
    -extfile "$T/codesign.ext" >/dev/null 2>&1
cp "$T/company.crt" "$T/company-chain.pem"
gcc -static -O2 -Wall -o "$T/probe" "$HERE/tests/probe.c"

sudo -n mkdir -p "$ROOT/etc/urados/keys" "$ROOT/data"
sudo -n cp /etc/login.defs "$ROOT/etc/login.defs"
printf 'root:x:0:0:root:/root:/bin/sh\n' | sudo -n tee "$ROOT/etc/passwd" >/dev/null
printf 'root:x:0:\nusers:x:100:\n' | sudo -n tee "$ROOT/etc/group" >/dev/null
printf 'root:!:19000:0:99999:7:::\n' | sudo -n tee "$ROOT/etc/shadow" >/dev/null
printf 'root:!::\nusers:!::\n' | sudo -n tee "$ROOT/etc/gshadow" >/dev/null
sudo -n chmod 600 "$ROOT/etc/shadow" "$ROOT/etc/gshadow"
sudo -n cp "$T/dev.pub" "$ROOT/etc/urados/keys/dev.pem"
sudo -n cp "$T/root.crt" "$ROOT/etc/urados/keys/test-root.crt"

# SELinux: a private copy of the policy store. libsemanage writes only under
# $ROOT (semanage_set_root), so the host store is never modified.
[ -f /etc/selinux/config ] || { echo "the suite needs an SELinux policy store at /etc/selinux" >&2; exit 1; }
sudo -n cp -a /etc/selinux "$ROOT/etc/selinux"
sudo -n mkdir -p "$ROOT/var/lib"
sudo -n cp -a /var/lib/selinux "$ROOT/var/lib/selinux"
# The stock policy has no label for /data/app. urados.fc supplies one on a
# device; add an equivalent rule to the staged copy only.
printf '/data/app(/.*)?\tsystem_u:object_r:user_home_t:s0\n' |
    sudo -n tee -a "$ROOT/etc/selinux/default/contexts/files/file_contexts" >/dev/null

"$URDEV" init "$T/notes" notes 1.0.0 >/dev/null
cp "$T/probe" "$T/notes/app/notes"
echo "not for the app to read" > "$T/notes/app/extra.txt"
expect_ok "urdev check accepts a new project" "$URDEV" check "$T/notes"
expect_ok "urdev pack signs with a certificate chain and local key" "$URDEV" pack "$T/notes" "$T/notes-1.0.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem"
expect_fail "urdev rejects a certificate that does not match the signing key" "$URDEV" pack "$T/notes" "$T/cert-key-mismatch.zip" --key "$T/dev.pem" --cert "$T/company-chain.pem"
"$URDEV" init "$T/other" other 1.0.0 >/dev/null
cp "$T/probe" "$T/other/app/other"
"$URDEV" pack "$T/other" "$T/other-rogue.zip" --key "$T/rogue.pem" >/dev/null
"$URDEV" pack "$T/other" "$T/other-1.0.0.zip" --key "$T/dev.pem" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/rogue-root.key" -out "$T/rogue-root.crt" \
    -days 3650 -subj "/CN=Untrusted Test Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
"$URDEV" csr "$T/rogue.pem" "$T/rogue.csr" "Untrusted Publisher" >/dev/null
openssl x509 -req -in "$T/rogue.csr" -CA "$T/rogue-root.crt" -CAkey "$T/rogue-root.key" \
    -CAcreateserial -out "$T/rogue-publisher.crt" -days 365 -sha256 \
    -extfile "$T/codesign.ext" >/dev/null 2>&1
cp "$T/rogue-publisher.crt" "$T/rogue-chain.pem"
"$URDEV" pack "$T/other" "$T/other-untrusted-cert.zip" --key "$T/rogue.pem" --cert "$T/rogue-chain.pem" >/dev/null

echo "== verify (no root needed)"
expect_ok "certificate-signed package verifies against trusted CA root" "$URPKG" --root "$ROOT" verify "$T/notes-1.0.0.zip"
expect_ok "legacy public-key package remains supported" "$URPKG" --root "$ROOT" verify "$T/other-1.0.0.zip"
expect_fail "certificate signed by an untrusted CA is rejected" "$URPKG" --root "$ROOT" verify "$T/other-untrusted-cert.zip"
expect_fail "package signed by an untrusted key is rejected" "$URPKG" --root "$ROOT" verify "$T/other-rogue.zip"

rm -rf "$T/tamper" && mkdir "$T/tamper"
(cd "$T/tamper" && unzip -q "$T/notes-1.0.0.zip" && echo "# edited" >>app/notes && zip -q -r "$T/tampered.zip" .)
expect_fail "modified payload is rejected" "$URPKG" --root "$ROOT" verify "$T/tampered.zip"

echo "== manifest validation"
rm -rf "$T/bad" && cp -r "$T/notes" "$T/bad"
sed 's#system_cache/app/notes#../etc/passwd#' "$T/notes/manifest.xml" >"$T/bad/manifest.xml"
expect_fail "entry outside system_cache/app is rejected" "$URDEV" check "$T/bad"
{
    echo '<?xml version="1.0"?>'
    echo '<!DOCTYPE package [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    echo '<package><name>notes</name><version>1.0.0</version><entry>system_cache/app/notes</entry><label>&x;</label></package>'
} >"$T/bad/manifest.xml"
expect_fail "DOCTYPE with an external entity is rejected" "$URDEV" check "$T/bad"

echo "== install (root)"
expect_fail "untrusted package is refused at install" sudo -n "$URPKG" --root "$ROOT" install "$T/other-rogue.zip"
expect_eq "refused install creates no account" "0" "$(sudo -n grep -c '^other:' "$ROOT/etc/passwd" || true)"
expect_eq "refused install leaves no app directory" "no" "$(sudo -n test -e "$ROOT/data/app/other" && echo yes || echo no)"
expect_ok "install a signed package" sudo -n "$URPKG" --root "$ROOT" install "$T/notes-1.0.0.zip"
expect_fail "reinstalling the same package is refused" sudo -n "$URPKG" --root "$ROOT" install "$T/notes-1.0.0.zip"

expect_eq "app user exists" "1" "$(sudo -n grep -c '^notes:' "$ROOT/etc/passwd")"
expect_eq "app user's primary group is users (gid 100)" "100" "$(awk -F: '$1=="notes"{print $4}' "$ROOT/etc/passwd")"
expect_eq "private group lists the app user" "notes" "$(sudo -n awk -F: '$1=="notes"{print $4}' "$ROOT/etc/group")"
NOTES_UID=$(awk -F: '$1=="notes"{print $3}' "$ROOT/etc/passwd")
NOTES_GID=$(sudo -n awk -F: '$1=="notes"{print $3}' "$ROOT/etc/group")
expect_eq "trusted copy is root:root 0600" "0:0 600" "$(stat_of "$ROOT/data/app_progs/notes/package.zip")"
expect_eq "app_progs is root:root 0700" "0:0 700" "$(stat_of "$ROOT/data/app_progs")"
expect_eq "app data directory is notes:users 0700" "$NOTES_UID:100 700" "$(stat_of "$ROOT/data/app/notes")"
expect_eq "system_cache is root:root 0711" "0:0 711" "$(stat_of "$ROOT/data/app/notes/system_cache")"
expect_eq "system_cache is immutable" "yes" "$(immutable "$ROOT/data/app/notes/system_cache")"
expect_eq "staging area is empty after install" "0" "$(sudo -n ls -A "$ROOT/data/app_progs/.staging" | wc -l)"

echo "== install (SELinux)"
SEL_USERS="$ROOT/var/lib/selinux/default/active/users_extra"
SEL_LOGINS="$ROOT/var/lib/selinux/default/active/seusers"
expect_eq "SELinux user notes_u is defined" "1" "$(sudo -n grep -c '^user notes_u ' "$SEL_USERS" || true)"
expect_eq "login notes maps to SELinux user notes_u" "1" "$(sudo -n grep -c '^notes:notes_u:s0$' "$SEL_LOGINS" || true)"

# A store that cannot be written must fail the install and leave nothing behind.
sudo -n python3 "$HERE/tests/lockflag.py" set "$ROOT/var/lib/selinux/default/active"
set +e
sudo -n "$URPKG" --root "$ROOT" install "$T/other-1.0.0.zip" >"$T/locked.log" 2>&1
RC=$?
set -e
sudo -n python3 "$HERE/tests/lockflag.py" clear "$ROOT/var/lib/selinux/default/active"
expect_eq "install fails when the SELinux store is locked" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
expect_eq "the failure comes from the SELinux step" "1" "$(grep -c 'SELinux' "$T/locked.log" || true)"
expect_eq "failed SELinux install leaves no account" "0" "$(sudo -n grep -c '^other:' "$ROOT/etc/passwd" || true)"
expect_eq "failed SELinux install leaves no SELinux user" "0" "$(sudo -n grep -c '^user other_u ' "$SEL_USERS" || true)"
expect_eq "failed SELinux install leaves no login mapping" "0" "$(sudo -n grep -c '^other:' "$SEL_LOGINS" || true)"
expect_eq "failed SELinux install leaves no app directory" "no" "$(sudo -n test -e "$ROOT/data/app/other" && echo yes || echo no)"
expect_eq "failed SELinux install leaves no trusted copy" "no" "$(sudo -n test -e "$ROOT/data/app_progs/other" && echo yes || echo no)"

echo "== start (app user)"
APP_UID=$(awk -F: '$1=="notes"{print $3}' "$ROOT/etc/passwd")
set +e
sudo -n "$URPKG" --root "$ROOT" start notes hello world >"$T/run.log" 2>&1
RC=$?
set -e
cat "$T/run.log" | sed 's/^/          /'
expect_eq "start returns the entry point's exit status" "0" "$RC"
expect_eq "entry runs as the app user" "1" "$(grep -c "^uid=$APP_UID " "$T/run.log")"
expect_eq "entry receives its arguments" "2" "$(grep -c '^arg=' "$T/run.log")"
expect_eq "entry cannot write into system_cache/app" "1" "$(grep -c '^cache_write=denied' "$T/run.log")"
expect_eq "entry cannot rename system_cache" "1" "$(grep -c '^rename_cache=denied' "$T/run.log")"
expect_eq "entry cannot regain root" "1" "$(grep -c '^setuid0=denied' "$T/run.log")"
expect_eq "entry can write its own data" "1" "$(grep -c '^data_write=ok' "$T/run.log")"
expect_eq "probe reports PASS" "1" "$(grep -c '^probe=PASS' "$T/run.log")"
expect_eq "data file is owned by the app user" "$NOTES_UID" "$(sudo -n stat -c '%u' "$ROOT/data/app/notes/probe-data.txt")"
expect_eq "extracted code folder is root:notes 0110" "0:$NOTES_GID 110" "$(stat_of "$ROOT/data/app/notes/system_cache/app")"
expect_eq "entry point is root:notes 0550" "0:$NOTES_GID 550" "$(stat_of "$ROOT/data/app/notes/system_cache/app/notes")"
expect_eq "system_cache is immutable again after start" "yes" "$(immutable "$ROOT/data/app/notes/system_cache")"

echo "== start (refusals)"
sudo -n cp "$T/tampered.zip" "$ROOT/data/app_progs/notes/package.zip"
expect_fail "a tampered trusted copy is not run" sudo -n "$URPKG" --root "$ROOT" start notes
sudo -n cp "$T/notes-1.0.0.zip" "$ROOT/data/app_progs/notes/package.zip"
expect_fail "starting an app that was never installed fails" sudo -n "$URPKG" --root "$ROOT" start nosuchapp
expect_ok "start works again after the trusted copy is restored" sudo -n "$URPKG" --root "$ROOT" start notes

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
