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

echo "== build"
make -C "$HERE" all >/dev/null
sh "$HERE/../selinux/test/build.sh" >/dev/null
sudo -n true
command -v getfacl >/dev/null 2>&1 || { echo "E2E tests require getfacl (acl package)" >&2; exit 1; }

echo "== prepare"
# A previous test run may have left an old immutable cache in the staging root.
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
printf 'root:x:0:\nusers:x:100:\nextras:x:101:notes\n' | sudo -n tee "$ROOT/etc/group" >/dev/null
printf 'root:!:19000:0:99999:7:::\n' | sudo -n tee "$ROOT/etc/shadow" >/dev/null
printf 'root:!::\nusers:!::\nextras:!::\n' | sudo -n tee "$ROOT/etc/gshadow" >/dev/null
sudo -n chmod 600 "$ROOT/etc/shadow" "$ROOT/etc/gshadow"
sudo -n cp "$T/root.crt" "$ROOT/etc/urados/keys/test-root.crt"

# SELinux: a private copy of the policy store. libsemanage writes only under
# $ROOT (semanage_set_root), so the host store is never modified.
[ -f /etc/selinux/config ] || { echo "the suite needs an SELinux policy store at /etc/selinux" >&2; exit 1; }
sudo -n cp -a /etc/selinux "$ROOT/etc/selinux"
sudo -n mkdir -p "$ROOT/var/lib"
sudo -n cp -a /var/lib/selinux "$ROOT/var/lib/selinux"
# Add Urados labels to the private staged file-context database used by
# apprestorecon; the host policy store is never changed.
sudo -n sh -c 'cat "$1" >>"$2"' sh "$HERE/../selinux/urados.fc" \
    "$ROOT/etc/selinux/default/contexts/files/file_contexts"
sudo -n semodule -n -p "$ROOT" -s default -i \
    "$HERE/../selinux/build/urados.pp" "$HERE/../selinux/build/urados_device_stub.pp" >/dev/null

"$URDEV" init "$T/notes" notes 1.0.0 >/dev/null
expect_eq "new scripts target the trusted BusyBox shell" "#!/urados/bin/user/sh" "$(head -n 1 "$T/notes/app/notes")"
cp "$T/probe" "$T/notes/app/notes"
echo "readable package resource for the app" > "$T/notes/app/extra.txt"
expect_ok "urdev check accepts a new project" "$URDEV" check "$T/notes"
expect_ok "urdev pack signs with a certificate chain and local key" "$URDEV" pack "$T/notes" "$T/notes-1.0.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem"
expect_fail "packing without a whole signer certificate is refused" "$URDEV" pack "$T/notes" "$T/no-cert.zip" --key "$T/company.key"
expect_fail "urdev rejects a certificate that does not match the signing key" "$URDEV" pack "$T/notes" "$T/cert-key-mismatch.zip" --key "$T/dev.pem" --cert "$T/company-chain.pem"
"$URDEV" init "$T/other" other 1.0.0 >/dev/null
cp "$T/probe" "$T/other/app/other"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/rogue-root.key" -out "$T/rogue-root.crt" \
    -days 3650 -subj "/CN=Untrusted Test Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
"$URDEV" csr "$T/rogue.pem" "$T/rogue.csr" "Untrusted Publisher" >/dev/null
openssl x509 -req -in "$T/rogue.csr" -CA "$T/rogue-root.crt" -CAkey "$T/rogue-root.key" \
    -CAcreateserial -out "$T/rogue-publisher.crt" -days 365 -sha256 \
    -extfile "$T/codesign.ext" >/dev/null 2>&1
cp "$T/rogue-publisher.crt" "$T/rogue-chain.pem"
"$URDEV" pack "$T/other" "$T/other-1.0.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem" >/dev/null
"$URDEV" pack "$T/other" "$T/other-untrusted-cert.zip" --key "$T/rogue.pem" --cert "$T/rogue-chain.pem" >/dev/null

echo "== verify (no root needed)"
expect_ok "certificate-signed package verifies against trusted CA root" "$URPKG" --root "$ROOT" verify "$T/notes-1.0.0.zip"
expect_ok "second package verifies through its signer certificate" "$URPKG" --root "$ROOT" verify "$T/other-1.0.0.zip"
expect_fail "certificate signed by an untrusted CA is rejected" "$URPKG" --root "$ROOT" verify "$T/other-untrusted-cert.zip"

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
expect_eq "app uses the global users primary group only" "100" "$(awk -F: '$1=="notes"{print $4}' "$ROOT/etc/passwd")"
NOTES_UID=$(awk -F: '$1=="notes"{print $3}' "$ROOT/etc/passwd")
USERS_GID=$(sudo -n awk -F: '$1=="users"{print $3}' "$ROOT/etc/group")
expect_eq "no per-app Unix group is created" "0" "$(sudo -n grep -c '^notes:' "$ROOT/etc/group" || true)"
expect_eq "trusted copy is root:root 0600" "0:0 600" "$(stat_of "$ROOT/data/app_progs/notes.zip")"
expect_eq "app_progs is root:root 0700" "0:0 700" "$(stat_of "$ROOT/data/app_progs")"
expect_eq "per-app lock is root:root 0600" "0:0 600" "$(stat_of "$ROOT/data/app_progs/.locks/app-notes.lock")"
expect_eq "app parent is root:users 0710" "0:$USERS_GID 710" "$(stat_of "$ROOT/data/app/notes")"
expect_eq "ordinary app data home is root:users 0770" "0:$USERS_GID 770" "$(stat_of "$ROOT/data/app/notes/data")"
expect_eq "data home ACL grants RWX only to its app UID" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/data" | grep -Fxc "user:$NOTES_UID:rwx")"
expect_eq "data home shared-group ACL grants no access" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/data" | grep -Fxc 'group::---')"
expect_eq "data files inherit the owning app UID ACL" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/data" | grep -Fxc "default:user:$NOTES_UID:rwx")"
expect_eq "data files inherit no shared-group access" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/data" | grep -Fxc 'default:group::---')"
expect_eq "system_cache is root:users setgid 2730" "0:$USERS_GID 2730" "$(stat_of "$ROOT/data/app/notes/system_cache")"
expect_eq "system_cache grants only this app UID WX" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/system_cache" | grep -Fxc "user:$NOTES_UID:-wx")"
expect_eq "system_cache group ACL grants no access" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/system_cache" | grep -Fxc 'group::---')"
expect_eq "package code folder is root:users setgid 2770" "0:$USERS_GID 2770" "$(stat_of "$ROOT/data/app/notes/system_cache/app")"
expect_eq "package code ACL grants this app RWX" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/system_cache/app" | grep -Fxc "user:$NOTES_UID:rwx")"
expect_eq "generated-code folder is root:users setgid 2770" "0:$USERS_GID 2770" "$(stat_of "$ROOT/data/app/notes/system_cache/user")"
expect_eq "staging area is empty after install" "0" "$(sudo -n ls -A "$ROOT/data/app_progs/.staging" | wc -l)"

echo "== install (SELinux)"
SEL_USERS="$ROOT/var/lib/selinux/default/active/users_extra"
SEL_LOGINS="$ROOT/var/lib/selinux/default/active/seusers"
expect_eq "SELinux user notes_u is defined" "1" "$(sudo -n grep -c '^user notes_u ' "$SEL_USERS" || true)"
expect_eq "login notes maps to SELinux user notes_u" "1" "$(sudo -n grep -c '^notes:notes_u:s0$' "$SEL_LOGINS" || true)"
expect_ok "apprestorecon labels the separate data and mutable-code trees" \
    sudo -n "$APPRESTORECON" --root "$ROOT" notes

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
expect_eq "failed SELinux install leaves no trusted copy" "no" "$(sudo -n test -e "$ROOT/data/app_progs/other.zip" && echo yes || echo no)"

echo "== start (app user)"
APP_UID=$(awk -F: '$1=="notes"{print $3}' "$ROOT/etc/passwd")
set +e
sudo -n "$URPKG" --root "$ROOT" start notes hello world >"$T/run.log" 2>&1
RC=$?
set -e
cat "$T/run.log" | sed 's/^/          /'
expect_eq "start returns the entry point's exit status" "0" "$RC"
expect_eq "entry runs as the app user" "1" "$(grep -c "^uid=$APP_UID " "$T/run.log")"
expect_eq "app gets only the shared users group, not extra memberships" "1" "$(grep -c '^groups=100$' "$T/run.log")"
expect_eq "entry receives its arguments" "2" "$(grep -c '^arg=' "$T/run.log")"
expect_eq "entry can write its mutable system_cache" "1" "$(grep -c '^cache_write=ok' "$T/run.log")"
expect_eq "entry cannot list the top-level system_cache" "1" "$(grep -c '^cache_list=denied' "$T/run.log")"
expect_eq "entry cannot rename system_cache" "1" "$(grep -c '^rename_cache=denied' "$T/run.log")"
expect_eq "entry can read its own package code" "1" "$(grep -c '^read_extra=ok' "$T/run.log")"
expect_eq "entry can execute generated code in its own cache" "1" "$(grep -c '^cache_generated_exec=ok' "$T/run.log")"
expect_eq "entry cannot regain root" "1" "$(grep -c '^setuid0=denied' "$T/run.log")"
expect_eq "entry can write its own data" "1" "$(grep -c '^data_write=ok' "$T/run.log")"
expect_eq "probe reports PASS" "1" "$(grep -c '^probe=PASS' "$T/run.log")"
expect_eq "data file is owned by the app user" "$NOTES_UID" "$(sudo -n stat -c '%u' "$ROOT/data/app/notes/data/probe-data.txt")"
expect_eq "app-created data file has no shared-group ACL permissions" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/data/probe-data.txt" | grep -Fxc 'group::---')"
expect_fail "app cannot chmod its root-owned data home" sudo -n "$URPKG" --root "$ROOT" start notes --op chmod /data/app/notes/data
expect_eq "the chmod failure is due to protected data-home ownership" "1" "$(grep -c 'chmod /data/app/notes/data: denied' "$T/last.log")"
expect_eq "installed program is root:users 0770" "0:$USERS_GID 770" "$(stat_of "$ROOT/data/app/notes/system_cache/app/notes")"
expect_eq "installed program ACL grants only this app UID" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/system_cache/app/notes" | grep -Fxc "user:$NOTES_UID:rwx")"
expect_eq "app-created executable is owned by its app UID" "$NOTES_UID" "$(sudo -n stat -c '%u' "$ROOT/data/app/notes/system_cache/user/generated-probe")"
expect_eq "app-created executable has no shared-group ACL permissions" "1" "$(sudo -n getfacl -cp "$ROOT/data/app/notes/system_cache/user/generated-probe" | grep -Fxc 'group::---')"
sudo -n touch "$ROOT/data/app/notes/system_cache/root-write-check"
expect_eq "root can create entries in the cache" "0:$USERS_GID 660" "$(stat_of "$ROOT/data/app/notes/system_cache/root-write-check")"
sudo -n rm -f "$ROOT/data/app/notes/system_cache/root-write-check"

sudo -n cp /bin/false "$ROOT/data/app/notes/system_cache/app/notes"
expect_ok "start refreshes package code from the trusted ZIP" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "refreshed package entry executes successfully" "0" \
    "$(sudo -n "$URPKG" --root "$ROOT" start notes >"$T/refreshed.log" 2>&1; echo $?)"
expect_eq "app-created code remains available across starts" "yes" \
    "$(sudo -n test -x "$ROOT/data/app/notes/system_cache/user/generated-probe" && echo yes || echo no)"
sudo -n rm -rf "$ROOT/data/app/notes/system_cache/app"
expect_ok "start recreates a missing package-code tree from the trusted ZIP" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "recreated package entry runs successfully" "1" "$(grep -c '^probe=PASS' "$T/last.log")"

echo "== start (refusals)"
sudo -n cp "$T/tampered.zip" "$ROOT/data/app_progs/notes.zip"
expect_fail "a tampered trusted copy is not run" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "failed verification leaves the prior complete package tree intact" "yes" \
    "$(sudo -n test -f "$ROOT/data/app/notes/system_cache/app/extra.txt" && echo yes || echo no)"
sudo -n cp "$T/notes-1.0.0.zip" "$ROOT/data/app_progs/notes.zip"
expect_fail "starting an app that was never installed fails" sudo -n "$URPKG" --root "$ROOT" start nosuchapp
expect_ok "start works again after the trusted copy is restored" sudo -n "$URPKG" --root "$ROOT" start notes

echo "== per-app cache isolation"
expect_ok "install a second certificate-signed app" sudo -n "$URPKG" --root "$ROOT" install "$T/other-1.0.0.zip"
sudo -n chmod 0644 "$ROOT/data/app/notes/data/probe-data.txt"
set +e
sudo -n "$URPKG" --root "$ROOT" start other --op read \
    /data/app/notes/data/probe-data.txt >"$T/cross-data.log" 2>&1
RC=$?
set -e
expect_eq "other app cannot read notes data even when its file is group-readable" "1" "$RC"
expect_eq "cross-app data read is denied by the protected home ACL" "1" "$(grep -c 'denied' "$T/cross-data.log")"
set +e
sudo -n "$URPKG" --root "$ROOT" start other --op write \
    /data/app/notes/system_cache/user/cross-app-marker >"$T/cross-app.log" 2>&1
RC=$?
set -e
expect_eq "other app cannot write into notes system_cache" "1" "$RC"
expect_eq "cross-app write was denied by per-app DAC" "1" "$(grep -c 'denied' "$T/cross-app.log")"
expect_eq "cross-app marker was not created" "no" \
    "$(sudo -n test -e "$ROOT/data/app/notes/system_cache/user/cross-app-marker" && echo yes || echo no)"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
