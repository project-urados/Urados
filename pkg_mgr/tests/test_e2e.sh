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
sudo -n true

echo "== prepare"
sudo -n rm -rf "$T"
mkdir -p "$T"
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
USERS_GID=$(awk -F: '$1=="users"{print $3}' "$ROOT/etc/group")
sudo -n chown "0:$USERS_GID" "$ROOT/data"
sudo -n chmod 0755 "$ROOT/data"
sudo -n cp "$T/root.crt" "$ROOT/etc/urados/keys/test-root.crt"


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

# App names are user names and ext4 folder/file names. Anything outside
# [a-z_][a-z0-9_-]* (up to 32 bytes) must be refused before any account,
# trusted copy or app directory is created.
for bad in "Notes" "no/tes" "no.tes" "../notes" "no tes" ".notes" "9notes"; do
    rm -rf "$T/badname"
    expect_fail "urdev init refuses app name '$bad'" "$URDEV" init "$T/badname" "$bad" 1.0.0
done
expect_fail "urdev init refuses a name longer than 32 bytes" \
    "$URDEV" init "$T/badname" "$(printf 'a%.0s' $(seq 1 33))" 1.0.0
rm -rf "$T/badname"
expect_ok "install a signed package" sudo -n "$URPKG" --root "$ROOT" install "$T/notes-1.0.0.zip"
expect_fail "reinstalling the same package is refused" sudo -n "$URPKG" --root "$ROOT" install "$T/notes-1.0.0.zip"
expect_eq "app user exists" "1" "$(sudo -n grep -c '^notes:' "$ROOT/etc/passwd")"
expect_eq "app user's primary group matches the staged users group" "$USERS_GID" "$(awk -F: '$1=="notes"{print $4}' "$ROOT/etc/passwd")"
expect_eq "app uses the global users primary group only" "$USERS_GID" "$(awk -F: '$1=="notes"{print $4}' "$ROOT/etc/passwd")"
NOTES_UID=$(awk -F: '$1=="notes"{print $3}' "$ROOT/etc/passwd")
expect_eq "no per-app Unix group is created" "0" "$(sudo -n grep -c '^notes:' "$ROOT/etc/group" || true)"
expect_eq "existing data root is preserved as root:users 0755" "0:$USERS_GID 755" "$(stat_of "$ROOT/data")"
expect_eq "trusted copy is root:root 0600" "0:0 600" "$(stat_of "$ROOT/data/app_progs/notes.zip")"
expect_eq "app_progs is root:root 0700" "0:0 700" "$(stat_of "$ROOT/data/app_progs")"
expect_eq "per-app lock is root:root 0600" "0:0 600" "$(stat_of "$ROOT/data/app_progs/.locks/app-notes.lock")"
expect_eq "app parent is root:users 0710" "0:$USERS_GID 710" "$(stat_of "$ROOT/data/app/notes")"
expect_eq "ordinary app data home is appuid:root 0700" "$NOTES_UID:0 700" "$(stat_of "$ROOT/data/app/notes/data")"
expect_eq "install does not create a runtime tree before start" "no" "$(sudo -n test -e "$ROOT/run/app/notes" && echo yes || echo no)"
expect_eq "install does not create the init-managed runtime parent" "no" "$(sudo -n test -e "$ROOT/run/app" && echo yes || echo no)"
expect_eq "staging area is empty after install" "0" "$(sudo -n ls -A "$ROOT/data/app_progs/.staging" | wc -l)"

echo "== install (account and confinement)"
expect_eq "app account has no login shell" "/urados/sbin/nologin" "$(awk -F: '$1=="notes"{print $7}' "$ROOT/etc/passwd")"
expect_eq "app account home is its data home" "/data/app/notes/data" "$(awk -F: '$1=="notes"{print $6}' "$ROOT/etc/passwd")"

# start must not create or change permissions on the init-managed /run/app.
expect_fail "start does not create missing /run/app" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "failed start leaves /run absent" "no" "$(sudo -n test -e "$ROOT/run" && echo yes || echo no)"
sudo -n mkdir -p "$ROOT/run/app"
sudo -n chown 0:0 "$ROOT/run" "$ROOT/run/app"
sudo -n chmod 0755 "$ROOT/run"
sudo -n chmod 0777 "$ROOT/run/app"
expect_fail "start refuses an unsafe /run/app mode" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "start does not repair /run/app permissions" "777" "$(sudo -n stat -c '%a' "$ROOT/run/app")"
sudo -n chmod 0711 "$ROOT/run/app"

# A leftover app directory is refused by the up-front "already exists" check,
# before any account or trusted copy is created. The refusal must not remove it.
expect_ok "a leftover /data/app/other directory exists" sudo -n mkdir -p "$ROOT/data/app/other/data"
set +e
sudo -n "$URPKG" --root "$ROOT" install "$T/other-1.0.0.zip" >"$T/leftover.log" 2>&1
RC=$?
set -e
expect_eq "refused install keeps the pre-existing app directory" "yes" "$(sudo -n test -d "$ROOT/data/app/other/data" && echo yes || echo no)"
sudo -n rm -rf "$ROOT/data/app/other"
expect_eq "install is refused when the app directory already exists" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
expect_eq "refused install leaves no account" "0" "$(sudo -n grep -c '^other:' "$ROOT/etc/passwd" || true)"
expect_eq "refused install leaves no trusted copy" "no" "$(sudo -n test -e "$ROOT/data/app_progs/other.zip" && echo yes || echo no)"

echo "== start (app user)"
APP_UID=$(awk -F: '$1=="notes"{print $3}' "$ROOT/etc/passwd")
set +e
sudo -n "$URPKG" --root "$ROOT" start notes hello world >"$T/run.log" 2>&1
RC=$?
set -e
cat "$T/run.log" | sed 's/^/          /'
expect_eq "start returns the entry point's exit status" "0" "$RC"
expect_eq "entry runs as the app user" "1" "$(grep -c "^uid=$APP_UID " "$T/run.log")"
expect_eq "entry gets only the shared users group, not extra memberships" "1" "$(grep -c "^groups=$USERS_GID$" "$T/run.log")"
expect_eq "entry receives its arguments" "2" "$(grep -c '^arg=' "$T/run.log")"
expect_eq "runtime directory has appuid:root 0570 permissions" "1" "$(grep -c '^runtime_dir=appuid:root 570$' "$T/run.log")"
expect_eq "runtime entry has appuid:root 0570 permissions" "1" "$(grep -c '^runtime_file=appuid:root 570$' "$T/run.log")"
expect_eq "entry cannot write its verified package file" "1" "$(grep -c '^runtime_file_write=denied' "$T/run.log")"
expect_eq "entry cannot create files in its runtime directory" "1" "$(grep -c '^runtime_create=denied' "$T/run.log")"
expect_eq "entry cannot replace its /run/app entry" "1" "$(grep -c '^rename_runtime=denied' "$T/run.log")"
expect_eq "entry can list its own runtime payload" "1" "$(grep -c '^runtime_list=ok' "$T/run.log")"
expect_eq "entry can read its own package code" "1" "$(grep -c '^read_extra=ok' "$T/run.log")"
expect_eq "entry cannot regain root" "1" "$(grep -c '^setuid0=denied' "$T/run.log")"
expect_eq "entry runs with no_new_privs set" "1" "$(grep -c '^no_new_privs=1$' "$T/run.log")"
expect_eq "entry can write its own data" "1" "$(grep -c '^data_write=ok' "$T/run.log")"
expect_eq "probe reports PASS" "1" "$(grep -c '^probe=PASS' "$T/run.log")"
expect_eq "data file is owned by the app user" "$NOTES_UID" "$(sudo -n stat -c '%u' "$ROOT/data/app/notes/data/probe-data.txt")"
expect_eq "app-created data file has no group permissions" "600" "$(sudo -n stat -c '%a' "$ROOT/data/app/notes/data/probe-data.txt")"
expect_eq "runtime package entry is appuid:root 0570" "$NOTES_UID:0 570" "$(stat_of "$ROOT/run/app/notes/notes")"
expect_eq "runtime parent is root:root 0711" "0:0 711" "$(stat_of "$ROOT/run/app")"

sudo -n cp /bin/false "$ROOT/run/app/notes/notes"
expect_ok "start refreshes package code from the trusted ZIP" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "refreshed package entry executes successfully" "0" \
    "$(sudo -n "$URPKG" --root "$ROOT" start notes >"$T/refreshed.log" 2>&1; echo $?)"
expect_eq "verified runtime entry remains available after start" "yes" \
    "$(sudo -n test -x "$ROOT/run/app/notes/notes" && echo yes || echo no)"
sudo -n rm -rf "$ROOT/run/app/notes"
expect_ok "start recreates a missing package-code tree from the trusted ZIP" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "recreated package entry runs successfully" "1" "$(grep -c '^probe=PASS' "$T/last.log")"

echo "== start (refusals)"
sudo -n cp "$T/tampered.zip" "$ROOT/data/app_progs/notes.zip"
expect_fail "a tampered trusted copy is not run" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "failed verification leaves the prior complete package tree intact" "yes" \
    "$(sudo -n test -f "$ROOT/run/app/notes/extra.txt" && echo yes || echo no)"
sudo -n cp "$T/notes-1.0.0.zip" "$ROOT/data/app_progs/notes.zip"
expect_fail "starting an app that was never installed fails" sudo -n "$URPKG" --root "$ROOT" start nosuchapp
expect_ok "start works again after the trusted copy is restored" sudo -n "$URPKG" --root "$ROOT" start notes

echo "== per-app isolation"
expect_ok "install a second certificate-signed app" sudo -n "$URPKG" --root "$ROOT" install "$T/other-1.0.0.zip"
sudo -n chmod 0644 "$ROOT/data/app/notes/data/probe-data.txt"
set +e
sudo -n "$URPKG" --root "$ROOT" start other --op read \
    /data/app/notes/data/probe-data.txt >"$T/cross-data.log" 2>&1
RC=$?
set -e
expect_eq "other app cannot read notes data even when its file is group-readable" "1" "$RC"
expect_eq "cross-data read is denied by the private app-owned home" "1" "$(grep -c 'denied' "$T/cross-data.log")"
set +e
sudo -n "$URPKG" --root "$ROOT" start other --op read \
    /run/app/notes/extra.txt >"$T/cross-runtime-read.log" 2>&1
RC=$?
set -e
expect_eq "other app cannot read notes runtime payload" "1" "$RC"
expect_eq "cross-runtime read is denied by per-app DAC" "1" "$(grep -c 'denied' "$T/cross-runtime-read.log")"
set +e
sudo -n "$URPKG" --root "$ROOT" start other --op write \
    /run/app/notes/cross-app-marker >"$T/cross-app.log" 2>&1
RC=$?
set -e
expect_eq "other app cannot write into notes runtime" "1" "$RC"
expect_eq "cross-app runtime write was denied by per-app DAC" "1" "$(grep -c 'denied' "$T/cross-app.log")"
expect_eq "cross-app runtime marker was not created" "no" \
    "$(sudo -n test -e "$ROOT/run/app/notes/cross-app-marker" && echo yes || echo no)"

echo "== stop, update and uninstall"

# A probe started with --hold keeps running until it is stopped. pid_alive
# treats zombies as gone. Background starts go through sudo, so $! is the
# sudo process, and wait reaps it once the app has stopped.
pid_alive() { [ -d "/proc/$1" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; }
wait_log() { # wait_log FILE PATTERN: up to 10 seconds for PATTERN to appear
    i=0
    while ! grep -q "$2" "$1" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 100 ] && return 1
        sleep 0.1
    done
}
hold_pid() { sed -n 's/^hold=started pid=//p' "$1" | head -n 1; }
spawned_pid() { sed -n 's/^spawned=//p' "$1" | head -n 1; }
yesno() { if "$@"; then echo yes; else echo no; fi; }
start_hold() { # start_hold NAME LOG ARGS...: start an app in the background
    name=$1; log=$2; shift 2
    sudo -n "$URPKG" --root "$ROOT" start "$name" "$@" >"$log" 2>&1 &
}
mkver() { # mkver SRC DST VERSION: copy a project and set its manifest version
    rm -rf "$2" && cp -r "$1" "$2" && sed -i "s#<version>[^<]*</version>#<version>$3</version>#" "$2/manifest.xml"
}
stat_path() { sudo -n test -e "$1" && echo yes || echo no; }
installed_version() { sudo -n "$URPKG" --root "$ROOT" verify "$ROOT/data/app_progs/$1.zip" | sed -n 1p | cut -d, -f1; }

echo "  -- stop"
expect_eq "stop reports an app that is not running" "notes is not running" \
    "$(sudo -n "$URPKG" --root "$ROOT" stop notes 2>/dev/null)"
expect_fail "stop refuses an app that was never installed" sudo -n "$URPKG" --root "$ROOT" stop nosuchapp
expect_fail "stop refuses an invalid app name" sudo -n "$URPKG" --root "$ROOT" stop "Bad.Name"
expect_fail "stop refuses a timeout above the maximum" sudo -n "$URPKG" --root "$ROOT" stop --timeout 601 notes
expect_fail "stop refuses a non-numeric timeout" sudo -n "$URPKG" --root "$ROOT" stop --timeout soon notes

start_hold notes "$T/hold-term.log" --hold 120; H1=$!
expect_ok "a long-running app is started in the background" wait_log "$T/hold-term.log" "hold=started"
P1=$(hold_pid "$T/hold-term.log")
expect_ok "stop terminates a running app" sudo -n "$URPKG" --root "$ROOT" stop --timeout 5 notes
wait "$H1" 2>/dev/null || true
expect_eq "stopped app process is gone" "no" "$(yesno pid_alive "$P1")"
expect_eq "SIGTERM ended the app before it finished" "0" "$(grep -c 'hold=finished' "$T/hold-term.log" || true)"
expect_eq "stop releases the app lock for the next start" "yes" \
    "$(sudo -n "$URPKG" --root "$ROOT" stop notes >/dev/null 2>&1 && echo yes || echo no)"

start_hold notes "$T/hold-tree.log" --hold 120 --spawn; H2=$!
expect_ok "an app with a detached child is running" wait_log "$T/hold-tree.log" "spawned="
P2=$(hold_pid "$T/hold-tree.log")
C2=$(spawned_pid "$T/hold-tree.log")
expect_ok "stop reaches every process of the app" sudo -n "$URPKG" --root "$ROOT" stop --timeout 5 notes
wait "$H2" 2>/dev/null || true
expect_eq "the app's main process is gone" "no" "$(yesno pid_alive "$P2")"
expect_eq "the detached child in its own session is gone" "no" "$(yesno pid_alive "$C2")"

start_hold notes "$T/hold-kill.log" --hold 120 --ignore-term; H3=$!
expect_ok "an app that ignores SIGTERM is running" wait_log "$T/hold-kill.log" "hold=started"
P3=$(hold_pid "$T/hold-kill.log")
expect_ok "stop escalates to SIGKILL after the grace period" sudo -n "$URPKG" --root "$ROOT" stop --timeout 1 notes
wait "$H3" 2>/dev/null || true
expect_eq "SIGKILL ended the app that ignored SIGTERM" "no" "$(yesno pid_alive "$P3")"

start_hold notes "$T/hold-force.log" --hold 120 --ignore-term; H4=$!
expect_ok "an app that ignores SIGTERM is running again" wait_log "$T/hold-force.log" "hold=started"
P4=$(hold_pid "$T/hold-force.log")
FSTART=$(date +%s)
expect_ok "stop --force kills at once" sudo -n "$URPKG" --root "$ROOT" stop --force --timeout 600 notes
FEND=$(date +%s)
wait "$H4" 2>/dev/null || true
expect_eq "--force does not wait for the grace period" "yes" "$([ $((FEND - FSTART)) -lt 20 ] && echo yes || echo no)"
expect_eq "forced app process is gone" "no" "$(yesno pid_alive "$P4")"

echo "  -- update"
mkver "$T/notes" "$T/v09" 0.9.0
mkver "$T/notes" "$T/v11" 1.1.0
mkver "$T/notes" "$T/v12" 1.2.0
"$URDEV" pack "$T/v09" "$T/notes-0.9.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem" >/dev/null
"$URDEV" pack "$T/v11" "$T/notes-1.1.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem" >/dev/null
"$URDEV" pack "$T/v12" "$T/notes-1.2.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem" >/dev/null
"$URDEV" pack "$T/v11" "$T/notes-rogue.zip" --key "$T/rogue.pem" --cert "$T/rogue-chain.pem" >/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/pub2.key" >/dev/null 2>&1
"$URDEV" csr "$T/pub2.key" "$T/pub2.csr" "Second Publisher" >/dev/null
openssl x509 -req -in "$T/pub2.csr" -CA "$T/root.crt" -CAkey "$T/root.key" \
    -CAcreateserial -out "$T/pub2.crt" -days 365 -sha256 -extfile "$T/codesign.ext" >/dev/null 2>&1
cp "$T/pub2.crt" "$T/pub2-chain.pem"
"$URDEV" pack "$T/v12" "$T/notes-1.2.0-otherkey.zip" --key "$T/pub2.key" --cert "$T/pub2-chain.pem" >/dev/null
rm -rf "$T/ghost" && "$URDEV" init "$T/ghost" ghost 1.0.0 >/dev/null
cp "$T/probe" "$T/ghost/app/ghost"
"$URDEV" pack "$T/ghost" "$T/ghost-1.0.0.zip" --key "$T/company.key" --cert "$T/company-chain.pem" >/dev/null

start_hold notes "$T/hold-up.log" --hold 120; HU=$!
expect_ok "the app is running before the update attempts" wait_log "$T/hold-up.log" "hold=started"
PU=$(hold_pid "$T/hold-up.log")
expect_fail "update refuses a downgrade" sudo -n "$URPKG" --root "$ROOT" update "$T/notes-0.9.0.zip"
expect_fail "update refuses the installed version" sudo -n "$URPKG" --root "$ROOT" update "$T/notes-1.0.0.zip"
expect_fail "update refuses a package signed by another publisher key" \
    sudo -n "$URPKG" --root "$ROOT" update "$T/notes-1.2.0-otherkey.zip"
expect_fail "update refuses an untrusted package" sudo -n "$URPKG" --root "$ROOT" update "$T/notes-rogue.zip"
expect_fail "update refuses a package for an app that is not installed" \
    sudo -n "$URPKG" --root "$ROOT" update "$T/ghost-1.0.0.zip"
expect_fail "update refuses a missing package" sudo -n "$URPKG" --root "$ROOT" update "$T/no-such.zip"
expect_eq "refused updates leave the running app running" "yes" "$(yesno pid_alive "$PU")"
expect_eq "refused updates keep the installed version" "OK notes 1.0.0" "$(installed_version notes)"
expect_eq "refused updates leave no staged package behind" "0" \
    "$(sudo -n ls -A "$ROOT/data/app_progs/.staging" | wc -l)"

expect_ok "update replaces the app with a newer signed version and stops it" \
    sudo -n "$URPKG" --root "$ROOT" update --timeout 2 "$T/notes-1.1.0.zip"
wait "$HU" 2>/dev/null || true
expect_eq "updated app process was stopped" "no" "$(yesno pid_alive "$PU")"
expect_eq "trusted copy is now the new version" "OK notes 1.1.0" "$(installed_version notes)"
expect_eq "update removes the old runtime tree" "no" "$(stat_path "$ROOT/run/app/notes")"
expect_eq "update keeps the app account" "1" "$(sudo -n grep -c '^notes:' "$ROOT/etc/passwd")"
expect_eq "update keeps the app's private data" "yes" \
    "$(stat_path "$ROOT/data/app/notes/data/probe-data.txt")"
expect_eq "update keeps the trusted copy root:root 0600" "0:0 600" "$(stat_of "$ROOT/data/app_progs/notes.zip")"
expect_eq "update leaves no staging files" "0" "$(sudo -n ls -A "$ROOT/data/app_progs/.staging" | wc -l)"
expect_ok "the updated app starts" sudo -n "$URPKG" --root "$ROOT" start notes
expect_eq "the updated payload passes its self-check" "1" "$(grep -c '^probe=PASS' "$T/last.log")"

PORT=18081
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$T" >"$T/http.log" 2>&1 &
HTTP_PID=$!
i=0
until curl -fsS "http://127.0.0.1:$PORT/notes-1.2.0.zip" -o /dev/null 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && break
    sleep 0.1
done
start_hold notes "$T/hold-http.log" --hold 120; HH=$!
expect_ok "the app is running before the HTTP update" wait_log "$T/hold-http.log" "hold=started"
PH=$(hold_pid "$T/hold-http.log")
expect_ok "update fetches a newer package over HTTP and stops the running app" \
    sudo -n "$URPKG" --root "$ROOT" update "http://127.0.0.1:$PORT/notes-1.2.0.zip"
wait "$HH" 2>/dev/null || true
expect_eq "HTTP-updated app process was stopped" "no" "$(yesno pid_alive "$PH")"
expect_eq "trusted copy is now 1.2.0 after the HTTP update" "OK notes 1.2.0" "$(installed_version notes)"
kill "$HTTP_PID" 2>/dev/null || true
wait "$HTTP_PID" 2>/dev/null || true

echo "  -- uninstall"
start_hold other "$T/hold-other.log" --hold 120; HO=$!
expect_ok "the app to uninstall is running" wait_log "$T/hold-other.log" "hold=started"
PO=$(hold_pid "$T/hold-other.log")
expect_ok "uninstall stops a running app and removes it" \
    sudo -n "$URPKG" --root "$ROOT" uninstall --timeout 2 other
wait "$HO" 2>/dev/null || true
expect_eq "uninstalled app process is gone" "no" "$(yesno pid_alive "$PO")"
expect_eq "uninstall removes the app account" "0" "$(sudo -n grep -c '^other:' "$ROOT/etc/passwd" || true)"
expect_eq "uninstall removes the app data home" "no" "$(stat_path "$ROOT/data/app/other")"
expect_eq "uninstall removes the trusted package" "no" "$(stat_path "$ROOT/data/app_progs/other.zip")"
expect_eq "uninstall removes the runtime tree" "no" "$(stat_path "$ROOT/run/app/other")"
expect_eq "uninstall removes the app lock file" "no" "$(stat_path "$ROOT/data/app_progs/.locks/app-other.lock")"
expect_eq "uninstall keeps other apps" "1" "$(sudo -n grep -c '^notes:' "$ROOT/etc/passwd")"
expect_fail "uninstalling an app twice reports it is not installed" \
    sudo -n "$URPKG" --root "$ROOT" uninstall other
expect_ok "a fully uninstalled app can be installed again" sudo -n "$URPKG" --root "$ROOT" install "$T/other-1.0.0.zip"
expect_ok "simulate an earlier partial uninstall that removed only the account" \
    sudo -n userdel -P "$ROOT" other
expect_ok "uninstall completes a partial earlier removal" sudo -n "$URPKG" --root "$ROOT" uninstall other
expect_eq "completed partial removal leaves no trusted package" "no" \
    "$(stat_path "$ROOT/data/app_progs/other.zip")"

start_hold notes "$T/hold-final.log" --hold 120 --ignore-term; HF=$!
expect_ok "an app that ignores SIGTERM is running for uninstall" wait_log "$T/hold-final.log" "hold=started"
PF=$(hold_pid "$T/hold-final.log")
expect_ok "uninstall kills an app that ignores SIGTERM after the grace period" \
    sudo -n "$URPKG" --root "$ROOT" uninstall --timeout 1 notes
wait "$HF" 2>/dev/null || true
expect_eq "uninstall killed the app that ignored SIGTERM" "no" "$(yesno pid_alive "$PF")"
expect_eq "notes account is removed by uninstall" "0" "$(sudo -n grep -c '^notes:' "$ROOT/etc/passwd" || true)"
expect_eq "notes runtime tree is removed by uninstall" "no" "$(stat_path "$ROOT/run/app/notes")"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
