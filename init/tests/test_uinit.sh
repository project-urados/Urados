#!/bin/sh
# Integration tests for uinit. Run from init/ (make test does this).
#
# Tests that change identity, mount file systems, or run as PID 1 need
# passwordless sudo. Mount tests also need loop devices and sfdisk/mkfs.ext4.
# Everything the suite creates is under build/test and is removed on exit.
set -eu
PATH="$PATH:/sbin:/urados/sbin"
export PATH

HERE=$(cd "$(dirname "$0")/.." && pwd)
B="$HERE/build"
U="$B/uinit"
T="$B/test"
PASS=0
FAIL=0
R=""
LOOP=""
DISK=""

ok()  { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }

cleanup() {
    # Unmount everything under the test directory, deepest first, then detach the loop device.
    findmnt -rn -o TARGET 2>/dev/null | grep -F "$T/" | sort -r |
        while read -r m; do sudo -n umount -l "$m" 2>/dev/null || true; done
    if [ -n "$LOOP" ]; then
        sudo -n losetup -d "$LOOP" 2>/dev/null || true
    fi
    sudo -n rm -rf "$T" 2>/dev/null || true
}
trap cleanup EXIT

# expect_rc DESC WANT CMD...: CMD must exit with WANT. Its output goes to last.log.
expect_rc() {
    desc=$1; want=$2; shift 2
    set +e
    "$@" >"$T/last.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" = "$want" ]; then
        ok "$desc"
    else
        bad "$desc (exit $rc, want $want)"
        sed 's/^/          /' "$T/last.log"
    fi
}

# expect_log DESC PATTERN: last.log must contain PATTERN.
expect_log() {
    if grep -q -- "$2" "$T/last.log"; then
        ok "$1"
    else
        bad "$1 (no '$2' in output)"
        sed 's/^/          /' "$T/last.log"
    fi
}

# expect_no_log DESC PATTERN: last.log must not contain PATTERN.
expect_no_log() {
    if grep -q -- "$2" "$T/last.log"; then
        bad "$1 ('$2' appeared)"
        sed 's/^/          /' "$T/last.log"
    else
        ok "$1"
    fi
}

# expect_eq DESC WANT GOT
expect_eq() {
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi
}

# stage NAME: sets R to a fresh staging root with a valid id file.
stage() {
    R="$T/$1"
    sudo -n rm -rf "$R"
    mkdir -p "$R/urados/etc/urados/init/hw"
    cat > "$R/urados/etc/urados/init/id" <<'EOF'
# test identity
NAME="Urados"
VERSION=9.9.9
CHANNEL=test
EOF
}

# put RELPATH: writes stdin to a unit under the current staging root.
put() {
    mkdir -p "$(dirname "$R/urados/etc/urados/init/hw/$1")"
    cat > "$R/urados/etc/urados/init/hw/$1"
}

mkdir -p "$T"

echo "== id file and --check"
expect_rc "example tree validates with --check" 0 \
    "$U" --root "$HERE/examples/root" --check
expect_log "--check follows run statements" "starting services"

expect_rc "missing id file fails" 1 "$U" --root "$T/no-such-root" --check
expect_log "missing id file is reported" "id: No such file"

stage badid
printf 'NAME=Urados\n' > "$R/urados/etc/urados/init/id"
expect_rc "id without VERSION fails" 1 "$U" --root "$R" --check
expect_log "id error names VERSION" "VERSION is missing"

echo "== parse and run control"
stage syntax
put init.uinit <<'EOF'
log before
frobnicate now
EOF
expect_rc "syntax error fails the boot" 1 "$U" --root "$R"
expect_log "syntax error gives file and line" "init.uinit:2:"
expect_no_log "syntax error runs nothing" "before"

stage recurse
put init.uinit <<'EOF'
run init.uinit
EOF
expect_rc "unit that runs itself is stopped" 1 "$U" --root "$R"
expect_log "nesting limit is reported" "nesting too deep"

stage nested
put init.uinit <<'EOF'
run units/one.uinit
log back in init
EOF
put units/one.uinit <<'EOF'
log in one
run two.uinit
EOF
put units/two.uinit <<'EOF'
log in two
EOF
expect_rc "relative run paths resolve from the unit's folder" 0 "$U" --root "$R"
expect_log "nested unit ran" "in two"
expect_log "parent continued after nested run" "back in init"

stage optional
put init.uinit <<'EOF'
optional exec -- /bin/false
log still running
EOF
expect_rc "optional failure does not stop the unit" 0 "$U" --root "$R"
expect_log "optional failure is logged" "optional statement failed"
expect_log "unit continues after an optional failure" "still running"

stage required
put init.uinit <<'EOF'
exec -- /bin/false
log never
EOF
expect_rc "a failed exec stops the boot" 1 "$U" --root "$R"
expect_no_log "statements after a failure do not run" "never"

stage missingcmd
put init.uinit <<'EOF'
exec -- /no/such/command
EOF
expect_rc "a missing command fails the boot" 1 "$U" --root "$R"
expect_log "missing command is reported" "cannot run /no/such/command"

echo "== command identity"
# The staging root is under a directory that other users cannot traverse, so the
# nobody child cannot write files there. Identity is read from /proc instead.
stage identity
put init.uinit <<'EOF'
spawn user=nobody group=nogroup groups=nogroup -- /bin/sleep 6
exec user=nobody group=nogroup groups=nogroup -- /bin/sleep 5
EOF
rm -f "$T/uinit.pid" "$T/ids.txt"
sudo -n sh -c "echo \$\$ > '$T/uinit.pid'; exec '$U' --root '$R'" >"$T/identity.log" 2>&1 &
BG=$!
i=0
while [ $i -lt 50 ] && [ "$(pgrep -u 65534 -x sleep | wc -l)" -lt 2 ]; do
    sleep 0.1
    i=$((i + 1))
done
UP=$(cat "$T/uinit.pid" 2>/dev/null || echo 0)
for p in $(pgrep -u 65534 -x sleep); do
    st="/proc/$p/status"
    echo "ppid=$(awk '/^PPid:/{print $2}' "$st") uid=$(awk '/^Uid:/{print $2" "$3" "$4" "$5}' "$st") gid=$(awk '/^Gid:/{print $2" "$3" "$4" "$5}' "$st") groups=$(awk '/^Groups:/{for(i=2;i<=NF;i++) printf "%s%s", (i>2?",":""), $i}' "$st")" >>"$T/ids.txt"
done
if wait "$BG"; then
    ok "spawn and exec start without error"
else
    bad "spawn and exec start without error"
    sed 's/^/          /' "$T/identity.log"
fi
expect_eq "spawn and exec both run as nobody" 2 \
    "$(grep -c -x "ppid=$UP uid=65534 65534 65534 65534 gid=65534 65534 65534 65534 groups=65534" "$T/ids.txt" || true)"
expect_eq "commands are children of uinit (their own pids)" 2 \
    "$(grep -c "ppid=$UP " "$T/ids.txt" || true)"

stage nonroot
put init.uinit <<'EOF'
exec user=nobody -- /bin/true
EOF
expect_rc "changing user without root fails" 1 "$U" --root "$R"
expect_log "failure is the permission error, not a silent fallback" "Operation not permitted"

echo "== mounts"
# Virtual file systems need no device, so they work without loop devices.
stage virtual
put init.uinit <<'EOF'
mount NONE /run/state type=tmpfs opts=nosuid,nodev,mode=755
mount NONE /run/proc type=proc opts=nosuid,nodev,noexec
EOF
expect_rc "NONE mounts tmpfs and proc" 0 sudo -n "$U" --root "$R"
expect_eq "tmpfs mount is in place" tmpfs "$(findmnt -n -o FSTYPE "$R/run/state")"
expect_eq "proc mount is in place" proc "$(findmnt -n -o FSTYPE "$R/run/proc")"

stage missing
put init.uinit <<'EOF'
mount LABEL=UINIT-NO-SUCH-LABEL /mnt/none timeout=1
EOF
expect_rc "a missing LABEL fails after its timeout" 1 sudo -n "$U" --root "$R"
expect_log "timeout error names the label" "no device with LABEL=UINIT-NO-SUCH-LABEL after 1 s"

stage optmissing
put init.uinit <<'EOF'
optional mount UUID=00000000-0000-4000-8000-000000000000 /mnt/none timeout=1
log boot continues
EOF
expect_rc "an optional missing UUID does not stop the boot" 0 sudo -n "$U" --root "$R"
expect_log "boot continues after an optional missing device" "boot continues"

echo "== import"
stage imports
put init.uinit <<'EOF'
import units/a.uinit units/b.uinit
log main continues
EOF
put units/a.uinit <<'EOF'
log first
EOF
put units/b.uinit <<'EOF'
log second
EOF
expect_rc "import runs several units" 0 "$U" --root "$R"
expect_eq "imports run in the order given" first "$(grep -o 'first\|second' "$T/last.log" | head -n 1)"
expect_log "importing unit continues after imports" "main continues"

stage importfail
put init.uinit <<'EOF'
import units/bad.uinit
log NEVER
EOF
put units/bad.uinit <<'EOF'
exec -- /bin/false
EOF
expect_rc "a failed import stops the importing unit" 1 "$U" --root "$R"
expect_no_log "statements after a failed import do not run" "NEVER"

stage importopt
put init.uinit <<'EOF'
optional import units/bad.uinit
log continues
EOF
put units/bad.uinit <<'EOF'
exec -- /bin/false
EOF
expect_rc "optional import failure does not stop the unit" 0 "$U" --root "$R"
expect_log "unit continues after an optional import failure" "continues"

echo "== chmod and chown"
stage attrs
mkdir -p "$R/data/sub"
touch "$R/data/f" "$R/data/sub/g"
put init.uinit <<'EOF'
chmod 0700 /data/f
chmod -R 0750 /data/sub
chown nobody:nogroup /data/f
chown -R :nogroup /data/sub
EOF
expect_rc "chmod and chown run as root" 0 sudo -n "$U" --root "$R"
expect_eq "chmod sets the mode" 700 "$(stat -c %a "$R/data/f")"
expect_eq "chown sets the owner and group" "nobody nogroup" "$(stat -c '%U %G' "$R/data/f")"
expect_eq "chmod -R sets the mode below a directory" 750 "$(stat -c %a "$R/data/sub/g")"
expect_eq "chown -R sets the group below a directory" nogroup "$(stat -c %G "$R/data/sub/g")"

stage attrx
mkdir -p "$R/data/tree"
touch "$R/data/plain" "$R/data/script"
chmod 0644 "$R/data/plain" "$R/data/tree"
chmod 0744 "$R/data/script"
put init.uinit <<'EOF'
chmod -R +X /data
EOF
expect_rc "chmod +X runs recursively" 0 sudo -n "$U" --root "$R"
expect_eq "chmod +X adds execute bits to directories" 755 "$(stat -c %a "$R/data/tree")"
expect_eq "chmod +X adds missing execute bits to executable files" 755 "$(stat -c %a "$R/data/script")"
expect_eq "chmod +X leaves non-executable files unchanged" 644 "$(stat -c %a "$R/data/plain")"

stage attrlink
mkdir -p "$R/data"
printf 'x\n' > "$T/attr-outside"
chmod 0644 "$T/attr-outside"
ln -s "$T/attr-outside" "$R/data/link"
put init.uinit <<'EOF'
chmod -R 0600 /data
EOF
expect_rc "chmod -R does not follow symbolic links" 0 sudo -n "$U" --root "$R"
expect_eq "the link's target keeps its mode" 644 "$(stat -c %a "$T/attr-outside")"

stage attrlinkroot
mkdir -p "$R/data"
ln -s "$T/attr-outside" "$R/data/link"
put init.uinit <<'EOF'
chmod 0600 /data/link
EOF
expect_rc "chmod on a symbolic link fails" 1 sudo -n "$U" --root "$R"
expect_log "the failure says it is a symbolic link" "symbolic link"
expect_eq "chmod on a link leaves its target alone" 644 "$(stat -c %a "$T/attr-outside")"

stage attrbad
mkdir -p "$R/data"
touch "$R/data/f"
put init.uinit <<'EOF'
chown no-such-user-uinit /data/f
EOF
expect_rc "chown to an unknown user fails" 1 sudo -n "$U" --root "$R"
expect_log "the error names the user" "no such user 'no-such-user-uinit'"

echo "== exec modes"
stage modeexit0
put init.uinit <<'EOF'
exec mode=exit -- /bin/sh -c "exit 0"
log NEVER
EOF
expect_rc "mode=exit with status 0 ends the boot with 0" 0 "$U" --root "$R"
expect_no_log "mode=exit stops the boot" "NEVER"

stage modeexit42
put init.uinit <<'EOF'
exec mode=exit -- /bin/sh -c "exit 42"
log NEVER
EOF
expect_rc "mode=exit returns the command's status" 42 "$U" --root "$R"
expect_no_log "mode=exit with status 42 stops the boot" "NEVER"

stage modeexitsig
put init.uinit <<'EOF'
exec mode=exit -- /bin/sh -c 'kill -TERM $$'
EOF
expect_rc "mode=exit on a signal returns 128 + signal" 143 "$U" --root "$R"

stage modenzok
put init.uinit <<'EOF'
exec mode=exit-nonzero -- /bin/sh -c "exit 0"
log continues
EOF
expect_rc "mode=exit-nonzero with status 0 continues the boot" 0 "$U" --root "$R"
expect_log "boot continues after exit-nonzero with status 0" "continues"

stage modenz5
put init.uinit <<'EOF'
exec mode=exit-nonzero -- /bin/sh -c "exit 5"
log NEVER
EOF
expect_rc "mode=exit-nonzero with status 5 ends the boot with 5" 5 "$U" --root "$R"
expect_no_log "mode=exit-nonzero stops the boot" "NEVER"

stage modenzopt
put init.uinit <<'EOF'
optional exec mode=exit-nonzero -- /bin/sh -c "exit 3"
log NEVER
EOF
expect_rc "optional does not stop an exit mode" 3 "$U" --root "$R"

stage modewait
put init.uinit <<'EOF'
exec mode=wait -- /bin/sh -c "exit 9"
log NEVER
EOF
expect_rc "mode=wait with status 9 fails the boot" 1 "$U" --root "$R"
expect_no_log "mode=wait failure stops the unit" "NEVER"

echo "== replace"
stage replacepid
put init.uinit <<EOF
exec mode=replace -- /bin/sh -c 'echo \$\$ > "$T/replace.pid"'
log NEVER
EOF
rm -f "$T/replace.pid" "$T/uinit.pid"
expect_rc "mode=replace runs the command in uinit's place" 0 \
    sudo -n sh -c "echo \$\$ > '$T/uinit.pid'; exec '$U' --root '$R'"
expect_eq "replace keeps uinit's PID" "$(cat "$T/uinit.pid")" "$(cat "$T/replace.pid")"
expect_no_log "nothing after a replace runs" "NEVER"

stage replaceexit
put init.uinit <<'EOF'
exec mode=replace -- /bin/sh -c "exit 7"
log NEVER
EOF
expect_rc "the replaced command's status is the process status" 7 sudo -n "$U" --root "$R"

stage replaceid
put init.uinit <<'EOF'
exec mode=replace user=nobody group=nogroup groups=nogroup -- /bin/sleep 4
log NEVER
EOF
rm -f "$T/uinit.pid"
sudo -n sh -c "echo \$\$ > '$T/uinit.pid'; exec '$U' --root '$R'" >"$T/replaceid.log" 2>&1 &
BG=$!
i=0
while [ $i -lt 50 ] && [ -z "$(pgrep -u 65534 -x sleep)" ]; do
    sleep 0.1
    i=$((i + 1))
done
UP=$(cat "$T/uinit.pid" 2>/dev/null || echo 0)
SP=$(pgrep -u 65534 -x sleep | head -n 1)
expect_eq "replace changes identity and keeps the PID" "$UP" "${SP:-none}"
expect_eq "the replaced command runs as nobody" 65534 \
    "$(awk '/^Uid:/{print $2}' "/proc/${SP:-0}/status" 2>/dev/null || echo none)"
if wait "$BG"; then
    ok "replaced command finishes with status 0"
else
    bad "replaced command finishes with status 0"
    sed 's/^/          /' "$T/replaceid.log"
fi

stage replacemissing
put init.uinit <<'EOF'
optional exec mode=replace user=nobody group=nogroup -- /no/such/command
log continues
EOF
expect_rc "a replace that cannot start, before any identity change, is optional" 0 "$U" --root "$R"
expect_log "unit continues after that optional replace" "continues"

stage replacefatal
printf 'not a program\n' > "$T/noexec.sh"
chmod 0755 "$T/noexec.sh"
put init.uinit <<EOF
optional exec mode=replace user=nobody group=nogroup -- $T/noexec.sh
log NEVER
EOF
expect_rc "a replace that fails after an identity change stops the boot, even if optional" 1 \
    sudo -n "$U" --root "$R"
expect_log "the failure says uinit changed its identity" "changed its identity"
expect_no_log "nothing after that replace runs" "NEVER"

# Loop disk with two ext4 partitions: partition 1 has UUID and LABEL, partition 2 another label.
echo "== mounts on a loop disk"
IMG="$T/disk.img"
rm -f "$IMG"
truncate -s 40M "$IMG"
printf 'label: dos\n,8M,L\n,8M,L\n' | sfdisk -q "$IMG"
LOOP=$(sudo -n losetup -f --show -P "$IMG")
DISK=$(basename "$LOOP")
i=0
while [ ! -b "${LOOP}p2" ] && [ $i -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
sudo -n mkfs.ext4 -q -F -L UINITTEST -U 6f1d2a3c-4b5e-4f70-8a9b-0c1d2e3f4a5b "${LOOP}p1"
sudo -n mkfs.ext4 -q -F -L UINITOTHER "${LOOP}p2"

stage disk
put init.uinit <<EOF
mount LABEL=UINITTEST /mnt/by-label opts=ro timeout=5
mount UUID=6F1D2A3C-4B5E-4F70-8A9B-0C1D2E3F4A5B /mnt/by-uuid opts=ro timeout=5
mount PARTNUM=$DISK:2 /mnt/by-partnum type=ext4 timeout=5
EOF
expect_rc "mounts by label, uuid and partition number" 0 sudo -n "$U" --root "$R"
expect_eq "LABEL picks partition 1" "${LOOP}p1" "$(findmnt -n -o SOURCE "$R/mnt/by-label")"
expect_eq "UUID picks partition 1" "${LOOP}p1" "$(findmnt -n -o SOURCE "$R/mnt/by-uuid")"
expect_eq "PARTNUM picks partition 2" "${LOOP}p2" "$(findmnt -n -o SOURCE "$R/mnt/by-partnum")"
case ",$(findmnt -n -o OPTIONS "$R/mnt/by-label")," in
    *,ro,*) ok "opts=ro makes the mount read-only" ;;
    *) bad "opts=ro makes the mount read-only" ;;
esac

stage badpart
put init.uinit <<EOF
mount PARTNUM=$DISK:9 /mnt/none timeout=1
EOF
expect_rc "a missing partition number fails" 1 sudo -n "$U" --root "$R"
expect_log "missing partition is reported" "no partition 9 on disk $DISK"

echo "== PID 1"
# As PID 1, uinit must stay up after a failed boot, because exiting PID 1 panics the kernel.
stage pid1
put init.uinit <<'EOF'
exec -- /bin/false
EOF
sudo -n unshare -fp --mount-proc "$U" --root "$R" >"$T/pid1.log" 2>&1 &
UPID=$!
i=0
while ! grep -q "staying up as PID 1" "$T/pid1.log" 2>/dev/null && [ $i -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
if grep -q "staying up as PID 1" "$T/pid1.log" && kill -0 "$UPID" 2>/dev/null; then
    ok "PID 1 stays up after a failed boot"
else
    bad "PID 1 stays up after a failed boot"
    sed 's/^/          /' "$T/pid1.log"
fi
sudo -n pkill -KILL -f "uinit --root $R" 2>/dev/null || true
wait "$UPID" 2>/dev/null || true

echo
echo "test_uinit: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
