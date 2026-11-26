#!/bin/sh
# Integration tests for uinit. Run from init/ (make test does this).
#
# Tests that change identity, mount file systems, or run as PID 1 need
# passwordless sudo. Mount tests also need loop devices and sfdisk/mkfs.ext4.
# Everything the suite creates is under build/test and is removed on exit.
set -eu
PATH="$PATH:/usr/sbin:/sbin"
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
