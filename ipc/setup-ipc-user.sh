#!/bin/sh
# Create the Urados user IPC rundir: /run/ipc/user
#
# Access model (see selinux/urados.te, rule 6):
#   - Only members of the group 'users' may use the rundir (mode 2770, setgid).
#   - No communication method is imposed: files, FIFOs, UNIX sockets and
#     shared mappings are all allowed, so developers can layer their own
#     encryption on top.
#   - The rundir is a dedicated tmpfs mounted with noexec,nosuid,nodev, so
#     nothing placed in it can be executed.
#
# Usage:
#   setup-ipc-user.sh [--root DIR] [--group NAME] [--size SIZE] [--no-mount]
#
#   --root DIR    Prefix all paths with DIR (staging/testing). Default: /
#   --group NAME  Group allowed to use the rundir. Default: users
#   --size SIZE   tmpfs size limit. Default: 64M
#   --no-mount    Create the directory with the right owner/mode but do not
#                 mount tmpfs (for staging, containers or tests). Without a
#                 mount the noexec guarantee does NOT hold; do not use this
#                 on a device.
#
# Must run as root to mount (unless --no-mount). Idempotent.

set -eu

ROOT=""
GROUP_NAME="users"
SIZE="64M"
DO_MOUNT=1

die() { echo "setup-ipc-user: error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --root)     [ $# -ge 2 ] || die "--root needs a value"; ROOT="$2"; shift 2 ;;
        --group)    [ $# -ge 2 ] || die "--group needs a value"; GROUP_NAME="$2"; shift 2 ;;
        --size)     [ $# -ge 2 ] || die "--size needs a value"; SIZE="$2"; shift 2 ;;
        --no-mount) DO_MOUNT=0; shift ;;
        -h|--help)  sed -n '2,22p' "$0"; exit 0 ;;
        *)          die "unknown argument: $1" ;;
    esac
done

case "$ROOT" in
    "") ;;
    /*) ROOT="${ROOT%/}" ;;
    *)  die "--root must be an absolute path" ;;
esac

case "$GROUP_NAME" in
    ""|*[!A-Za-z0-9_.-]*) die "invalid group name: $GROUP_NAME" ;;
esac
case "$SIZE" in
    *[!0-9KkMmGg]*|"") die "invalid size: $SIZE" ;;
esac

IPC_DIR="$ROOT/run/ipc/user"
IPC_PARENT="$ROOT/run/ipc"

if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
    die "group '$GROUP_NAME' does not exist"
fi
GID=$(getent group "$GROUP_NAME" | cut -d: -f3)

# /run/ipc is traversal-only for everyone (urados_path_dir_t).
mkdir -p "$IPC_PARENT"
chown root:root "$IPC_PARENT" 2>/dev/null || true
chmod 0755 "$IPC_PARENT"

mkdir -p "$IPC_DIR"

if [ "$DO_MOUNT" -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || die "mounting the IPC tmpfs requires root (or use --no-mount)"

    # Only mount once. If already a mountpoint, verify its options instead.
    if command -v findmnt >/dev/null 2>&1 && findmnt -M "$IPC_DIR" >/dev/null 2>&1; then
        OPTS=$(findmnt -M "$IPC_DIR" -no OPTIONS)
    else
        mount -t tmpfs -o "size=$SIZE,mode=2770,uid=0,gid=$GID,noexec,nosuid,nodev" \
            tmpfs "$IPC_DIR"
        OPTS=$(findmnt -M "$IPC_DIR" -no OPTIONS 2>/dev/null || echo "noexec")
    fi

    case ",$OPTS," in
        *,noexec,*) ;;
        *) die "$IPC_DIR is not mounted noexec (options: $OPTS)" ;;
    esac
fi

# Ownership and mode: group-only access, setgid so new entries inherit the group.
chgrp "$GID" "$IPC_DIR" 2>/dev/null || chown ":$GID" "$IPC_DIR"
chmod 2770 "$IPC_DIR"

# Report.
MODE=$(stat -c '%a' "$IPC_DIR")
OWNER=$(stat -c '%U:%G' "$IPC_DIR")
echo "IPC rundir ready: $IPC_DIR (owner $OWNER, mode $MODE)"
if [ "$DO_MOUNT" -eq 0 ]; then
    echo "warning: --no-mount used; noexec is NOT enforced on this directory" >&2
fi
