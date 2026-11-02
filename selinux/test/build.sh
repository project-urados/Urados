#!/bin/sh
# Build Urados command-line tools and the SELinux policy, then install the tools.
# The policy is compiled by default but is loaded only with --install-policy.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=/usr/local
DESTDIR=
BUILD_POLICY=1
INSTALL_POLICY=0

usage() {
    cat <<'EOF'
Usage: ./build-install.sh [options]

Build urpkg and urdev, compile the SELinux policy, and install the tools.

Options:
  --prefix DIR       Installation prefix (default: /usr/local; tools go in DIR/bin)
  --destdir DIR      Stage installation under DIR, e.g. for package creation
  --binaries-only    Build/install urpkg and urdev without compiling SELinux policy
  --install-policy   Load selinux/build/urados.pp with semodule after building
  -h, --help         Show this help

The SELinux policy is compiled by default, but is not loaded unless
--install-policy is supplied. Loading it changes the active policy on this
machine and requires root. The Urados policy also expects device-specific base
policy declarations described in selinux/base/users.conf; do not load it on a
stock host policy unless that policy has been prepared for Urados.

Examples:
  ./build-install.sh
  sudo ./build-install.sh --prefix /usr --install-policy
  ./build-install.sh --destdir "$PWD/package-root"
EOF
}

fail() { echo "build-install: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || fail "--prefix requires a directory"
            PREFIX=$2; shift 2 ;;
        --destdir)
            [ "$#" -ge 2 ] || fail "--destdir requires a directory"
            DESTDIR=$2; shift 2 ;;
        --binaries-only)
            BUILD_POLICY=0; shift ;;
        --install-policy)
            INSTALL_POLICY=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *) fail "unknown option: $1 (try --help)" ;;
    esac
done

[ "$BUILD_POLICY" -eq 1 ] || [ "$INSTALL_POLICY" -eq 0 ] || \
    fail "--install-policy cannot be used with --binaries-only"
case "$PREFIX" in
    /*) ;;
    *) fail "--prefix must be an absolute path" ;;
esac
if [ -n "$DESTDIR" ]; then
    case "$DESTDIR" in
        /*) ;;
        *) fail "--destdir must be an absolute path" ;;
    esac
    [ "$INSTALL_POLICY" -eq 0 ] || fail "--install-policy cannot be used with --destdir"
fi
if [ "$INSTALL_POLICY" -eq 1 ]; then
    command -v semodule >/dev/null 2>&1 || fail "--install-policy requested, but semodule was not found"
    [ "$(id -u)" -eq 0 ] || fail "--install-policy must be run as root (for example: sudo ./build-install.sh --install-policy)"
fi

for tool in make cc pkg-config install; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command not found: $tool"
done

if ! pkg-config --exists libxml-2.0 libzip libcurl libcrypto; then
    fail "missing C development dependencies (libxml2, libzip, libcurl, OpenSSL); install their development packages"
fi

printf '%s\n' '== Building Urados command-line tools'
make -C "$ROOT/pkg_mgr" all

if [ "$BUILD_POLICY" -eq 1 ]; then
    printf '%s\n' '== Compiling SELinux policy'
    sh "$ROOT/selinux/test/build.sh"
fi

if [ -n "$DESTDIR" ]; then
    BIN_DIR=${DESTDIR%/}${PREFIX%/}/bin
else
    BIN_DIR=${PREFIX%/}/bin
fi
[ -n "$BIN_DIR" ] || BIN_DIR=/bin
mkdir -p "$BIN_DIR" || fail "cannot create installation directory: $BIN_DIR"
install -m 0755 "$ROOT/pkg_mgr/build/urpkg" "$BIN_DIR/urpkg"
install -m 0755 "$ROOT/pkg_mgr/build/urdev" "$BIN_DIR/urdev"
printf 'Installed urpkg and urdev to %s\n' "$BIN_DIR"

if [ "$INSTALL_POLICY" -eq 1 ]; then
    printf '%s\n' '== Loading SELinux module urados.pp'
    semodule -i "$ROOT/selinux/build/urados.pp"
fi

if [ "$BUILD_POLICY" -eq 1 ]; then
    printf 'SELinux build artifacts are in %s\n' "$ROOT/selinux/build"
fi
