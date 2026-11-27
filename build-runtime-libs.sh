#!/usr/bin/env bash
# Build the shared third-party libraries used by Urados into a staged target
# filesystem. The logical runtime prefix is always /urados; DESTDIR is only the
# host-side staging directory.
#
# Usage:
#   scripts/build-runtime-libs.sh
#   STAGE_DIR=/path/to/stage JOBS=8 scripts/build-runtime-libs.sh
#   DRY_RUN=1 scripts/build-runtime-libs.sh
#
# The script also stages static archives for libzip, GNU libunistring, MIT
# Kerberos, and libgpg-error. Upstream p11-kit intentionally does not support
# a public static libp11-kit.a; see docs/BUILD.md.
#
# The script builds libraries only where the upstream build system permits it.
# It intentionally does not alter the host /usr, /lib, or /etc.

set -Eeuo pipefail

PREFIX=${PREFIX:-/urados}
STAGE_DIR=${STAGE_DIR:-"$PWD/stage"}
WORK_DIR=${WORK_DIR:-"$PWD/.runtime-libs-work"}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}

# Pin releases for reproducibility. Override any VERSION variable when moving
# to a newer audited release. The URLs below are official upstream archives.
ZLIB_VERSION=${ZLIB_VERSION:-1.3.1}
OPENSSL_VERSION=${OPENSSL_VERSION:-3.5.4}
ATTR_VERSION=${ATTR_VERSION:-2.5.2}
ACL_VERSION=${ACL_VERSION:-2.3.2}
LIBXML2_VERSION=${LIBXML2_VERSION:-2.13.9}
LIBZIP_VERSION=${LIBZIP_VERSION:-1.11.4}
CURL_VERSION=${CURL_VERSION:-8.17.0}
UTIL_LINUX_VERSION=${UTIL_LINUX_VERSION:-2.41.2}
LIBUNISTRING_VERSION=${LIBUNISTRING_VERSION:-1.5}
KRB5_VERSION=${KRB5_VERSION:-1.22.3}
LIBGPG_ERROR_VERSION=${LIBGPG_ERROR_VERSION:-1.61}

# Override this for cross builds, for example OPENSSL_TARGET=linux-aarch64.
OPENSSL_TARGET=${OPENSSL_TARGET:-}

SRC_DIR="$WORK_DIR/src"
BUILD_DIR="$WORK_DIR/build"
STATE_DIR="$WORK_DIR/state"
TARGET_DIR="$STAGE_DIR$PREFIX"

export LC_ALL=C
export PATH="$TARGET_DIR/bin:$TARGET_DIR/sbin:$PATH"
export PKG_CONFIG_PATH="$TARGET_DIR/lib/pkgconfig:$TARGET_DIR/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
# Make pkg-config resolve /urados to the staged /path/to/stage/urados while
# retaining /urados in installed .pc files and generated runtime metadata.
export PKG_CONFIG_SYSROOT_DIR="$STAGE_DIR"
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
export CPPFLAGS="-I$TARGET_DIR/include${CPPFLAGS:+ $CPPFLAGS}"
export LDFLAGS="-L$TARGET_DIR/lib -Wl,-rpath,$PREFIX/lib${LDFLAGS:+ $LDFLAGS}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

for cmd in cc make cmake pkg-config curl tar xz; do
    need_cmd "$cmd"
done

if [[ ${DRY_RUN:-0} == 1 ]]; then
    cat <<EOF
Dry run: host tools are available.

Target prefix: $PREFIX
Staging root:  $STAGE_DIR
Work root:     $WORK_DIR
Parallel jobs: $JOBS

    Would build shared/runtime libraries: zlib, OpenSSL, libattr, libacl,
    libxml2, libzip, libcurl, and util-linux/libblkid.
    Would also stage static archives for libzip, libunistring, MIT Kerberos,
    and libgpg-error.
    p11-kit public static library: unsupported by upstream.
EOF
    exit 0
fi

mkdir -p "$SRC_DIR" "$BUILD_DIR" "$STATE_DIR" "$TARGET_DIR"

cpu_jobs() {
    printf '%s' "$JOBS"
}

fetch() {
    local name=$1
    local url=$2
    local archive="$SRC_DIR/${url##*/}"

    if [[ ! -s "$archive" ]]; then
        echo "==> download $name" >&2
        if ! curl --fail --location --retry 3 --retry-delay 2 --output "$archive" "$url"; then
            rm -f "$archive"
            echo "error: failed to download $name from $url" >&2
            return 1
        fi
    else
        echo "==> reuse $archive" >&2
    fi
    [[ -s "$archive" ]] || {
        echo "error: downloaded archive is empty: $archive" >&2
        return 1
    }
    printf '%s\n' "$archive"
}

unpack_once() {
    local archive=$1
    local name=$2
    local source="$SRC_DIR/$name"

    if [[ ! -f "$source/.urados-unpacked" ]]; then
        echo "==> unpack $name" >&2
        rm -rf "$source"
        mkdir -p "$source"
        if ! tar -xf "$archive" --strip-components=1 -C "$source"; then
            rm -rf "$source"
            echo "error: failed to unpack $archive" >&2
            return 1
        fi
        : > "$source/.urados-unpacked"
    fi
    printf '%s\n' "$source"
}

mark_done() {
    : > "$STATE_DIR/$1.done"
}

done_for() {
    [[ -f "$STATE_DIR/$1.done" ]]
}

build_zlib() {
    local key="zlib-$ZLIB_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch zlib "https://zlib.net/fossils/zlib-$ZLIB_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build zlib $ZLIB_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX"
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_openssl() {
    local key="openssl-$OPENSSL_VERSION"
    done_for "$key" && return
    local archive source target
    archive=$(fetch openssl "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    target=${OPENSSL_TARGET:-}
    if [[ -z "$target" ]]; then
        case "$(uname -m)" in
            x86_64) target=linux-x86_64 ;;
            aarch64|arm64) target=linux-aarch64 ;;
            armv7l) target=linux-armv4 ;;
            riscv64) target=linux64-riscv64 ;;
            *) echo "error: set OPENSSL_TARGET for $(uname -m)" >&2; exit 1 ;;
        esac
    fi
    echo "==> build OpenSSL $OPENSSL_VERSION ($target)"
    (
        cd "$source"
        ./Configure "$target" \
            --prefix="$PREFIX" \
            --openssldir="$PREFIX/ssl" \
            --libdir=lib \
            shared \
            no-tests
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install_sw
    )
    mark_done "$key"
}

build_attr() {
    local key="attr-$ATTR_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch attr "https://download.savannah.nongnu.org/releases/attr/attr-$ATTR_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libattr $ATTR_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX"
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_acl() {
    local key="acl-$ACL_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch acl "https://download.savannah.nongnu.org/releases/acl/acl-$ACL_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libacl $ACL_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            CPPFLAGS="-I$TARGET_DIR/include $CPPFLAGS" \
            LDFLAGS="-L$TARGET_DIR/lib $LDFLAGS"
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_libxml2() {
    local key="libxml2-$LIBXML2_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch libxml2 "https://download.gnome.org/sources/libxml2/${LIBXML2_VERSION%.*}/libxml2-$LIBXML2_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libxml2 $LIBXML2_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --with-minimum \
            --with-zlib="$TARGET_DIR" \
            --without-docs \
            --without-python \
            --without-icu \
            --without-lzma
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_libzip() {
    local key="libzip-$LIBZIP_VERSION"
    done_for "$key" && return
    local archive source build static_build static_stage
    archive=$(fetch libzip "https://libzip.org/download/libzip-$LIBZIP_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    build="$BUILD_DIR/$key"
    static_build="$BUILD_DIR/$key-static"
    static_stage="$WORK_DIR/static-stage/$key"
    echo "==> build libzip $LIBZIP_VERSION"
    cmake -S "$source" -B "$build" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH="$TARGET_DIR" \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_TOOLS=OFF \
        -DBUILD_REGRESS=OFF \
        -DBUILD_OSSFUZZ=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_DOC=OFF \
        -DENABLE_BZIP2=OFF \
        -DENABLE_LZMA=OFF \
        -DENABLE_ZSTD=OFF \
        -DENABLE_READLINE=OFF \
        -DENABLE_COMMONCRYPTO=OFF \
        -DENABLE_GNUTLS=OFF \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_WINDOWS_CRYPTO=OFF
    cmake --build "$build" --parallel "$(cpu_jobs)"
    DESTDIR="$STAGE_DIR" cmake --install "$build"

    echo "==> build static libzip $LIBZIP_VERSION"
    cmake -S "$source" -B "$static_build" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH="$TARGET_DIR" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TOOLS=OFF \
        -DBUILD_REGRESS=OFF \
        -DBUILD_OSSFUZZ=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_DOC=OFF \
        -DENABLE_BZIP2=OFF \
        -DENABLE_LZMA=OFF \
        -DENABLE_ZSTD=OFF \
        -DENABLE_READLINE=OFF \
        -DENABLE_COMMONCRYPTO=OFF \
        -DENABLE_GNUTLS=OFF \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_WINDOWS_CRYPTO=OFF
    cmake --build "$static_build" --parallel "$(cpu_jobs)"
    rm -rf "$static_stage"
    mkdir -p "$static_stage"
    DESTDIR="$static_stage" cmake --install "$static_build"
    install -m 0644 "$static_stage$PREFIX/lib/libzip.a" "$TARGET_DIR/lib/libzip.a"
    mark_done "$key"
}

build_curl() {
    local key="curl-$CURL_VERSION"
    done_for "$key" && return
    local archive source build
    archive=$(fetch curl "https://curl.se/download/curl-$CURL_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    build="$BUILD_DIR/$key"
    echo "==> build libcurl $CURL_VERSION"
    cmake -S "$source" -B "$build" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH="$TARGET_DIR" \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_LIBS=OFF \
        -DBUILD_CURL_EXE=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTING=OFF \
        -DCURL_USE_OPENSSL=ON \
        -DCURL_USE_LIBPSL=OFF \
        -DCURL_USE_LIBSSH2=OFF \
        -DUSE_LIBIDN2=OFF \
        -DCURL_BROTLI=OFF \
        -DCURL_ZLIB=ON \
        -DCURL_ZSTD=OFF
    cmake --build "$build" --parallel "$(cpu_jobs)"
    DESTDIR="$STAGE_DIR" cmake --install "$build"
    mark_done "$key"
}

build_libunistring_static() {
    local key="libunistring-$LIBUNISTRING_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch libunistring "https://ftp.gnu.org/gnu/libunistring/libunistring-$LIBUNISTRING_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build static libunistring $LIBUNISTRING_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --libdir="$PREFIX/lib" \
            --enable-static \
            --disable-shared
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_krb5_static() {
    local key="krb5-$KRB5_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch krb5 "https://kerberos.org/dist/krb5-$KRB5_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build static MIT Kerberos $KRB5_VERSION"
    (
        cd "$source/src"
        ./configure --prefix="$PREFIX" \
            --libdir="$PREFIX/lib" \
            --disable-shared \
            --enable-static \
            --disable-pkinit \
            --without-libedit \
            --without-keyutils \
            --without-system-verto \
            --without-ldap \
            --without-lmdb \
            --disable-rpath
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_libgpg_error_static() {
    local key="libgpg-error-$LIBGPG_ERROR_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch libgpg-error "https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2")
    source=$(unpack_once "$archive" "$key")
    echo "==> build static libgpg-error $LIBGPG_ERROR_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --libdir="$PREFIX/lib" \
            --enable-static \
            --disable-shared
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_libblkid() {
    local key="util-linux-$UTIL_LINUX_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch util-linux "https://www.kernel.org/pub/linux/utils/util-linux/v${UTIL_LINUX_VERSION%.*}/util-linux-$UTIL_LINUX_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libblkid from util-linux $UTIL_LINUX_VERSION"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --libdir="$PREFIX/lib" \
            --disable-all-programs \
            --enable-libblkid \
            --disable-nls \
            --without-systemd
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_zlib
build_openssl
build_attr
build_acl
build_libxml2
build_libzip
build_curl
build_libunistring_static
build_krb5_static
build_libgpg_error_static
build_libblkid

cat <<EOF

Staging complete.

Target prefix: $PREFIX
Staging root:  $STAGE_DIR
Target tree:   $TARGET_DIR

Use these paths when configuring Urados against the staged libraries:
  PKG_CONFIG_PATH=$TARGET_DIR/lib/pkgconfig:$TARGET_DIR/share/pkgconfig
  CPPFLAGS=-I$TARGET_DIR/include
  LDFLAGS=-L$TARGET_DIR/lib -Wl,-rpath,$PREFIX/lib

The target image should receive the contents of:
  $TARGET_DIR  ->  $PREFIX

The script does not install anything into the host's /usr, /lib, or /etc.
EOF
