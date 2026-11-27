#!/bin/bash
# Build the shared third-party libraries used by Urados into a staged target
# filesystem. The logical runtime prefix is always /urados; DESTDIR is only the
# host-side staging directory.
#
# Usage:
#   scripts/build-runtime-libs.sh
#   STAGE_DIR=/path/to/stage JOBS=8 scripts/build-runtime-libs.sh
#   DRY_RUN=1 scripts/build-runtime-libs.sh
#
# The script also stages static archives for libzip, bzip2, xz, zstd, brotli,
# GNU libunistring, libidn2, libpsl, nghttp2, nghttp3, GMP, Nettle, libtasn1,
# GnuTLS, MIT Kerberos, OpenLDAP, and libgpg-error. Upstream p11-kit
# intentionally does not support a public static libp11-kit.a, so only its
# shared library is staged; see docs/BUILD.md.
#
# The script builds libraries only where the upstream build system permits it.
# It intentionally does not alter the host's system directories.

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
BZIP2_VERSION=${BZIP2_VERSION:-1.0.8}
XZ_VERSION=${XZ_VERSION:-5.8.1}
ZSTD_VERSION=${ZSTD_VERSION:-1.5.7}
BROTLI_VERSION=${BROTLI_VERSION:-1.1.0}
LIBIDN2_VERSION=${LIBIDN2_VERSION:-2.3.8}
LIBPSL_VERSION=${LIBPSL_VERSION:-0.21.5}
NGHTTP2_VERSION=${NGHTTP2_VERSION:-1.66.0}
NGHTTP3_VERSION=${NGHTTP3_VERSION:-1.7.0}
GMP_VERSION=${GMP_VERSION:-6.3.0}
NETTLE_VERSION=${NETTLE_VERSION:-3.10.2}
LIBTASN1_VERSION=${LIBTASN1_VERSION:-4.20.0}
P11_KIT_VERSION=${P11_KIT_VERSION:-0.25.5}
GNUTLS_VERSION=${GNUTLS_VERSION:-3.8.10}
OPENLDAP_VERSION=${OPENLDAP_VERSION:-2.6.10}

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
    libxml2, libzip, libcurl, util-linux/libblkid, xz, zstd, brotli, libidn2,
    libpsl, nghttp2, nghttp3, GMP, Nettle, libtasn1, p11-kit, GnuTLS,
    and OpenLDAP.
    Would also stage static archives for libzip, bzip2, xz, zstd, brotli,
    libunistring, libidn2, libpsl, nghttp2, nghttp3, GMP, Nettle, libtasn1,
    GnuTLS, MIT Kerberos, OpenLDAP, and libgpg-error.
    p11-kit public static library: unsupported by upstream (shared only).
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
        # --with-pic: libidn2.so links this archive, so it must be position-independent.
        ./configure --prefix="$PREFIX" \
            --libdir="$PREFIX/lib" \
            --enable-static \
            --disable-shared \
            --with-pic
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

build_bzip2() {
    local key="bzip2-$BZIP2_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch bzip2 "https://sourceware.org/pub/bzip2/bzip2-$BZIP2_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build static bzip2 $BZIP2_VERSION"
    # bzip2's Makefile has neither DESTDIR support nor a pkg-config file, so the
    # static library and public header are copied into the staged tree directly.
    (
        cd "$source"
        make -j"$(cpu_jobs)" libbz2.a
    )
    install -d "$TARGET_DIR/lib" "$TARGET_DIR/include"
    install -m 0644 "$source/libbz2.a" "$TARGET_DIR/lib/libbz2.a"
    install -m 0644 "$source/bzlib.h" "$TARGET_DIR/include/bzlib.h"
    mark_done "$key"
}

build_xz() {
    local key="xz-$XZ_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch xz "https://tukaani.org/xz/xz-$XZ_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build xz $XZ_VERSION (liblzma)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --disable-xz \
            --disable-xzdec \
            --disable-lzmadec \
            --disable-lzmainfo \
            --disable-scripts \
            --disable-doc \
            --disable-nls
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_zstd() {
    local key="zstd-$ZSTD_VERSION"
    done_for "$key" && return
    local archive source build
    archive=$(fetch zstd "https://github.com/facebook/zstd/releases/download/v$ZSTD_VERSION/zstd-$ZSTD_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    build="$BUILD_DIR/$key"
    echo "==> build zstd $ZSTD_VERSION (shared and static)"
    cmake -S "$source/build/cmake" -B "$build" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH="$TARGET_DIR" \
        -DZSTD_BUILD_SHARED=ON \
        -DZSTD_BUILD_STATIC=ON \
        -DZSTD_BUILD_PROGRAMS=OFF \
        -DZSTD_BUILD_TESTS=OFF
    cmake --build "$build" --parallel "$(cpu_jobs)"
    DESTDIR="$STAGE_DIR" cmake --install "$build"
    mark_done "$key"
}

build_brotli() {
    local key="brotli-$BROTLI_VERSION"
    done_for "$key" && return
    local archive source build static_build static_stage a name
    archive=$(fetch brotli "https://github.com/google/brotli/archive/refs/tags/v$BROTLI_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    build="$BUILD_DIR/$key"
    static_build="$BUILD_DIR/$key-static"
    static_stage="$WORK_DIR/static-stage/$key"
    echo "==> build brotli $BROTLI_VERSION (shared)"
    cmake -S "$source" -B "$build" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH="$TARGET_DIR" \
        -DBUILD_SHARED_LIBS=ON \
        -DBROTLI_DISABLE_TESTS=ON
    cmake --build "$build" --parallel "$(cpu_jobs)"
    DESTDIR="$STAGE_DIR" cmake --install "$build"

    echo "==> build static brotli $BROTLI_VERSION"
    cmake -S "$source" -B "$static_build" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH="$TARGET_DIR" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBROTLI_DISABLE_TESTS=ON
    cmake --build "$static_build" --parallel "$(cpu_jobs)"
    rm -rf "$static_stage"
    mkdir -p "$static_stage"
    DESTDIR="$static_stage" cmake --install "$static_build"
    # Brotli's CMake may name static archives libfoo-static.a; the link line
    # expects libfoo.a, so normalize the name while copying.
    for a in "$static_stage$PREFIX"/lib/*.a; do
        name=$(basename "$a")
        install -m 0644 "$a" "$TARGET_DIR/lib/${name/-static.a/.a}"
    done
    mark_done "$key"
}

build_libidn2() {
    local key="libidn2-$LIBIDN2_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch libidn2 "https://ftp.gnu.org/gnu/libidn/libidn2-$LIBIDN2_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libidn2 $LIBIDN2_VERSION (shared and static)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared \
            --disable-doc \
            --disable-nls
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_libpsl() {
    local key="libpsl-$LIBPSL_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch libpsl "https://github.com/rockdaboot/libpsl/releases/download/$LIBPSL_VERSION/libpsl-$LIBPSL_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libpsl $LIBPSL_VERSION (shared and static)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared \
            --enable-builtin \
            --enable-runtime=libidn2
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_nghttp2() {
    local key="nghttp2-$NGHTTP2_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch nghttp2 "https://github.com/nghttp2/nghttp2/releases/download/v$NGHTTP2_VERSION/nghttp2-$NGHTTP2_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build nghttp2 $NGHTTP2_VERSION (library only)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-lib-only \
            --enable-static \
            --enable-shared
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_nghttp3() {
    local key="nghttp3-$NGHTTP3_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch nghttp3 "https://github.com/ngtcp2/nghttp3/releases/download/v$NGHTTP3_VERSION/nghttp3-$NGHTTP3_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build nghttp3 $NGHTTP3_VERSION (library only)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-lib-only \
            --enable-static \
            --enable-shared
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_gmp() {
    local key="gmp-$GMP_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch gmp "https://ftp.gnu.org/gnu/gmp/gmp-$GMP_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build GMP $GMP_VERSION (shared and static)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_nettle() {
    local key="nettle-$NETTLE_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch nettle "https://ftp.gnu.org/gnu/nettle/nettle-$NETTLE_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build Nettle $NETTLE_VERSION (shared and static, with hogweed)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared \
            --disable-documentation
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_libtasn1() {
    local key="libtasn1-$LIBTASN1_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch libtasn1 "https://ftp.gnu.org/gnu/libtasn1/libtasn1-$LIBTASN1_VERSION.tar.gz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build libtasn1 $LIBTASN1_VERSION (shared and static)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared \
            --disable-doc
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_p11_kit() {
    local key="p11-kit-$P11_KIT_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch p11-kit "https://github.com/p11-glue/p11-kit/releases/download/$P11_KIT_VERSION/p11-kit-$P11_KIT_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build p11-kit $P11_KIT_VERSION (shared only; upstream forbids static)"
    (
        cd "$source"
        # libffi is not staged, so use p11-kit's precompiled closures rather
        # than pulling in the host's libffi.
        ./configure --prefix="$PREFIX" \
            --without-libffi \
            --disable-nls
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_gnutls() {
    local key="gnutls-$GNUTLS_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch gnutls "https://www.gnupg.org/ftp/gcrypt/gnutls/v${GNUTLS_VERSION%.*}/gnutls-$GNUTLS_VERSION.tar.xz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build GnuTLS $GNUTLS_VERSION (shared and static)"
    (
        cd "$source"
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared \
            --disable-doc \
            --disable-tests \
            --disable-nls \
            --without-tpm2
        make -j"$(cpu_jobs)"
        make DESTDIR="$STAGE_DIR" install
    )
    mark_done "$key"
}

build_openldap() {
    local key="openldap-$OPENLDAP_VERSION"
    done_for "$key" && return
    local archive source
    archive=$(fetch openldap "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-$OPENLDAP_VERSION.tgz")
    source=$(unpack_once "$archive" "$key")
    echo "==> build OpenLDAP $OPENLDAP_VERSION client libraries (shared and static)"
    (
        cd "$source"
        # Only libldap and liblber are needed; skip the slapd server.
        ./configure --prefix="$PREFIX" \
            --enable-static \
            --enable-shared \
            --disable-slapd \
            --with-tls=openssl \
            --without-cyrus-sasl
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
build_bzip2
build_xz
build_zstd
build_brotli
build_libidn2
build_libpsl
build_nghttp2
build_nghttp3
build_gmp
build_nettle
build_libtasn1
build_p11_kit
build_gnutls
build_openldap

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

The script does not install anything into the host's system directories.
EOF
