# Building Urados

Urados is a native C project. The compiler needs the development headers and
`pkg-config` metadata for libxml2, libzip, libcurl, OpenSSL, libselinux,
libsemanage, and libacl. Runtime libraries alone are not enough.

## Debian 13/Trixie, including ChromeOS Crostini

```sh
sudo apt update
sudo apt install \
  build-essential pkg-config \
  libxml2-dev libzip-dev libcurl4-openssl-dev libssl-dev \
  libselinux1-dev libsemanage-dev libacl1-dev
```

Then build with:

```sh
make -j2
```

The build checks all `pkg-config` dependencies before compiling. If a package
is missing, it prints the missing dependency and points back to this file
instead of starting parallel compiler jobs with incomplete flags.

## Ubuntu

On older Ubuntu releases, the SELinux management development package is named
`libsemanage1-dev`:

```sh
sudo apt update
sudo apt install \
  build-essential pkg-config \
  libxml2-dev libzip-dev libcurl4-openssl-dev libssl-dev \
  libselinux1-dev libsemanage1-dev libacl1-dev
```

If `libsemanage1-dev` is not available on a newer Ubuntu release, use
`libsemanage-dev` instead.

## Fedora or RHEL-like systems

```sh
sudo dnf install \
  gcc make pkgconf-pkg-config \
  libxml2-devel libzip-devel libcurl-devel openssl-devel \
  libselinux-devel libsemanage-devel libacl-devel
```

## Tests

The certificate tests need the normal build dependencies. The full end-to-end
suite additionally needs passwordless `sudo`, ACL utilities such as `getfacl`,
SELinux policy tools, and a usable local SELinux policy store:

```sh
make test
```

On a device, compile and install the SELinux policy only after preparing the
device-specific base policy described in `selinux/base/users.conf`.
