# Building Urados

Urados is a native C project. The compiler needs the development headers and
`pkg-config` metadata for libxml2, libzip, libcurl, OpenSSL, and libacl.
Runtime libraries alone are not enough.

## Debian 13/Trixie, including ChromeOS Crostini

```sh
sudo apt update
sudo apt install \
  build-essential pkg-config \
  libxml2-dev libzip-dev libcurl4-openssl-dev libssl-dev \
  libacl1-dev
```

Then build with:

```sh
make -j2
```

The build checks all `pkg-config` dependencies before compiling. If a package
is missing, it prints the missing dependency and points back to this file
instead of starting parallel compiler jobs with incomplete flags.

## Ubuntu

```sh
sudo apt update
sudo apt install \
  build-essential pkg-config \
  libxml2-dev libzip-dev libcurl4-openssl-dev libssl-dev libacl1-dev
```

## Fedora or RHEL-like systems

```sh
sudo dnf install \
  gcc make pkgconf-pkg-config \
  libxml2-devel libzip-devel libcurl-devel openssl-devel \
  libacl-devel
```

## Tests

The certificate tests need the normal build dependencies. The full end-to-end
suite additionally needs passwordless `sudo` and ACL utilities such as `getfacl`
(Debian/Ubuntu package `acl`):

```sh
make test
```
