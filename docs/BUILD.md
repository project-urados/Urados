# Building Urados

Urados contains two independently buildable native C components:

- **Package manager (`pkg_mgr/`)** — builds `urpkg` and `urdev`.
- **Uinit (`init/`)** — builds the `uinit` init system.

The repository root Makefile delegates to each component Makefile. A component target checks only that component's dependencies, so you can build Uinit without installing the package-manager libraries, or build the package manager without installing `libblkid`.

## Dependencies

All builds require:

- a C11 compiler (`gcc` or `clang`)
- GNU Make
- `pkg-config`

The package manager additionally requires development metadata and libraries for:

- libxml2 (`libxml-2.0`)
- libzip (`libzip`)
- libcurl (`libcurl`)
- OpenSSL 3 (`libcrypto`)
- libacl (`libacl`)

Uinit additionally requires the util-linux `libblkid` development package (`blkid`).

### Debian or Ubuntu

```sh
sudo apt update
sudo apt install \
  build-essential pkg-config \
  libxml2-dev libzip-dev libcurl4-openssl-dev libssl-dev libacl1-dev \
  libblkid-dev
```

If you only need Uinit:

```sh
sudo apt install build-essential pkg-config libblkid-dev
```

### Fedora or RHEL-like systems

```sh
sudo dnf install \
  gcc make pkgconf-pkg-config \
  libxml2-devel libzip-devel libcurl-devel openssl-devel libacl-devel \
  libblkid-devel
```

If you only need Uinit:

```sh
sudo dnf install gcc make pkgconf-pkg-config libblkid-devel
```

Runtime libraries alone are not enough; the `pkg-config` files and development headers must also be installed.

## Build commands

Run these commands from the repository root:

```sh
# Build both components (the default).
make -j2

# Build only the package manager and developer tool.
make pkg_mgr -j2

# Build only Uinit.
make uinit -j2
```

The output files are:

| Target | Output |
| --- | --- |
| `make pkg_mgr` | `pkg_mgr/build/urpkg`, `pkg_mgr/build/urdev` |
| `make uinit` | `init/build/uinit` |
| `make` | all three binaries |

The same commands can be run inside `pkg_mgr/` or `init/` when working on one component directly.

## Selective static linking for Uinit

Uinit supports static linking of one `pkg-config` module and the libraries that module declares as dependencies. The option applies only to Uinit; it does not change package-manager linking.

For the current Uinit dependency:

```sh
make uinit STATIC_LIB=blkid
```

`STATIC_LIB` is a `pkg-config` module name, not an arbitrary `-l` argument. The build uses `pkg-config --libs --static STATIC_LIB`, then enables static linking only while those library flags are processed. The selected static archives must be installed by the platform's development packages. An unknown module, or a module with no static link flags, stops with an error before compilation.

Use a normal build when a static archive is unavailable:

```sh
make uinit
```

## Tests and checks

### Package manager

```sh
make test
```

This builds the package manager, runs certificate tests, runs the extraction-limit test, and runs the staged end-to-end suite. The end-to-end suite requires passwordless `sudo`, ACL utilities such as `getfacl`, and the host's normal filesystem tools. Its staged root is under `pkg_mgr/build/test/root`; it does not intentionally modify the host's `/data` tree or account database.

### Uinit

```sh
make -C init test
```

The Uinit suite includes parser tests, staged configuration and process tests, identity-drop tests, and mount tests. Mount, identity, and PID 1 scenarios need passwordless `sudo`; loop-device tests also need `losetup`, `sfdisk`, and `mkfs.ext4`.

For a quick configuration-only validation:

```sh
make uinit
make -C init check-example
```

`check-example` runs the example tree with `--check`; it parses reachable units and performs no mounts or commands.

## Installation

The root `install` target installs only the package-manager tools because their `/usr/local/bin` destination is suitable for ordinary command-line use:

```sh
sudo make install
```

Override the destination when packaging a filesystem image:

```sh
make install DESTDIR="$PWD/stage" PREFIX=/usr
```

This creates `stage/usr/bin/urpkg` and `stage/usr/bin/urdev`.

Uinit is a boot component and does not have a generic `make install` destination. Install it into the target image's intended PID 1 location as part of the image or initramfs integration, preserving the target system's ownership, mode, and boot configuration.

## Cleaning

```sh
make clean
```

This removes both `pkg_mgr/build/` and `init/build/`. To clean one component only, use `make -C pkg_mgr clean` or `make -C init clean`.
