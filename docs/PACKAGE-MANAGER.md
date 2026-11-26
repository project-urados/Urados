# Package manager and developer tools

The package-manager component is in `pkg_mgr/` and produces two binaries:

- `urdev` runs on a publisher or developer workstation. It creates projects, validates manifests, creates keys and CSRs, and signs packages.
- `urpkg` runs with administrator privileges on a device. It verifies, installs, and starts signed packages.

The package format is an APK/JAR-style ZIP with SHA-256 metadata. See [X.509 package signing](CODE-SIGNING.md) for certificate policy and CA operations.

![Package manager lifecycle](images/flow.png)

## Build

From the repository root:

```sh
make pkg_mgr
```

The binaries are written to `pkg_mgr/build/`. For dependencies, tests, installation, and static Uinit linking, see [Building Urados](BUILD.md).

## Create a project

Create a skeleton project with a safe application name:

```sh
urdev init ./my-app my-app 1.0.0
```

The generated project contains `manifest.xml` and an `app/` directory. Put the application entry point and payload files below `app/`. Application names must match `[a-z_][a-z0-9_-]*` and be no longer than 32 bytes.

Validate the project before signing:

```sh
urdev check ./my-app
```

The check validates the manifest and entry path without creating an install or device state.

## Create publisher credentials

Generate a private key locally. Keep it secret and do not copy it to the device or CA host:

```sh
urdev keygen company-private.pem company-public.pem
```

By default the private key is encrypted. For a development-only key without a passphrase:

```sh
urdev keygen company-private.pem company-public.pem --no-passphrase
```

Create a CSR and send only the CSR to the certificate authority:

```sh
urdev csr company-private.pem company.csr \
  --country US \
  --organization "Example Company" \
  --common-name "Example Publisher" \
  --email developer@example.com
```

The signing certificate must be a publisher leaf with `digitalSignature` key usage and `codeSigning` extended key usage. The package contains the publisher leaf followed by any intermediate certificates; it does not contain the trusted root.

## Build a signed package

Concatenate the leaf certificate first, followed by any intermediate certificates:

```sh
cat company-signing.crt issuing-intermediate.crt > company-chain.pem
```

Create the signed package:

```sh
urdev pack ./my-app my-app-1.0.0.zip \
  --key company-private.pem \
  --cert company-chain.pem
```

The package contains:

```text
manifest.xml
SIGNER_CERTS.pem
META-INF/MANIFEST.MF
META-INF/CERT.SF
META-INF/CERT.SIG
app/...
```

The private key is never copied into the ZIP. `META-INF/MANIFEST.MF` hashes the package content, `CERT.SF` signs the manifest metadata, and `CERT.SIG` contains the publisher signature over `CERT.SF`.

## Configure device trust

The device administrator installs only public, self-signed CA roots in the trust directory:

```sh
sudo install -d -m 0755 /etc/urados/keys
sudo install -m 0644 urados-root.crt /etc/urados/keys/urados-root.crt
```

Each `.crt` file must contain one complete PEM-encoded self-signed CA certificate with `CA:TRUE` and `keyCertSign`. Do not install the CA private key. There is no unsigned-package or raw-public-key compatibility mode.

## Verify, install, and start

Verify a package before changing device state:

```sh
urpkg verify my-app-1.0.0.zip
```

Install from a local path or HTTP(S) URL:

```sh
sudo urpkg install my-app-1.0.0.zip
sudo urpkg install https://example.invalid/releases/my-app-1.0.0.zip
```

Start an installed application and pass arguments after the application name:

```sh
sudo urpkg start my-app -- hello world
```

`urpkg start` verifies the root-owned archive again, extracts a fresh package-code tree, atomically publishes it, drops privileges in the child process, sets `no_new_privs`, clears the inherited environment, and executes the manifest entry.

## Command reference

### `urdev`

```text
urdev init   <dir> <name> [version]
urdev check  <dir>
urdev keygen <private.pem> <public.pem> [--no-passphrase]
urdev csr    <private.pem> <request.csr> [subject options]
urdev pack   <dir> <out.zip> --key FILE --cert CHAIN.pem
```

CSR subject options are `--common-name`, `--country`, `--state`, `--locality`, `--organization`, `--organizational-unit`, and `--email`. `--common-name` is required.

### `urpkg`

```text
urpkg [--root DIR] [--keys DIR] verify <package.zip>
urpkg [--root DIR] [--keys DIR] install <source>
urpkg [--root DIR] [--keys DIR] start <name> [args...]
```

`--keys DIR` selects the administrator trust directory. By default it is `<root>/etc/urados/keys`. `--root DIR` prefixes device paths and is intended for staged development and tests; it is not a security boundary.

## On-device storage

After installation, the trusted archive is stored at:

```text
/data/app_progs/<name>.zip          root:root, mode 0600
/data/app_progs/.locks/             root-only per-app locks
/data/app/<name>/data/              app-private writable data
/data/app/<name>/system_cache/app/  extracted package programs
/data/app/<name>/system_cache/user/ app-created mutable programs
```

The package archive is the source of truth for verification. Failed verification or extraction does not replace the previous complete package-code tree. The application sandbox and its limitations are documented in [App filesystem and execution model](APP-SANDBOX.md).

## Staged operation and testing

Use `--root` to exercise device paths under a staging directory:

```sh
make pkg_mgr
sudo -n pkg_mgr/build/urpkg --root "$PWD/pkg_mgr/build/test-root" \
  --keys "$PWD/pkg_mgr/build/test-root/etc/urados/keys" \
  verify my-app-1.0.0.zip
```

The staged mode is useful for tests, but a plain chroot-style path prefix is not a production security boundary. Run the repository test suite with:

```sh
make test
```

The end-to-end tests require passwordless `sudo` and ACL tools. Review the output and verify the target device separately; passing staged tests does not prove the host's account, mount, or filesystem configuration.
