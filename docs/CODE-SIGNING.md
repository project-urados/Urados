# X.509 package signing

Urados supports publisher certificates for package signatures. This is code signing, not TLS: the leaf certificate must have `digitalSignature` key usage and the `codeSigning` extended key usage. RSA keys of at least 2048 bits, EC keys of at least 256 bits, and Ed25519 keys are supported for package signatures.

## Security model

A publisher creates and keeps its private key on its own computer. Only a CSR is sent to the CA for approval. The CA returns the signed publisher certificate (and any intermediate certificates); the private key is never sent to Urados, the CA operator, or an installation device. The CA signing key should be kept offline or in a dedicated CA/HSM environment and must not be installed in the package manager.

The device administrator installs only the public self-signed CA root certificate in `/etc/urados/keys/` as a PEM `.crt` file. Every package must contain the publisher's leaf certificate followed by any intermediate certificates in `SIGNER_CERTS.pem`; do not include the root certificate. The complete chain file is included in the signed package digest, so changing or replacing it invalidates the package signature. `urpkg` verifies the certificate path to an installed root, certificate validity dates, the code-signing EKU and digital-signature key usage, then verifies the package signature. The certificate chain is metadata and is not extracted as application content.

Certificate validity is checked when `urpkg verify`, `install`, or `start` runs. There is no trusted timestamp or OCSP/CRL support yet: the publisher certificate must still be valid each time an installed package is verified, and individual publisher-certificate revocation is not currently enforced. Removing/replacing a root invalidates every publisher chain issued under it, not just one publisher. Treat this as an initial certificate-verification implementation; add and distribute a revocation mechanism before relying on individual publisher revocation in production.

## Publisher workflow

Generate a private key locally. For example, to create an encrypted 3072-bit RSA key:

```sh
openssl genpkey -algorithm RSA -aes-256-cbc \
  -pkeyopt rsa_keygen_bits:3072 -out company-private.pem
```

Create a CSR using `urdev` (OpenSSL will prompt for the private-key passphrase if the key is encrypted):

```sh
urdev csr company-private.pem company.csr "Company Publisher"
openssl req -in company.csr -verify -noout
```

Send **only** `company.csr` to the CA operator using the organization's approved process. Verify the certificate returned by the CA before use. The returned leaf certificate must be issued for code signing, not TLS/web-server authentication. For a chain with an intermediate, concatenate the leaf first, then the intermediate(s):

```sh
cat company-signing.crt issuing-intermediate.crt > company-chain.pem
```

Sign the project locally. The private key is read only by `urdev` on the publisher's machine; the package carries the public certificate chain:

```sh
urdev pack ./my-app my-app.zip \
  --key company-private.pem --cert company-chain.pem
```

The private key is not copied into the ZIP. The first PEM certificate in the chain must correspond to the supplied private key.

## CA operator workflow

Review and approve the CSR according to your enrollment policy. Keep the CA private key in a controlled offline signing environment. Issue a publisher leaf certificate with a short, policy-appropriate lifetime and these extensions:

```ini
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
```

For example, with an RSA/ECDSA CA key and OpenSSL, save those extensions as `publisher-ext.cnf` and sign the approved CSR in the protected CA environment:

```sh
openssl x509 -req -in company.csr \
  -CA urados-root.crt -CAkey urados-root.key -CAcreateserial \
  -out company-signing.crt -days 180 -sha256 \
  -extfile publisher-ext.cnf
```

Do not copy `urados-root.key` to a package build host or device. Protect and back up the CA key separately; the `.crt` public root can be distributed freely.

## Device administrator workflow

Install the public root as a trusted root, not the CA private key:

```sh
sudo install -d -m 0755 /etc/urados/keys
sudo install -m 0644 urados-root.crt /etc/urados/keys/urados-root.crt
```

Then verify a package before installation:

```sh
urpkg verify my-app.zip
```

The `--keys DIR` option selects the trust directory. Its `.crt` files must each contain exactly one complete PEM-encoded self-signed CA certificate with `CA:TRUE` and `keyCertSign`. Raw public-key files are not trust anchors; malformed or extra certificates in a root file are rejected. Keep this directory administrator-controlled. There is no raw-key or unsigned-package compatibility mode: all packages require `SIGNER_CERTS.pem` and a chain to an installed CA root. Chains are limited to 16 certificates; archives and aggregate uncompressed content are each limited to 1 GiB, with individual payload files limited to 256 MiB.
