#!/bin/sh
# Certificate-signing tests; independent of the SELinux install staging tests.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
B="$HERE/build"
T=$(mktemp -d "${TMPDIR:-/tmp}/urados-cert-test.XXXXXX")
PASS=0
FAIL=0
cleanup() { rm -rf "$T"; }
trap cleanup EXIT HUP INT TERM
ok() { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }
expect_ok() {
    desc=$1; shift
    if "$@" >"$T/last.log" 2>&1; then ok "$desc"; else bad "$desc"; cat "$T/last.log"; fi
}
expect_fail() {
    desc=$1; shift
    if "$@" >"$T/last.log" 2>&1; then bad "$desc (succeeded)"; cat "$T/last.log"; else ok "$desc"; fi
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/root.key" -out "$T/root.crt" \
    -days 3650 -subj "/CN=Urados Certificate Test Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/intermediate.key" >/dev/null 2>&1
openssl req -new -key "$T/intermediate.key" -out "$T/intermediate.csr" \
    -subj "/CN=Urados Test Issuing CA" >/dev/null 2>&1
cat > "$T/intermediate.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$T/intermediate.csr" -CA "$T/root.crt" -CAkey "$T/root.key" \
    -CAcreateserial -out "$T/intermediate.crt" -days 1000 -sha256 \
    -extfile "$T/intermediate.ext" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/publisher.key" >/dev/null 2>&1
expect_ok "urdev creates publisher CSR with full subject" "$B/urdev" csr "$T/publisher.key" "$T/publisher.csr" \
    --country US --state California --locality "San Francisco" \
    --organization "Urados Test" --organizational-unit "Publishers" \
    --common-name "Test Publisher" --email publisher@example.test
expect_ok "publisher CSR self-signature verifies" openssl req -in "$T/publisher.csr" -verify -noout
expect_ok "publisher CSR contains requested subject" sh -c \
    "openssl req -in '$T/publisher.csr' -noout -subject | grep -F 'CN = Test Publisher' | grep -F 'O = Urados Test'"
cat > "$T/codesign.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$T/publisher.csr" -CA "$T/intermediate.crt" -CAkey "$T/intermediate.key" \
    -CAcreateserial -out "$T/publisher.crt" -days 365 -sha256 \
    -extfile "$T/codesign.ext" >/dev/null 2>&1
cat "$T/publisher.crt" "$T/intermediate.crt" > "$T/publisher-chain.pem"
mkdir -p "$T/trusted"
cp "$T/root.crt" "$T/trusted/test-root.crt"
"$B/urdev" init "$T/app" certdemo 1.0.0 >/dev/null
echo '#!/bin/sh' > "$T/app/app/certdemo"
echo 'echo certificate-signed' >> "$T/app/app/certdemo"
chmod 0755 "$T/app/app/certdemo"
expect_ok "urdev packs with local key and certificate" "$B/urdev" pack "$T/app" "$T/certified.zip" --key "$T/publisher.key" --cert "$T/publisher-chain.pem"
expect_ok "urpkg validates signature and chain to installed CA root" "$B/urpkg" --keys "$T/trusted" verify "$T/certified.zip"

# Test aggregate decompression guards using compact zero-filled ZIP entries and
# test-only binaries built with a 64 KiB aggregate budget.
mkdir -p "$T/limit-bomb/app" "$T/empty-trust" "$T/extract-output"
for name in one two three; do truncate -s 32768 "$T/limit-bomb/app/$name"; done
echo '<package/>' > "$T/limit-bomb/manifest.xml"
echo x > "$T/limit-bomb/SIGNATURE"
(cd "$T/limit-bomb" && zip -q -9 "$T/limit-bomb.zip" manifest.xml SIGNATURE app/one app/two app/three)
expect_fail "verifier enforces aggregate uncompressed size limits" "$B/urpkg_small_limit" --keys "$T/empty-trust" verify "$T/limit-bomb.zip"
if sudo -n "$B/test_extract_limit" "$T/limit-bomb.zip" "$T/extract-output" >"$T/last.log" 2>&1; then
    ok "extractor enforces aggregate uncompressed size limits"
else
    bad "extractor enforces aggregate uncompressed size limits"
    cat "$T/last.log"
fi

# A second, untrusted CA signs an otherwise valid code-signing certificate.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/rogue-root.key" -out "$T/rogue-root.crt" \
    -days 3650 -subj "/CN=Untrusted Test Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
"$B/urdev" keygen "$T/rogue.key" "$T/rogue.pub" --no-passphrase >/dev/null
"$B/urdev" csr "$T/rogue.key" "$T/rogue.csr" "Untrusted Publisher" >/dev/null
openssl x509 -req -in "$T/rogue.csr" -CA "$T/rogue-root.crt" -CAkey "$T/rogue-root.key" \
    -CAcreateserial -out "$T/rogue.crt" -days 365 -sha256 \
    -extfile "$T/codesign.ext" >/dev/null 2>&1
cp "$T/rogue.crt" "$T/rogue-chain.pem"
expect_ok "urdev creates package with untrusted chain" "$B/urdev" pack "$T/app" "$T/untrusted.zip" --key "$T/rogue.key" --cert "$T/rogue-chain.pem"
expect_fail "urpkg rejects signer chain outside installed roots" "$B/urpkg" --keys "$T/trusted" verify "$T/untrusted.zip"
expect_fail "urdev refuses a certificate/private-key mismatch" "$B/urdev" pack "$T/app" "$T/mismatch.zip" --key "$T/rogue.key" --cert "$T/publisher-chain.pem"
cp "$T/publisher-chain.pem" "$T/chain-junk.pem"
echo 'untrusted trailing bytes' >> "$T/chain-junk.pem"
expect_fail "urdev rejects non-PEM trailing chain data" "$B/urdev" pack "$T/app" "$T/junk-chain.zip" --key "$T/publisher.key" --cert "$T/chain-junk.pem"
{
    cat "$T/publisher.crt"
    i=0
    while [ "$i" -lt 16 ]; do cat "$T/intermediate.crt"; i=$((i + 1)); done
} > "$T/too-many-chain.pem"
expect_fail "urdev rejects chains longer than 16 certificates" "$B/urdev" pack "$T/app" "$T/long-chain.zip" --key "$T/publisher.key" --cert "$T/too-many-chain.pem"

# Package signers and trust anchors are always full X.509 certificates.
"$B/urdev" keygen "$T/legacy.key" "$T/legacy.pub" --no-passphrase >/dev/null
expect_fail "urdev refuses to pack without a complete signer certificate chain" \
    "$B/urdev" pack "$T/app" "$T/no-certificate.zip" --key "$T/legacy.key"
cp "$T/legacy.pub" "$T/trusted/raw-public-key.pem"
expect_fail "raw public keys are rejected from the X.509 trust directory" \
    "$B/urpkg" --keys "$T/trusted" verify "$T/certified.zip"
rm "$T/trusted/raw-public-key.pem"
cp "$T/certified.zip" "$T/no-signer-certificate.zip"
zip -q -d "$T/no-signer-certificate.zip" SIGNER_CERTS.pem
expect_fail "packages without embedded signer certificates are rejected" \
    "$B/urpkg" --keys "$T/trusted" verify "$T/no-signer-certificate.zip"

# A code-signing certificate may not be repurposed from a TLS-only certificate.
sed 's/extendedKeyUsage=codeSigning/extendedKeyUsage=serverAuth/' "$T/codesign.ext" > "$T/tls.ext"
openssl x509 -req -in "$T/publisher.csr" -CA "$T/root.crt" -CAkey "$T/root.key" \
    -CAcreateserial -out "$T/tls.crt" -days 365 -sha256 -extfile "$T/tls.ext" >/dev/null 2>&1
expect_fail "urdev rejects a TLS-only certificate for package signing" "$B/urdev" pack "$T/app" "$T/tls.zip" --key "$T/publisher.key" --cert "$T/tls.crt"

# An intermediate EKU constrains its descendants even when the leaf allows code signing.
sed '/authorityKeyIdentifier/a extendedKeyUsage=serverAuth' "$T/intermediate.ext" > "$T/intermediate-tls.ext"
openssl x509 -req -in "$T/intermediate.csr" -CA "$T/root.crt" -CAkey "$T/root.key" \
    -CAcreateserial -out "$T/intermediate-tls.crt" -days 1000 -sha256 \
    -extfile "$T/intermediate-tls.ext" >/dev/null 2>&1
openssl x509 -req -in "$T/publisher.csr" -CA "$T/intermediate-tls.crt" -CAkey "$T/intermediate.key" \
    -CAcreateserial -out "$T/publisher-via-tls-ca.crt" -days 365 -sha256 \
    -extfile "$T/codesign.ext" >/dev/null 2>&1
cat "$T/publisher-via-tls-ca.crt" "$T/intermediate-tls.crt" > "$T/tls-ca-chain.pem"
expect_ok "urdev can package a leaf with a TLS-constrained intermediate" "$B/urdev" pack "$T/app" "$T/tls-ca.zip" --key "$T/publisher.key" --cert "$T/tls-ca-chain.pem"
expect_fail "urpkg rejects an intermediate restricted to TLS EKU" "$B/urpkg" --keys "$T/trusted" verify "$T/tls-ca.zip"

truncate -s 1073741825 "$T/oversized.zip"
expect_fail "urpkg rejects compressed archives over the size limit" "$B/urpkg" --keys "$T/trusted" verify "$T/oversized.zip"

rm -rf "$T/unpack" && mkdir "$T/unpack"
(cd "$T/unpack" && unzip -q "$T/certified.zip" && echo '# tampered' >>app/certdemo && zip -q -r "$T/tampered.zip" .)
expect_fail "certificate-signed package rejects modified payload" "$B/urpkg" --keys "$T/trusted" verify "$T/tampered.zip"
rm -rf "$T/chain-unpack" && mkdir "$T/chain-unpack"
(cd "$T/chain-unpack" && unzip -q "$T/certified.zip" && echo '# chain changed' >>SIGNER_CERTS.pem && zip -q -r "$T/chain-tampered.zip" .)
expect_fail "certificate-signed package rejects a changed signer chain" "$B/urpkg" --keys "$T/trusted" verify "$T/chain-tampered.zip"

echo "certificate tests passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
