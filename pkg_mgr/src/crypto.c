/*
 * crypto.c - package signatures and X.509 code-signing certificates.
 *
 * Legacy packages may use a raw trusted Ed25519 public key. Certificate
 * packages carry a PEM leaf/intermediate chain; trust anchors are self-signed
 * CA certificates (*.crt) installed by the device administrator. Private keys
 * are only read by urdev on the publisher's machine.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "urados_pkg.h"

static int is_ed25519(EVP_PKEY *k)
{
    return EVP_PKEY_get_base_id(k) == EVP_PKEY_ED25519;
}
static int is_supported_signing_key(EVP_PKEY *k)
{
    int id = EVP_PKEY_get_base_id(k);
    if (id == EVP_PKEY_ED25519)
        return 1;
    if (id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS)
        return EVP_PKEY_get_bits(k) >= 2048;
    if (id == EVP_PKEY_EC)
        return EVP_PKEY_get_bits(k) >= 256;
    return 0;
}
static const EVP_MD *signing_digest(EVP_PKEY *key)
{
    return is_ed25519(key) ? NULL : EVP_sha256();
}
void pkg_free_keys(EVP_PKEY **keys, size_t n)
{
    size_t i;
    if (!keys)
        return;
    for (i = 0; i < n; i++)
        EVP_PKEY_free(keys[i]);
    free(keys);
}
/* Load legacy raw public keys (*.pem). Certificate roots use the .crt suffix. */
int pkg_load_trusted_keys(const char *dir, EVP_PKEY ***out, size_t *outn,
                          char *err, size_t errlen)
{
    DIR *d;
    struct dirent *e;
    EVP_PKEY **keys = NULL;
    size_t cnt = 0, cap = 0;
    d = opendir(dir);
    if (!d) {
        pkg_seterr(err, errlen, "cannot open trusted key dir %s: %s", dir, strerror(errno));
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        char path[PKG_PATH_MAX];
        size_t l = strlen(e->d_name);
        int fd;
        FILE *fp;
        EVP_PKEY *k;
        if (l < 5 || e->d_name[0] == '.' || strcmp(e->d_name + l - 4, ".pem") != 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= (int)sizeof(path))
            continue;
        fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            continue;
        fp = fdopen(fd, "r");
        if (!fp) {
            close(fd);
            continue;
        }
        k = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!k) {
            pkg_seterr(err, errlen, "invalid legacy public key %s (certificate roots must end in .crt)", path);
            goto fail;
        }
        if (EVP_PKEY_get_base_id(k) != EVP_PKEY_ED25519) {
            EVP_PKEY_free(k);
            pkg_seterr(err, errlen, "legacy trusted key %s is not Ed25519", path);
            goto fail;
        }
        if (cnt == cap) {
            size_t ncap = cap ? cap * 2 : 4;
            EVP_PKEY **nk = realloc(keys, ncap * sizeof(*nk));
            if (!nk) {
                EVP_PKEY_free(k);
                pkg_seterr(err, errlen, "out of memory");
                goto fail;
            }
            keys = nk;
            cap = ncap;
        }
        keys[cnt++] = k;
    }
    closedir(d);
    *out = keys;
    *outn = cnt;
    return 0;
fail:
    closedir(d);
    pkg_free_keys(keys, cnt);
    return -1;
}
int pkg_check_signature(EVP_PKEY **keys, size_t n, const unsigned char *data,
                        size_t dlen, const unsigned char *sig, size_t slen)
{
    size_t i;
    for (i = 0; i < n; i++) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int ok;
        if (!ctx)
            return -1;
        ok = EVP_DigestVerifyInit(ctx, NULL, signing_digest(keys[i]), NULL, keys[i]) == 1 &&
             EVP_DigestVerify(ctx, sig, slen, data, dlen) == 1;
        EVP_MD_CTX_free(ctx);
        if (ok)
            return 0;
    }
    return -1;
}
int pkg_sign_data(EVP_PKEY *key, const unsigned char *data, size_t dlen,
                  unsigned char **sig, size_t *slen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t len = 0;
    unsigned char *buf = NULL;
    int rc = -1;
    if (!ctx || !is_supported_signing_key(key))
        goto out;
    if (EVP_DigestSignInit(ctx, NULL, signing_digest(key), NULL, key) != 1)
        goto out;
    if (EVP_DigestSign(ctx, NULL, &len, data, dlen) != 1 || len == 0)
        goto out;
    buf = malloc(len);
    if (!buf)
        goto out;
    if (EVP_DigestSign(ctx, buf, &len, data, dlen) != 1)
        goto out;
    *sig = buf;
    *slen = len;
    buf = NULL;
    rc = 0;
out:
    free(buf);
    EVP_MD_CTX_free(ctx);
    return rc;
}
/* Loads RSA (>=2048), EC (>=256 bits), or Ed25519 PEM private keys. */
int pkg_load_private_key(const char *path, EVP_PKEY **key, char *err, size_t errlen)
{
    int fd;
    FILE *fp;
    EVP_PKEY *k;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        pkg_seterr(err, errlen, "cannot open key %s: %s", path, strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "r");
    if (!fp) {
        close(fd);
        pkg_seterr(err, errlen, "cannot read key %s", path);
        return -1;
    }
    k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!k) {
        pkg_seterr(err, errlen, "cannot load key %s (wrong passphrase or not a PEM key)", path);
        return -1;
    }
    if (!is_supported_signing_key(k)) {
        EVP_PKEY_free(k);
        pkg_seterr(err, errlen, "key %s must be Ed25519, RSA >= 2048 bits, or EC >= 256 bits", path);
        return -1;
    }
    *key = k;
    return 0;
}
/* Creates a new file (O_EXCL, no symlinks), writes data and syncs it. */
static int write_new_file(const char *path, mode_t mode, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return -1;
    if (pkg_write_all(fd, data, len) != 0 || fsync(fd) != 0) {
        close(fd);
        unlink(path);
        return -1;
    }
    return close(fd);
}
int pkg_generate_key(const char *priv_path, const char *pub_path, int encrypt,
                     char *err, size_t errlen)
{
    EVP_PKEY *key = NULL;
    BIO *pb = NULL, *kb = NULL;
    char *pub = NULL, *priv = NULL;
    long plen, klen;
    int rc = -1;
    key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (!key) {
        pkg_seterr(err, errlen, "key generation failed");
        return -1;
    }
    pb = BIO_new(BIO_s_mem());
    kb = BIO_new(BIO_s_mem());
    if (!pb || !kb) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (PEM_write_bio_PUBKEY(pb, key) != 1) {
        pkg_seterr(err, errlen, "cannot encode public key");
        goto out;
    }
    if (PEM_write_bio_PrivateKey(kb, key, encrypt ? EVP_aes_256_cbc() : NULL,
                                 NULL, 0, NULL, NULL) != 1) {
        pkg_seterr(err, errlen, "cannot encode private key (passphrase mismatch?)");
        goto out;
    }
    plen = BIO_get_mem_data(pb, &pub);
    klen = BIO_get_mem_data(kb, &priv);
    if (write_new_file(pub_path, 0644, pub, (size_t)plen) != 0) {
        pkg_seterr(err, errlen, "cannot write %s: %s", pub_path, strerror(errno));
        goto out;
    }
    if (write_new_file(priv_path, 0600, priv, (size_t)klen) != 0) {
        pkg_seterr(err, errlen, "cannot write %s: %s", priv_path, strerror(errno));
        unlink(pub_path);
        goto out;
    }
    rc = 0;
out:
    BIO_free(pb);
    BIO_free(kb);
    EVP_PKEY_free(key);
    return rc;
}
static int cert_has_codesign_usage(X509 *cert)
{
    ASN1_BIT_STRING *ku = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    int digital_signature = ku && ASN1_BIT_STRING_get_bit(ku, 0);
    int codesign = 0;
    int i;
    if (eku) {
        for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
            if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == NID_code_sign) {
                codesign = 1;
                break;
            }
        }
    }
    ASN1_BIT_STRING_free(ku);
    EXTENDED_KEY_USAGE_free(eku);
    return X509_check_ca(cert) == 0 && digital_signature && codesign;
}
/* A CA EKU, when present, constrains every subordinate certificate. */
static int ca_eku_allows_codesign(X509 *cert)
{
    EXTENDED_KEY_USAGE *eku;
    int extidx = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    int crit = 0, allowed = 0, i;
    if (extidx < 0)
        return 1;
    if (X509_get_ext_by_NID(cert, NID_ext_key_usage, extidx) >= 0)
        return 0;
    eku = X509_get_ext_d2i(cert, NID_ext_key_usage, &crit, NULL);
    if (!eku)
        return 0;
    for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
        int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i));
        if (nid == NID_code_sign || nid == NID_anyExtendedKeyUsage) {
            allowed = 1;
            break;
        }
    }
    EXTENDED_KEY_USAGE_free(eku);
    return allowed;
}
static int is_pem_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}
/* Strictly parse a leaf-first PEM chain; reject junk and cap it at 16 certs. */
static int parse_signer_chain(const unsigned char *pem, size_t pemlen,
                              X509 **leaf_out, STACK_OF(X509) **chain_out,
                              char *err, size_t errlen)
{
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    const size_t beginlen = sizeof(begin) - 1, endlen = sizeof(end) - 1;
    size_t pos = 0;
    int count = 0, rc = -1;
    X509 *leaf = NULL;
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain || pemlen > INT_MAX) {
        pkg_seterr(err, errlen, "certificate chain is too large or out of memory");
        goto out;
    }
    while (pos < pemlen) {
        size_t start, endpos, blocklen, j;
        BIO *bio;
        X509 *cert;
        while (pos < pemlen && is_pem_space(pem[pos]))
            pos++;
        if (pos == pemlen)
            break;
        if (pemlen - pos < beginlen || memcmp(pem + pos, begin, beginlen) != 0) {
            pkg_seterr(err, errlen, "unexpected data in signer certificate chain");
            goto out;
        }
        start = pos;
        pos += beginlen;
        if (pos >= pemlen || (pem[pos] != '\n' && pem[pos] != '\r')) {
            pkg_seterr(err, errlen, "malformed PEM certificate header");
            goto out;
        }
        if (pem[pos++] == '\r' && pos < pemlen && pem[pos] == '\n')
            pos++;
        endpos = pemlen;
        for (j = pos; j + endlen <= pemlen; j++) {
            if ((j == 0 || pem[j - 1] == '\n') && memcmp(pem + j, end, endlen) == 0) {
                endpos = j;
                break;
            }
        }
        if (endpos == pemlen) {
            pkg_seterr(err, errlen, "unterminated PEM certificate");
            goto out;
        }
        pos = endpos + endlen;
        if (pos < pemlen && pem[pos] == '\r')
            pos++;
        if (pos < pemlen && pem[pos] == '\n')
            pos++;
        blocklen = pos - start;
        bio = BIO_new_mem_buf(pem + start, (int)blocklen);
        if (!bio) {
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!cert) {
            ERR_clear_error();
            pkg_seterr(err, errlen, "invalid PEM certificate in signer chain");
            goto out;
        }
        if (++count > 16) {
            X509_free(cert);
            pkg_seterr(err, errlen, "signer certificate chain has too many certificates (max 16)");
            goto out;
        }
        if (!leaf)
            leaf = cert;
        else if (!sk_X509_push(chain, cert)) {
            X509_free(cert);
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
    }
    if (!leaf) {
        pkg_seterr(err, errlen, "signer certificate chain contains no certificates");
        goto out;
    }
    *leaf_out = leaf;
    *chain_out = chain;
    leaf = NULL;
    chain = NULL;
    rc = 0;
out:
    X509_free(leaf);
    sk_X509_pop_free(chain, X509_free);
    return rc;
}
int pkg_validate_signer_certificate(const unsigned char *chain, size_t chainlen,
                                    EVP_PKEY *key, char *err, size_t errlen)
{
    X509 *leaf = NULL;
    STACK_OF(X509) *untrusted = NULL;
    EVP_PKEY *pub = NULL;
    int rc = -1;
    if (parse_signer_chain(chain, chainlen, &leaf, &untrusted, err, errlen) != 0)
        return -1;
    pub = X509_get_pubkey(leaf);
    if (!pub || EVP_PKEY_eq(pub, key) != 1) {
        pkg_seterr(err, errlen, "signer certificate does not match the private key");
        goto out;
    }
    if (!cert_has_codesign_usage(leaf)) {
        pkg_seterr(err, errlen, "signer certificate must be non-CA and allow digitalSignature/codeSigning");
        goto out;
    }
    rc = 0;
out:
    EVP_PKEY_free(pub);
    X509_free(leaf);
    sk_X509_pop_free(untrusted, X509_free);
    return rc;
}
static int is_suffix(const char *name, const char *suffix)
{
    size_t n = strlen(name), s = strlen(suffix);
    return n >= s && strcmp(name + n - s, suffix) == 0;
}
static int load_root_certificates(const char *dir, X509_STORE *store,
                                  size_t *loaded, char *err, size_t errlen)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d) {
        pkg_seterr(err, errlen, "cannot open certificate root directory %s: %s", dir, strerror(errno));
        return -1;
    }
    *loaded = 0;
    while ((e = readdir(d)) != NULL) {
        char path[PKG_PATH_MAX];
        int fd;
        FILE *fp;
        X509 *cert;
        EVP_PKEY *pub;
        ASN1_BIT_STRING *ku;
        int valid;
        if (e->d_name[0] == '.' || !is_suffix(e->d_name, ".crt"))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= (int)sizeof(path))
            continue;
        fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            continue;
        fp = fdopen(fd, "r");
        if (!fp) {
            close(fd);
            continue;
        }
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!cert) {
            pkg_seterr(err, errlen, "invalid root certificate %s", path);
            closedir(d);
            return -1;
        }
        ku = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
        valid = X509_check_ca(cert) > 0 && ku && ASN1_BIT_STRING_get_bit(ku, 5);
        ASN1_BIT_STRING_free(ku);
        pub = X509_get_pubkey(cert);
        valid = valid && pub && X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0 &&
                X509_verify(cert, pub) == 1;
        EVP_PKEY_free(pub);
        if (!valid) {
            X509_free(cert);
            pkg_seterr(err, errlen, "trust anchor %s must be a self-signed CA with keyCertSign", path);
            closedir(d);
            return -1;
        }
        if (X509_STORE_add_cert(store, cert) != 1) {
            unsigned long code = ERR_peek_last_error();
            if (ERR_GET_REASON(code) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(cert);
                pkg_seterr(err, errlen, "cannot add trust anchor %s", path);
                closedir(d);
                return -1;
            }
            ERR_clear_error();
        }
        (*loaded)++;
        X509_free(cert);
    }
    closedir(d);
    return 0;
}
int pkg_verify_certificate_signature(const unsigned char *chain, size_t chainlen,
                                     const char *roots_dir,
                                     const unsigned char *data, size_t datalen,
                                     const unsigned char *sig, size_t siglen,
                                     char *err, size_t errlen)
{
    X509 *leaf = NULL;
    STACK_OF(X509) *untrusted = NULL, *verified_chain = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    EVP_PKEY *pub = NULL;
    EVP_PKEY *one_key[1];
    size_t roots = 0;
    int i, rc = -1;
    if (parse_signer_chain(chain, chainlen, &leaf, &untrusted, err, errlen) != 0)
        goto out;
    store = X509_STORE_new();
    ctx = X509_STORE_CTX_new();
    if (!store || !ctx) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (!cert_has_codesign_usage(leaf)) {
        pkg_seterr(err, errlen, "signer certificate must allow digitalSignature/codeSigning");
        goto out;
    }
    if (load_root_certificates(roots_dir, store, &roots, err, errlen) != 0)
        goto out;
    if (roots == 0) {
        pkg_seterr(err, errlen, "no trusted root certificates (*.crt) in %s", roots_dir);
        goto out;
    }
    if (X509_STORE_CTX_init(ctx, store, leaf, untrusted) != 1) {
        pkg_seterr(err, errlen, "cannot initialize signer certificate validation");
        goto out;
    }
    X509_VERIFY_PARAM_set_auth_level(X509_STORE_CTX_get0_param(ctx), 2);
    if (X509_verify_cert(ctx) != 1) {
        int e = X509_STORE_CTX_get_error(ctx);
        pkg_seterr(err, errlen, "signer certificate chain is not trusted: %s",
                   X509_verify_cert_error_string(e));
        goto out;
    }
    verified_chain = X509_STORE_CTX_get1_chain(ctx);
    if (!verified_chain) {
        pkg_seterr(err, errlen, "cannot inspect validated certificate path");
        goto out;
    }
    for (i = 1; i < sk_X509_num(verified_chain); i++) {
        if (!ca_eku_allows_codesign(sk_X509_value(verified_chain, i))) {
            pkg_seterr(err, errlen, "a CA certificate in the signer path restricts usage to non-code-signing purposes");
            goto out;
        }
    }
    pub = X509_get_pubkey(leaf);
    if (!pub) {
        pkg_seterr(err, errlen, "cannot read public key from signer certificate");
        goto out;
    }
    if (!is_supported_signing_key(pub)) {
        pkg_seterr(err, errlen, "signer certificate key must be Ed25519, RSA >= 2048 bits, or EC >= 256 bits");
        goto out;
    }
    one_key[0] = pub;
    if (pkg_check_signature(one_key, 1, data, datalen, sig, siglen) != 0) {
        pkg_seterr(err, errlen, "package signature does not match its signer certificate");
        goto out;
    }
    rc = 0;
out:
    EVP_PKEY_free(pub);
    sk_X509_pop_free(verified_chain, X509_free);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_pop_free(untrusted, X509_free);
    X509_free(leaf);
    return rc;
}
int pkg_create_csr(const char *keypath, const char *csrpath, const char *common_name,
                   char *err, size_t errlen)
{
    EVP_PKEY *key = NULL;
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    BIO *mem = NULL;
    char *pem = NULL;
    long pemlen;
    int fd = -1, rc = -1;
    if (!common_name || !*common_name || strlen(common_name) > 255) {
        pkg_seterr(err, errlen, "CSR common name must contain 1 to 255 characters");
        return -1;
    }
    if (pkg_load_private_key(keypath, &key, err, errlen) != 0)
        return -1;
    req = X509_REQ_new();
    name = X509_NAME_new();
    mem = BIO_new(BIO_s_mem());
    if (!req || !name || !mem) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                   (const unsigned char *)common_name, -1, -1, 0) != 1 ||
        X509_REQ_set_version(req, 0L) != 1 || X509_REQ_set_subject_name(req, name) != 1 ||
        X509_REQ_set_pubkey(req, key) != 1 ||
        X509_REQ_sign(req, key, signing_digest(key)) <= 0 ||
        PEM_write_bio_X509_REQ(mem, req) != 1) {
        pkg_seterr(err, errlen, "cannot create certificate signing request");
        goto out;
    }
    pemlen = BIO_get_mem_data(mem, &pem);
    fd = open(csrpath, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0 || pkg_write_all(fd, pem, (size_t)pemlen) != 0 || fsync(fd) != 0) {
        pkg_seterr(err, errlen, "cannot write CSR %s: %s", csrpath, strerror(errno));
        if (fd >= 0) {
            close(fd);
            unlink(csrpath);
            fd = -1;
        }
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        unlink(csrpath);
        pkg_seterr(err, errlen, "cannot finish CSR %s", csrpath);
        goto out;
    }
    fd = -1;
    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    BIO_free(mem);
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return rc;
}
