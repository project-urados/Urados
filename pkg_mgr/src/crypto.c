/*
 * crypto.c - Ed25519 signing and verification with OpenSSL 3.
 *
 * Trusted keys are PEM public keys (*.pem) in one directory. A package is
 * accepted if any trusted key verifies its SIGNATURE. Ed25519 signs the whole
 * message, so the caller does not choose a digest algorithm.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "urados_pkg.h"

static int is_ed25519(EVP_PKEY *k)
{
    return EVP_PKEY_get_base_id(k) == EVP_PKEY_ED25519;
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

/* Loads every *.pem Ed25519 public key in dir. Symlinks are never trusted. */
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
            pkg_seterr(err, errlen, "invalid public key %s", path);
            goto fail;
        }
        if (!is_ed25519(k)) {
            EVP_PKEY_free(k);
            pkg_seterr(err, errlen, "trusted key %s is not Ed25519", path);
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
    if (cnt == 0) {
        pkg_seterr(err, errlen, "no trusted keys in %s", dir);
        free(keys);
        return -1;
    }
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
        ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, keys[i]) == 1 &&
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

    if (!ctx)
        return -1;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1)
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

/* Loads an Ed25519 private key. Encrypted keys prompt on the terminal. */
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
        pkg_seterr(err, errlen, "cannot load private key %s (wrong passphrase or not a PEM key)", path);
        return -1;
    }
    if (!is_ed25519(k)) {
        EVP_PKEY_free(k);
        pkg_seterr(err, errlen, "key %s is not Ed25519", path);
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

/*
 * Creates an Ed25519 key pair. The private key is written 0600. With
 * `encrypt` it is protected by a passphrase (AES-256-CBC PEM), which OpenSSL
 * asks for on the terminal.
 */
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
