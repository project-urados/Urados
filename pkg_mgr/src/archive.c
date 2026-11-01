/*
 * archive.c - verify and extract package archives (libzip + OpenSSL).
 *
 * Verification never trusts anything before the signature is checked:
 *   1. Walk every zip entry. Accept only manifest.xml, SIGNATURE and
 *      app/<safe path> regular files. Reject directories, symlinks, devices,
 *      encrypted entries, duplicate names and oversized files.
 *   2. Hash every accepted file (streaming, size-limited).
 *   3. Build the digest text (see urados_pkg.h) and check SIGNATURE against
 *      the trusted keys.
 *   4. Only then parse manifest.xml and check that its <entry> is a signed
 *      payload file.
 *
 * Extraction reads the archive again and re-hashes every file while writing
 * it. A mismatch aborts. Output is created with O_EXCL and O_NOFOLLOW relative
 * to a directory fd, so no symlink can redirect a write.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <zip.h>

#include "urados_pkg.h"

#define IO_CHUNK 65536

static zip_t *open_zip(const char *path, char *err, size_t errlen)
{
    int ec = 0;
    zip_t *z = zip_open(path, ZIP_RDONLY, &ec);

    if (!z) {
        zip_error_t e;

        zip_error_init_with_code(&e, ec);
        pkg_seterr(err, errlen, "cannot open package %s: %s", path, zip_error_strerror(&e));
        zip_error_fini(&e);
    }
    return z;
}

/* Rejects entries that are not plain, unencrypted regular files. */
static int check_entry_kind(zip_t *z, zip_uint64_t idx, const char *name,
                            char *err, size_t errlen)
{
    zip_uint8_t opsys = 0;
    zip_uint32_t attr = 0;
    zip_stat_t st;

    if (name[0] == '\0' || name[strlen(name) - 1] == '/') {
        pkg_seterr(err, errlen, "directory entry '%s' is not allowed", name);
        return -1;
    }
    zip_stat_init(&st);
    if (zip_stat_index(z, idx, 0, &st) != 0 || !(st.valid & ZIP_STAT_NAME)) {
        pkg_seterr(err, errlen, "cannot read zip entry %llu", (unsigned long long)idx);
        return -1;
    }
    if ((st.valid & ZIP_STAT_ENCRYPTION_METHOD) && st.encryption_method != ZIP_EM_NONE) {
        pkg_seterr(err, errlen, "encrypted entry '%s' is not allowed", name);
        return -1;
    }
    if (zip_file_get_external_attributes(z, idx, 0, &opsys, &attr) == 0 &&
        opsys == ZIP_OPSYS_UNIX && attr != 0) {
        mode_t mode = (mode_t)((attr >> 16) & 0xFFFF);
        if (mode != 0 && !S_ISREG(mode)) {
            pkg_seterr(err, errlen, "entry '%s' is not a regular file", name);
            return -1;
        }
    }
    return 0;
}

static int name_allowed(const char *name)
{
    if (strcmp(name, PKG_MANIFEST_FILE) == 0 || strcmp(name, PKG_SIGNATURE_FILE) == 0)
        return 1;
    if (strncmp(name, PKG_ZIP_APP_PREFIX, strlen(PKG_ZIP_APP_PREFIX)) != 0)
        return 0;
    return pkg_path_safe(name);
}

/*
 * Reads one entry, hashing it. If keep is non-NULL the contents are also
 * returned (NUL-terminated). Fails if the entry exceeds max bytes.
 */
static int read_entry(zip_t *z, zip_uint64_t idx, const char *name, size_t max,
                      unsigned char **keep, size_t *keeplen, char hex[65],
                      char *err, size_t errlen)
{
    zip_file_t *f;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *buf = NULL, *kbuf = NULL;
    size_t total = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int rc = -1;

    f = zip_fopen_index(z, idx, 0);
    if (!f) {
        pkg_seterr(err, errlen, "cannot open '%s' in package", name);
        return -1;
    }
    buf = malloc(IO_CHUNK);
    ctx = EVP_MD_CTX_new();
    if (!buf || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (keep) {
        kbuf = malloc(max + 1);
        if (!kbuf) {
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
    }
    for (;;) {
        zip_int64_t n = zip_fread(f, buf, IO_CHUNK);

        if (n < 0) {
            pkg_seterr(err, errlen, "corrupt data in '%s'", name);
            goto out;
        }
        if (n == 0)
            break;
        if (total + (size_t)n > max) {
            pkg_seterr(err, errlen, "'%s' is larger than the allowed %zu bytes", name, max);
            goto out;
        }
        EVP_DigestUpdate(ctx, buf, (size_t)n);
        if (kbuf)
            memcpy(kbuf + total, buf, (size_t)n);
        total += (size_t)n;
    }
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) != 1) {
        pkg_seterr(err, errlen, "hash failure");
        goto out;
    }
    pkg_hex_encode(md, mdlen, hex);
    if (keep) {
        kbuf[total] = '\0';
        *keep = kbuf;
        *keeplen = total;
        kbuf = NULL;
    }
    rc = 0;
out:
    free(kbuf);
    free(buf);
    EVP_MD_CTX_free(ctx);
    zip_fclose(f);
    return rc;
}

static int digest_cmp_q(const void *a, const void *b)
{
    return pkg_digest_cmp(a, b);
}

void pkg_verified_free(pkg_verified *v)
{
    size_t i;

    if (!v)
        return;
    for (i = 0; i < v->ndigests; i++)
        free(v->digests[i].name);
    free(v->digests);
    memset(v, 0, sizeof(*v));
}

int pkg_verify_keys(const char *zip_path, EVP_PKEY **keys, size_t nkeys,
                    pkg_verified *v, char *err, size_t errlen)
{
    zip_t *z;
    zip_int64_t count;
    zip_uint64_t i;
    pkg_digest *digs = NULL;
    size_t nd = 0, cap = 0, k;
    unsigned char *sig = NULL, *mbuf = NULL, *dtext = NULL;
    size_t siglen = 0, mlen = 0, dlen = 0;
    int have_sig = 0, have_manifest = 0, rc = -1;
    char entry_zip[PKG_PATH_MAX];

    memset(v, 0, sizeof(*v));
    z = open_zip(zip_path, err, errlen);
    if (!z)
        return -1;

    count = zip_get_num_entries(z, 0);
    if (count <= 0 || count > PKG_FILES_MAX + 2) {
        pkg_seterr(err, errlen, "package has no entries or too many entries");
        goto out;
    }

    for (i = 0; i < (zip_uint64_t)count; i++) {
        const char *name = zip_get_name(z, i, 0);
        char hex[65];

        if (!name) {
            pkg_seterr(err, errlen, "unreadable entry name");
            goto out;
        }
        if (check_entry_kind(z, i, name, err, errlen) != 0)
            goto out;
        if (!name_allowed(name)) {
            pkg_seterr(err, errlen, "entry '%s' is not allowed in a package", name);
            goto out;
        }
        if (strcmp(name, PKG_SIGNATURE_FILE) == 0) {
            if (have_sig) {
                pkg_seterr(err, errlen, "duplicate %s", PKG_SIGNATURE_FILE);
                goto out;
            }
            if (read_entry(z, i, name, PKG_META_MAX, &sig, &siglen, hex, err, errlen))
                goto out;
            have_sig = 1;
            continue; /* SIGNATURE is not part of the digest text */
        }
        if (strcmp(name, PKG_MANIFEST_FILE) == 0) {
            if (have_manifest) {
                pkg_seterr(err, errlen, "duplicate %s", PKG_MANIFEST_FILE);
                goto out;
            }
            if (read_entry(z, i, name, PKG_META_MAX, &mbuf, &mlen, hex, err, errlen))
                goto out;
            have_manifest = 1;
        } else if (read_entry(z, i, name, PKG_FILE_MAX, NULL, NULL, hex, err, errlen)) {
            goto out;
        }

        if (nd == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            pkg_digest *nb = realloc(digs, ncap * sizeof(*nb));
            if (!nb) {
                pkg_seterr(err, errlen, "out of memory");
                goto out;
            }
            digs = nb;
            cap = ncap;
        }
        digs[nd].name = strdup(name);
        if (!digs[nd].name) {
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
        memcpy(digs[nd].hex, hex, 65);
        nd++;
    }

    if (!have_sig || !have_manifest) {
        pkg_seterr(err, errlen, "package must contain %s and %s",
                   PKG_MANIFEST_FILE, PKG_SIGNATURE_FILE);
        goto out;
    }
    if (nd < 2) {
        pkg_seterr(err, errlen, "package has no payload");
        goto out;
    }

    qsort(digs, nd, sizeof(*digs), digest_cmp_q);
    for (k = 1; k < nd; k++) {
        if (strcmp(digs[k - 1].name, digs[k].name) == 0) {
            pkg_seterr(err, errlen, "duplicate entry '%s'", digs[k].name);
            goto out;
        }
    }
    if (pkg_digest_text(digs, nd, &dtext, &dlen) != 0) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (!keys || nkeys == 0 ||
        pkg_check_signature(keys, nkeys, dtext, dlen, sig, siglen) != 0) {
        pkg_seterr(err, errlen, "signature verification failed (untrusted or modified package)");
        goto out;
    }

    /* The signature is good, so the manifest is authentic and can be parsed. */
    if (pkg_manifest_parse(mbuf, mlen, &v->manifest, err, errlen) != 0)
        goto out;
    if (pkg_entry_zipname(v->manifest.entry, entry_zip, sizeof(entry_zip)) != 0) {
        pkg_seterr(err, errlen, "manifest entry is invalid");
        goto out;
    }
    {
        pkg_digest key;

        key.name = entry_zip;
        if (!bsearch(&key, digs, nd, sizeof(*digs), digest_cmp_q)) {
            pkg_seterr(err, errlen, "manifest entry '%s' is not in the package", v->manifest.entry);
            goto out;
        }
    }

    v->digests = digs;
    v->ndigests = nd;
    digs = NULL;
    nd = 0;
    rc = 0;
out:
    if (digs) {
        for (k = 0; k < nd; k++)
            free(digs[k].name);
        free(digs);
    }
    free(sig);
    free(mbuf);
    free(dtext);
    zip_close(z);
    return rc;
}

int pkg_verify(const char *zip_path, const char *keys_dir, pkg_verified *v,
               char *err, size_t errlen)
{
    EVP_PKEY **keys = NULL;
    size_t nkeys = 0;
    int rc;

    if (pkg_load_trusted_keys(keys_dir, &keys, &nkeys, err, errlen) != 0)
        return -1;
    rc = pkg_verify_keys(zip_path, keys, nkeys, v, err, errlen);
    pkg_free_keys(keys, nkeys);
    return rc;
}

/*
 * Extracts every app/ payload into appfd (the empty system_cache/app dir).
 * Directories and non-entry files are root:gid 0110 (traverse and execute
 * only). The entry point is root:gid 0550 so scripts can be read and run.
 * Every byte is re-hashed against the signed digest as it is written.
 */
int pkg_extract(const char *zip_path, int appfd, gid_t gid, const pkg_verified *v,
                char *err, size_t errlen)
{
    zip_t *z;
    zip_int64_t count;
    size_t i;
    char entry_zip[PKG_PATH_MAX];
    int rc = -1;

    if (pkg_entry_zipname(v->manifest.entry, entry_zip, sizeof(entry_zip)) != 0) {
        pkg_seterr(err, errlen, "manifest entry is invalid");
        return -1;
    }
    z = open_zip(zip_path, err, errlen);
    if (!z)
        return -1;
    count = zip_get_num_entries(z, 0);

    for (i = 0; i < v->ndigests; i++) {
        const pkg_digest *d = &v->digests[i];
        char *copy, *save = NULL, *tok, *next;
        const char *rel;
        int cur, ffd, zi = -1;
        zip_uint64_t j;
        zip_file_t *f;
        EVP_MD_CTX *ctx;
        unsigned char md[EVP_MAX_MD_SIZE], buf[IO_CHUNK];
        unsigned int mdlen = 0;
        char hex[65];
        int ok = 0;
        mode_t fmode;

        if (strncmp(d->name, PKG_ZIP_APP_PREFIX, strlen(PKG_ZIP_APP_PREFIX)) != 0)
            continue; /* manifest.xml and SIGNATURE are not installed */
        rel = d->name + strlen(PKG_ZIP_APP_PREFIX);

        for (j = 0; j < (zip_uint64_t)count; j++) {
            const char *n = zip_get_name(z, j, 0);
            if (n && strcmp(n, d->name) == 0) {
                zi = (int)j;
                break;
            }
        }
        if (zi < 0) {
            pkg_seterr(err, errlen, "'%s' vanished from the package", d->name);
            goto out;
        }

        copy = strdup(rel);
        if (!copy) {
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
        cur = dup(appfd);
        tok = strtok_r(copy, "/", &save);
        while (tok) {
            next = strtok_r(NULL, "/", &save);
            if (!next)
                break; /* tok is the final file name */
            {
                int nfd = pkg_open_subdir(cur, tok, 0110, 0, gid);

                close(cur);
                if (nfd < 0) {
                    pkg_seterr(err, errlen, "cannot create directory '%s': %s", tok, strerror(errno));
                    free(copy);
                    goto out;
                }
                cur = nfd;
            }
            tok = next;
        }
        /* The entry point is readable and executable so that scripts can run.
     * Every other file and every directory is execute-only (0110). */
    fmode = (strcmp(d->name, entry_zip) == 0) ? 0550 : 0110;

        ffd = openat(cur, tok, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        close(cur);
        if (ffd < 0) {
            pkg_seterr(err, errlen, "cannot create '%s': %s", d->name, strerror(errno));
            free(copy);
            goto out;
        }
        free(copy);

        ctx = EVP_MD_CTX_new();
        if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
            pkg_seterr(err, errlen, "out of memory");
            if (ctx)
                EVP_MD_CTX_free(ctx);
            close(ffd);
            goto out;
        }
        f = zip_fopen_index(z, (zip_uint64_t)zi, 0);
        if (f) {
            for (;;) {
                zip_int64_t n = zip_fread(f, buf, sizeof(buf));

                if (n < 0)
                    break;
                if (n == 0) {
                    ok = 1;
                    break;
                }
                EVP_DigestUpdate(ctx, buf, (size_t)n);
                if (pkg_write_all(ffd, buf, (size_t)n) != 0)
                    break;
            }
            zip_fclose(f);
        }
        EVP_DigestFinal_ex(ctx, md, &mdlen);
        EVP_MD_CTX_free(ctx);
        pkg_hex_encode(md, mdlen, hex);
        if (!ok || strcmp(hex, d->hex) != 0) {
            pkg_seterr(err, errlen, "'%s' does not match its signed digest", d->name);
            close(ffd);
            goto out;
        }
        if (fchown(ffd, 0, gid) != 0 || fchmod(ffd, fmode) != 0 || fsync(ffd) != 0) {
            pkg_seterr(err, errlen, "cannot set attributes on '%s': %s", d->name, strerror(errno));
            close(ffd);
            goto out;
        }
        close(ffd);
    }
    rc = 0;
out:
    zip_close(z);
    return rc;
}
