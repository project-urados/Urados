/*
 * archive.c - verify and extract package archives (libzip + OpenSSL).
 *
 * Verification never trusts anything before the signature is checked:
 *   1. Walk every zip entry. Accept only manifest.xml, SIGNER_CERTS.pem,
 *      META-INF/{MANIFEST.MF,CERT.SF,CERT.SIG} and app/<safe path> regular
 *      files. Reject directories, symlinks, devices, encrypted entries,
 *      duplicate names and oversized files.
 *   2. Hash every file outside META-INF/ (streaming, size-limited).
 *   3. Check CERT.SIG over CERT.SF against the signer chain to
 *      administrator-installed root certificates.
 *   4. Check CERT.SF against MANIFEST.MF and each MANIFEST.MF section, then
 *      MANIFEST.MF against the SHA-256 of every file (see meta_files.c).
 *   5. Only then parse manifest.xml and check that its <entry> is a signed
 *      payload file.
 *
 * Extraction reads the archive again and re-hashes every file while writing
 * it. A mismatch aborts. Output is created with O_EXCL and O_NOFOLLOW relative
 * to a directory fd, so no symlink can redirect a write.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
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
    static const char fd_prefix[] = "/proc/self/fd/";
    int ec = 0;
    struct stat st;
    zip_t *z;
    int stat_rc;

    if (strncmp(path, fd_prefix, sizeof(fd_prefix) - 1) == 0) {
        char *end = NULL;
        long fdno;
        const char *num = path + sizeof(fd_prefix) - 1;

        errno = 0;
        fdno = strtol(num, &end, 10);
        stat_rc = (errno == 0 && end != num && *end == '\0' && fdno >= 0 && fdno <= INT_MAX)
                      ? fstat((int)fdno, &st) : -1;
    } else {
        stat_rc = lstat(path, &st);
    }
    if (stat_rc != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > PKG_ARCHIVE_MAX) {
        pkg_seterr(err, errlen, "package %s is not a regular file or exceeds the %u-byte archive limit",
                   path, PKG_ARCHIVE_MAX);
        return NULL;
    }
    z = zip_open(path, ZIP_RDONLY, &ec);

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
    if (strcmp(name, PKG_MANIFEST_FILE) == 0 || strcmp(name, PKG_SIGNER_CERTS_FILE) == 0 ||
        strcmp(name, PKG_MF_FILE) == 0 || strcmp(name, PKG_SF_FILE) == 0 ||
        strcmp(name, PKG_SIG_FILE) == 0)
        return 1;
    if (strncmp(name, PKG_ZIP_APP_PREFIX, strlen(PKG_ZIP_APP_PREFIX)) != 0)
        return 0;
    return pkg_path_safe(name);
}

/*
 * Reads one entry, hashing it. If keep is non-NULL the contents are also
 * returned (NUL-terminated). Enforces both the per-entry and aggregate limits.
 */
static int read_entry(zip_t *z, zip_uint64_t idx, const char *name, size_t max,
                      unsigned char **keep, size_t *keeplen, char hex[65],
                      uint64_t *aggregate, char *err, size_t errlen)
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
        if (!aggregate || *aggregate > PKG_UNPACKED_MAX - (uint64_t)n) {
            pkg_seterr(err, errlen, "package exceeds the %llu-byte uncompressed data limit",
                       (unsigned long long)PKG_UNPACKED_MAX);
            goto out;
        }
        EVP_DigestUpdate(ctx, buf, (size_t)n);
        if (kbuf)
            memcpy(kbuf + total, buf, (size_t)n);
        total += (size_t)n;
        *aggregate += (uint64_t)n;
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

/* Reads a META-INF/ or manifest/chain entry that may appear only once. */
static int read_meta_once(zip_t *z, zip_uint64_t idx, const char *name, size_t max,
                          unsigned char **buf, size_t *len, int *seen, char hex[65],
                          uint64_t *unpacked, char *err, size_t errlen)
{
    if (*seen) {
        pkg_seterr(err, errlen, "duplicate %s", name);
        return -1;
    }
    if (read_entry(z, idx, name, max, buf, len, hex, unpacked, err, errlen) != 0)
        return -1;
    *seen = 1;
    return 0;
}

/*
 * Verifies an APK/JAR-style package: CERT.SIG over CERT.SF (signer chain to an
 * installed root), CERT.SF over MANIFEST.MF and each of its sections, and
 * MANIFEST.MF over the SHA-256 of every file outside META-INF/.
 */
static int verify_certificate_package(const char *zip_path, const char *roots_dir,
                                      pkg_verified *v, char *err, size_t errlen)
{
    zip_t *z;
    zip_int64_t count;
    zip_uint64_t i;
    pkg_digest *digs = NULL;
    size_t nd = 0, cap = 0, k;
    unsigned char *mf = NULL, *sf = NULL, *sig = NULL, *mbuf = NULL, *cert_chain = NULL;
    size_t mflen = 0, sflen = 0, siglen = 0, mlen = 0, cert_chain_len = 0;
    uint64_t unpacked = 0;
    int have_mf = 0, have_sf = 0, have_sig = 0, have_manifest = 0, have_cert_chain = 0;
    int rc = -1;
    char entry_zip[PKG_PATH_MAX];

    memset(v, 0, sizeof(*v));
    z = open_zip(zip_path, err, errlen);
    if (!z)
        return -1;

    count = zip_get_num_entries(z, 0);
    if (count <= 0 || count > PKG_FILES_MAX + 5) {
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

        /* META-INF/ files are metadata and are not in the digest list. */
        if (strcmp(name, PKG_MF_FILE) == 0) {
            if (read_meta_once(z, i, name, PKG_MF_MAX, &mf, &mflen, &have_mf, hex,
                               &unpacked, err, errlen))
                goto out;
            continue;
        }
        if (strcmp(name, PKG_SF_FILE) == 0) {
            if (read_meta_once(z, i, name, PKG_MF_MAX, &sf, &sflen, &have_sf, hex,
                               &unpacked, err, errlen))
                goto out;
            continue;
        }
        if (strcmp(name, PKG_SIG_FILE) == 0) {
            if (read_meta_once(z, i, name, PKG_META_MAX, &sig, &siglen, &have_sig, hex,
                               &unpacked, err, errlen))
                goto out;
            continue;
        }

        if (strcmp(name, PKG_MANIFEST_FILE) == 0) {
            if (read_meta_once(z, i, name, PKG_META_MAX, &mbuf, &mlen, &have_manifest, hex,
                               &unpacked, err, errlen))
                goto out;
        } else if (strcmp(name, PKG_SIGNER_CERTS_FILE) == 0) {
            if (read_meta_once(z, i, name, PKG_META_MAX, &cert_chain, &cert_chain_len,
                               &have_cert_chain, hex, &unpacked, err, errlen))
                goto out;
        } else if (read_entry(z, i, name, PKG_FILE_MAX, NULL, NULL, hex, &unpacked, err, errlen)) {
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

    if (!have_mf || !have_sf || !have_sig || !have_manifest || !have_cert_chain) {
        pkg_seterr(err, errlen, "package must contain %s, %s, %s, %s and %s",
                   PKG_MF_FILE, PKG_SF_FILE, PKG_SIG_FILE, PKG_MANIFEST_FILE,
                   PKG_SIGNER_CERTS_FILE);
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
    if (!roots_dir || pkg_verify_certificate_signature(cert_chain, cert_chain_len,
            roots_dir, sf, sflen, sig, siglen, err, errlen) != 0)
        goto out;
    if (pkg_meta_verify(mf, mflen, sf, sflen, digs, nd, err, errlen) != 0)
        goto out;

    /* Every file is authenticated now, so the manifest can be parsed. */
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
    free(mf);
    free(sf);
    free(sig);
    free(mbuf);
    free(cert_chain);
    zip_close(z);
    return rc;
}

int pkg_verify(const char *zip_path, const char *keys_dir, pkg_verified *v,
               char *err, size_t errlen)
{
    return verify_certificate_package(zip_path, keys_dir, v, err, errlen);
}

/*
 * Extracts every app/ payload into the writable system_cache/app code tree.
 * Root owns installed files; inherited POSIX ACLs grant read/write/execute only
 * to the owning app UID while the global users group has no access. Every byte
 * is re-hashed against the signed digest as it is written.
 */
int pkg_extract(const char *zip_path, int appfd, gid_t gid, const pkg_verified *v,
                char *err, size_t errlen)
{
    zip_t *z;
    zip_int64_t count;
    size_t i;
    uint64_t unpacked = 0;
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
        size_t file_total = 0;
        char hex[65];
        int ok = 0, size_limit = 0;
        mode_t fmode;

        if (strncmp(d->name, PKG_ZIP_APP_PREFIX, strlen(PKG_ZIP_APP_PREFIX)) != 0)
            continue; /* manifest.xml and SIGNER_CERTS.pem are not installed */
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
                int nfd = pkg_open_subdir(cur, tok, 02770, 0, gid);

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
        /* Code is mutable and executable by this app only; SELinux separately
         * forbids execution from the ordinary data tree. */
        fmode = 0770;

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
                if (file_total > PKG_FILE_MAX - (size_t)n ||
                    unpacked > PKG_UNPACKED_MAX - (uint64_t)n) {
                    pkg_seterr(err, errlen, "extracted package data exceeds the configured size limit");
                    size_limit = 1;
                    break;
                }
                EVP_DigestUpdate(ctx, buf, (size_t)n);
                if (pkg_write_all(ffd, buf, (size_t)n) != 0)
                    break;
                file_total += (size_t)n;
                unpacked += (uint64_t)n;
            }
            zip_fclose(f);
        }
        EVP_DigestFinal_ex(ctx, md, &mdlen);
        EVP_MD_CTX_free(ctx);
        pkg_hex_encode(md, mdlen, hex);
        if (!ok || strcmp(hex, d->hex) != 0) {
            if (!size_limit)
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
