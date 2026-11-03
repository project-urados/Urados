/*
 * pack.c - urdev: project scaffolding, checks and packaging.
 *
 * Project layout (the developer's source tree):
 *   <dir>/manifest.xml   package manifest (schema in manifest.c)
 *   <dir>/app/...        payload, installed as system_cache/app/...
 *
 * pack hashes every file, signs the digest text with the publisher key, and
 * writes manifest.xml, SIGNATURE, optional SIGNER_CERTS.pem and app/... into a zip archive. Symlinks and
 * special files are rejected, so the archive only contains what is listed.
 */
#include <dirent.h>
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

#define PACK_DEPTH_MAX 16

typedef struct {
    char *name;            /* zip name, owned */
    unsigned char *data;   /* file contents, owned */
    size_t len;
    char hex[65];
} pkg_file;

typedef struct {
    pkg_file *items;
    size_t n, cap;
} file_list;

static void list_free(file_list *l)
{
    size_t i;

    for (i = 0; i < l->n; i++) {
        free(l->items[i].name);
        free(l->items[i].data);
    }
    free(l->items);
    memset(l, 0, sizeof(*l));
}

/* Reads a regular file into the list and records its digest. */
static int list_add(file_list *l, const char *zipname, const char *path, char *err, size_t errlen)
{
    pkg_file *f;
    unsigned char *data = NULL;
    size_t len = 0;
    char *name;

    if (l->n >= PKG_FILES_MAX) {
        pkg_seterr(err, errlen, "too many files (max %d)", PKG_FILES_MAX);
        return -1;
    }
    if (pkg_read_file(path, PKG_FILE_MAX, &data, &len) != 0) {
        pkg_seterr(err, errlen, "cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    name = strdup(zipname);
    if (!name) {
        free(data);
        pkg_seterr(err, errlen, "out of memory");
        return -1;
    }
    if (l->n == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 16;
        pkg_file *ni = realloc(l->items, ncap * sizeof(*ni));

        if (!ni) {
            free(name);
            free(data);
            pkg_seterr(err, errlen, "out of memory");
            return -1;
        }
        l->items = ni;
        l->cap = ncap;
    }
    f = &l->items[l->n++];
    f->name = name;
    f->data = data;
    f->len = len;
    pkg_sha256(data, len, f->hex);
    return 0;
}

/* Adds every regular file under dir, recursively, with zip names under zprefix. */
static int walk(const char *dir, const char *zprefix, file_list *l, int depth,
                char *err, size_t errlen)
{
    DIR *d;
    struct dirent *e;
    int rc = -1;

    if (depth > PACK_DEPTH_MAX) {
        pkg_seterr(err, errlen, "directory tree is too deep at %s", dir);
        return -1;
    }
    d = opendir(dir);
    if (!d) {
        pkg_seterr(err, errlen, "cannot open %s: %s", dir, strerror(errno));
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        char path[PKG_PATH_MAX], zn[PKG_PATH_MAX], sub[PKG_PATH_MAX];
        struct stat st;
        int pl, zl;

        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        pl = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        zl = snprintf(zn, sizeof(zn), "%s%s", zprefix, e->d_name);
        if (pl < 0 || (size_t)pl >= sizeof(path) || zl < 0 || (size_t)zl >= sizeof(zn)) {
            pkg_seterr(err, errlen, "path too long under %s", dir);
            goto out;
        }
        if (lstat(path, &st) != 0) {
            pkg_seterr(err, errlen, "cannot stat %s: %s", path, strerror(errno));
            goto out;
        }
        if (S_ISLNK(st.st_mode)) {
            pkg_seterr(err, errlen, "symbolic links are not allowed: %s", path);
            goto out;
        }
        if (S_ISDIR(st.st_mode)) {
            if (snprintf(sub, sizeof(sub), "%s/", zn) >= (int)sizeof(sub)) {
                pkg_seterr(err, errlen, "path too long under %s", dir);
                goto out;
            }
            if (walk(path, sub, l, depth + 1, err, errlen) != 0)
                goto out;
        } else if (S_ISREG(st.st_mode)) {
            if (!pkg_path_safe(zn)) {
                pkg_seterr(err, errlen, "file name is not allowed: %s", path);
                goto out;
            }
            if (list_add(l, zn, path, err, errlen) != 0)
                goto out;
        } else {
            pkg_seterr(err, errlen, "unsupported file type: %s", path);
            goto out;
        }
    }
    rc = 0;
out:
    closedir(d);
    return rc;
}

static int cmp_items(const void *a, const void *b)
{
    return strcmp(((const pkg_file *)a)->name, ((const pkg_file *)b)->name);
}

/*
 * Checks that <dir>/manifest.xml parses and that its entry names a regular
 * file under <dir>/app/.
 */
int pkg_check_project(const char *dir, pkg_manifest *m, char *err, size_t errlen)
{
    char path[PKG_PATH_MAX];
    unsigned char *buf = NULL;
    size_t len = 0;
    struct stat st;
    int rc = -1;

    snprintf(path, sizeof(path), "%s/%s", dir, PKG_MANIFEST_FILE);
    if (pkg_read_file(path, PKG_META_MAX, &buf, &len) != 0) {
        pkg_seterr(err, errlen, "cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    if (pkg_manifest_parse(buf, len, m, err, errlen) != 0)
        goto out;
    snprintf(path, sizeof(path), "%s/app/%s", dir,
             m->entry + strlen(PKG_ENTRY_PREFIX));
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        pkg_seterr(err, errlen, "entry file %s is missing", path);
        goto out;
    }
    rc = 0;
out:
    free(buf);
    return rc;
}

/* Creates a project skeleton. The directory must not exist yet. */
int pkg_init_project(const char *dir, const char *name, const char *version,
                     char *err, size_t errlen)
{
    char path[PKG_PATH_MAX];
    FILE *fp;
    int fd;

    if (!pkg_name_valid(name)) {
        pkg_seterr(err, errlen, "invalid package name '%s'", name);
        return -1;
    }
    if (!pkg_version_valid(version)) {
        pkg_seterr(err, errlen, "invalid version '%s'", version);
        return -1;
    }
    if (mkdir(dir, 0755) != 0) {
        pkg_seterr(err, errlen, "cannot create %s: %s", dir, strerror(errno));
        return -1;
    }
    snprintf(path, sizeof(path), "%s/app", dir);
    if (mkdir(path, 0755) != 0) {
        pkg_seterr(err, errlen, "cannot create %s: %s", path, strerror(errno));
        return -1;
    }

    snprintf(path, sizeof(path), "%s/%s", dir, PKG_MANIFEST_FILE);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        pkg_seterr(err, errlen, "cannot create %s: %s", path, strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        pkg_seterr(err, errlen, "cannot write %s", path);
        return -1;
    }
    fprintf(fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<package>\n"
            "  <name>%s</name>\n"
            "  <version>%s</version>\n"
            "  <entry>%s%s</entry>\n"
            "  <label>%s</label>\n"
            "  <description>Describe what the app does.</description>\n"
            "  <author>Your name</author>\n"
            "</package>\n",
            name, version, PKG_ENTRY_PREFIX, name, name);
    if (fclose(fp) != 0) {
        pkg_seterr(err, errlen, "cannot write %s", path);
        return -1;
    }

    /* Placeholder entry point. Replace it with your program. */
    snprintf(path, sizeof(path), "%s/app/%s", dir, name);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
    if (fd < 0) {
        pkg_seterr(err, errlen, "cannot create %s: %s", path, strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return -1;
    }
    fprintf(fp, "#!/urados/bin/user/sh\necho \"hello from %s\"\n", name);
    return fclose(fp) == 0 ? 0 : -1;
}

int pkg_pack(const char *dir, const char *out_zip, EVP_PKEY *key,
             const char *cert_chain_path, char *err, size_t errlen)
{
    pkg_manifest m;
    file_list l = { NULL, 0, 0 };
    pkg_digest *digs = NULL;
    unsigned char *dtext = NULL, *sig = NULL, *cert_chain = NULL;
    size_t dlen = 0, siglen = 0, cert_chain_len = 0, ndigs, i;
    char path[PKG_PATH_MAX], tmp[PKG_PATH_MAX];
    zip_t *z = NULL;
    int ec = 0, rc = -1;

    if (pkg_check_project(dir, &m, err, errlen) != 0)
        return -1;
    if (!cert_chain_path) {
        pkg_seterr(err, errlen, "a publisher certificate chain is required (--cert CHAIN.pem)");
        goto out;
    }
    if (pkg_read_file(cert_chain_path, PKG_META_MAX, &cert_chain, &cert_chain_len) != 0) {
        pkg_seterr(err, errlen, "cannot read signer certificate chain %s: %s",
                   cert_chain_path, strerror(errno));
        goto out;
    }
    if (pkg_validate_signer_certificate(cert_chain, cert_chain_len, key, err, errlen) != 0)
        goto out;

    snprintf(path, sizeof(path), "%s/%s", dir, PKG_MANIFEST_FILE);
    if (list_add(&l, PKG_MANIFEST_FILE, path, err, errlen) != 0)
        goto out;
    snprintf(path, sizeof(path), "%s/app", dir);
    if (walk(path, PKG_ZIP_APP_PREFIX, &l, 0, err, errlen) != 0)
        goto out;

    qsort(l.items, l.n, sizeof(*l.items), cmp_items);
    ndigs = l.n + 1;
    digs = malloc((ndigs ? ndigs : 1) * sizeof(*digs));
    if (!digs) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    for (i = 0; i < l.n; i++) {
        digs[i].name = l.items[i].name;   /* borrowed; freed with the list */
        memcpy(digs[i].hex, l.items[i].hex, sizeof(digs[i].hex));
    }
    if (cert_chain) {
        digs[l.n].name = (char *)PKG_SIGNER_CERTS_FILE; /* static name */
        pkg_sha256(cert_chain, cert_chain_len, digs[l.n].hex);
    }
    qsort(digs, ndigs, sizeof(*digs), pkg_digest_cmp);
    if (pkg_digest_text(digs, ndigs, &dtext, &dlen) != 0) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (pkg_sign_data(key, dtext, dlen, &sig, &siglen) != 0) {
        pkg_seterr(err, errlen, "signing failed");
        goto out;
    }

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", out_zip) >= (int)sizeof(tmp)) {
        pkg_seterr(err, errlen, "output path too long");
        goto out;
    }
    unlink(tmp);
    z = zip_open(tmp, ZIP_CREATE | ZIP_TRUNCATE, &ec);
    if (!z) {
        pkg_seterr(err, errlen, "cannot create %s", tmp);
        goto out;
    }
    for (i = 0; i < l.n; i++) {
        zip_source_t *src = zip_source_buffer(z, l.items[i].data, l.items[i].len, 0);
        zip_int64_t idx;

        if (!src)
            goto zerr;
        idx = zip_file_add(z, l.items[i].name, src, ZIP_FL_ENC_UTF_8);
        if (idx < 0) {
            zip_source_free(src);
            goto zerr;
        }
        if (zip_file_set_external_attributes(z, (zip_uint64_t)idx, 0, ZIP_OPSYS_UNIX,
                                             (zip_uint32_t)(0100644u << 16)) != 0)
            goto zerr;
    }
    {
        zip_source_t *src = zip_source_buffer(z, sig, siglen, 0);
        zip_int64_t idx;

        if (!src)
            goto zerr;
        idx = zip_file_add(z, PKG_SIGNATURE_FILE, src, ZIP_FL_ENC_UTF_8);
        if (idx < 0) {
            zip_source_free(src);
            goto zerr;
        }
        if (zip_file_set_external_attributes(z, (zip_uint64_t)idx, 0, ZIP_OPSYS_UNIX,
                                             (zip_uint32_t)(0100644u << 16)) != 0)
            goto zerr;
    }
    if (cert_chain) {
        zip_source_t *src = zip_source_buffer(z, cert_chain, cert_chain_len, 0);
        zip_int64_t idx;

        if (!src)
            goto zerr;
        idx = zip_file_add(z, PKG_SIGNER_CERTS_FILE, src, ZIP_FL_ENC_UTF_8);
        if (idx < 0) {
            zip_source_free(src);
            goto zerr;
        }
        if (zip_file_set_external_attributes(z, (zip_uint64_t)idx, 0, ZIP_OPSYS_UNIX,
                                             (zip_uint32_t)(0100644u << 16)) != 0)
            goto zerr;
    }
    if (zip_close(z) != 0) {
        zip_discard(z);
        z = NULL;
        pkg_seterr(err, errlen, "cannot write %s", tmp);
        unlink(tmp);
        goto out;
    }
    z = NULL;
    if (rename(tmp, out_zip) != 0) {
        pkg_seterr(err, errlen, "cannot move the package to %s: %s", out_zip, strerror(errno));
        unlink(tmp);
        goto out;
    }
    rc = 0;
    goto out;

zerr:
    pkg_seterr(err, errlen, "cannot build the archive: %s", zip_strerror(z));
    zip_discard(z);
    z = NULL;
    unlink(tmp);

out:
    if (z)
        zip_discard(z);
    free(digs);
    free(dtext);
    free(sig);
    free(cert_chain);
    list_free(&l);
    return rc;
}
