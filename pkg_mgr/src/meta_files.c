/*
 * meta_files.c - APK/JAR-style signed metadata for Urados packages (SHA-256).
 *
 *   META-INF/MANIFEST.MF  main section, then one section per signed file:
 *                           Name: <zip name>
 *                           SHA-256-Digest: <base64 SHA-256 of the file>
 *   META-INF/CERT.SF      main section:
 *                           Signature-Version: 1.0
 *                           Created-By: ...            (optional)
 *                           SHA-256-Digest-Manifest: <base64 SHA-256 of MANIFEST.MF>
 *                         then one section per MANIFEST.MF section:
 *                           Name: <zip name>
 *                           SHA-256-Digest: <base64 SHA-256 of that MANIFEST.MF section>
 *   META-INF/CERT.SIG     signature over the bytes of CERT.SF, made with the
 *                         publisher key and checked against the signer chain.
 *
 * Only SHA-256 is accepted. Digests are canonical base64, so the verifier can
 * compare the digest text exactly. Each section ends with a blank line, and its
 * digest covers the exact bytes of the section including that blank line.
 * Headers longer than 72 bytes continue on lines that start with one space, as
 * in JAR manifests. Unknown headers and extra sections are rejected.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "urados_pkg.h"

#define B64_LEN        44   /* base64 of a 32-byte SHA-256 digest */
#define LINE_BYTES     72   /* JAR line limit, excluding the newline */
#define MF_ATTRS_MAX   16   /* headers per section */

typedef struct {
    char *key;
    char *val;
} mf_attr;

typedef struct {
    size_t start, end;      /* byte range of the section, blank line included */
    mf_attr *attrs;
    size_t nattrs, cap;
} mf_section;

typedef struct {
    unsigned char *p;
    size_t len, cap;
} sbuf;

static void sb_free(sbuf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

static int sb_append(sbuf *b, const void *data, size_t n)
{
    unsigned char *np;
    size_t ncap;

    if (n == 0)
        return 0;
    if (n > SIZE_MAX - b->len)
        return -1;
    if (b->len + n > b->cap) {
        ncap = b->cap ? b->cap : 256;
        while (ncap < b->len + n) {
            if (ncap > SIZE_MAX / 2)
                return -1;
            ncap *= 2;
        }
        np = realloc(b->p, ncap);
        if (!np)
            return -1;
        b->p = np;
        b->cap = ncap;
    }
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return 0;
}

/* Appends "key: value" as one or more lines, each at most 72 bytes. */
static int sb_header(sbuf *b, const char *key, const char *value)
{
    size_t klen = strlen(key), vlen = strlen(value), total = klen + 2 + vlen;
    size_t off, take;
    char *line;
    int rc = 0;

    line = malloc(total + 1);
    if (!line)
        return -1;
    memcpy(line, key, klen);
    memcpy(line + klen, ": ", 2);
    memcpy(line + klen + 2, value, vlen);

    take = total < LINE_BYTES ? total : LINE_BYTES;
    rc = sb_append(b, line, take);
    off = take;
    while (rc == 0 && off < total) {
        take = total - off;
        if (take > LINE_BYTES - 1)
            take = LINE_BYTES - 1;
        if (sb_append(b, "\n ", 2) != 0 || sb_append(b, line + off, take) != 0)
            rc = -1;
        off += take;
    }
    if (rc == 0)
        rc = sb_append(b, "\n", 1);
    free(line);
    return rc;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Canonical base64 of a 32-byte digest. out receives B64_LEN characters + NUL. */
static int md_b64(const unsigned char *md, char out[B64_LEN + 1])
{
    int n = EVP_EncodeBlock((unsigned char *)out, md, 32);

    if (n != B64_LEN)
        return -1;
    out[B64_LEN] = '\0';
    return 0;
}

static int sha256_b64(const void *data, size_t len, char out[B64_LEN + 1])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    if (EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL) != 1 || mdlen != 32)
        return -1;
    return md_b64(md, out);
}

/* Converts a 64-character lowercase or uppercase hex SHA-256 to canonical base64. */
static int hex_b64(const char *hex, char out[B64_LEN + 1])
{
    unsigned char md[32];
    size_t i;

    if (strlen(hex) != 64)
        return -1;
    for (i = 0; i < 32; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);

        if (hi < 0 || lo < 0)
            return -1;
        md[i] = (unsigned char)((hi << 4) | lo);
    }
    return md_b64(md, out);
}

/* One "Name: ..." + "SHA-256-Digest: ..." section followed by a blank line. */
static int entry_section(sbuf *s, const char *name, const char *digest)
{
    if (sb_header(s, "Name", name) != 0 || sb_header(s, "SHA-256-Digest", digest) != 0 ||
        sb_append(s, "\n", 1) != 0)
        return -1;
    return 0;
}

/* Builds MANIFEST.MF and CERT.SF. d must be sorted by name. */
int pkg_meta_build(const pkg_digest *d, size_t n, unsigned char **mfout, size_t *mflen,
                   unsigned char **sfout, size_t *sflen, char *err, size_t errlen)
{
    sbuf mf = { NULL, 0, 0 }, sf = { NULL, 0, 0 };
    char (*secdig)[B64_LEN + 1] = NULL;
    char b64[B64_LEN + 1];
    size_t i;
    int rc = -1;

    secdig = malloc((n ? n : 1) * sizeof(*secdig));
    if (!secdig)
        goto oom;

    if (sb_header(&mf, "Manifest-Version", "1.0") != 0 ||
        sb_header(&mf, "Created-By", PKG_CREATED_BY) != 0 || sb_append(&mf, "\n", 1) != 0)
        goto oom;
    for (i = 0; i < n; i++) {
        sbuf sec = { NULL, 0, 0 };
        int ok;

        if (hex_b64(d[i].hex, b64) != 0) {
            pkg_seterr(err, errlen, "invalid digest for '%s'", d[i].name);
            goto out;
        }
        ok = entry_section(&sec, d[i].name, b64) == 0 &&
             sb_append(&mf, sec.p, sec.len) == 0 &&
             sha256_b64(sec.p, sec.len, secdig[i]) == 0;
        sb_free(&sec);
        if (!ok)
            goto oom;
    }
    if (mf.len > PKG_MF_MAX) {
        pkg_seterr(err, errlen, "MANIFEST.MF would exceed %u bytes (too many files)", PKG_MF_MAX);
        goto out;
    }

    if (sha256_b64(mf.p, mf.len, b64) != 0)
        goto oom;
    if (sb_header(&sf, "Signature-Version", "1.0") != 0 ||
        sb_header(&sf, "Created-By", PKG_CREATED_BY) != 0 ||
        sb_header(&sf, "SHA-256-Digest-Manifest", b64) != 0 || sb_append(&sf, "\n", 1) != 0)
        goto oom;
    for (i = 0; i < n; i++) {
        sbuf sec = { NULL, 0, 0 };
        int ok = entry_section(&sec, d[i].name, secdig[i]) == 0 &&
                 sb_append(&sf, sec.p, sec.len) == 0;

        sb_free(&sec);
        if (!ok)
            goto oom;
    }
    if (sf.len > PKG_MF_MAX) {
        pkg_seterr(err, errlen, "CERT.SF would exceed %u bytes (too many files)", PKG_MF_MAX);
        goto out;
    }

    *mfout = mf.p;
    *mflen = mf.len;
    *sfout = sf.p;
    *sflen = sf.len;
    mf.p = NULL;
    sf.p = NULL;
    rc = 0;
    goto out;

oom:
    pkg_seterr(err, errlen, "out of memory");
out:
    free(secdig);
    sb_free(&mf);
    sb_free(&sf);
    return rc;
}

static void mf_free_attrs(mf_section *s)
{
    size_t j;

    for (j = 0; j < s->nattrs; j++) {
        free(s->attrs[j].key);
        free(s->attrs[j].val);
    }
    free(s->attrs);
    s->attrs = NULL;
    s->nattrs = s->cap = 0;
}

static void mf_free(mf_section *s, size_t n)
{
    size_t i;

    if (!s)
        return;
    for (i = 0; i < n; i++)
        mf_free_attrs(&s[i]);
    free(s);
}

static char *dup_n(const unsigned char *p, size_t n)
{
    char *s = malloc(n + 1);

    if (!s)
        return NULL;
    memcpy(s, p, n);
    s[n] = '\0';
    return s;
}

static int attr_add(mf_section *s, const unsigned char *k, size_t klen,
                    const unsigned char *v, size_t vlen)
{
    mf_attr *na;
    char *key, *val;

    if (s->nattrs == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 8;

        na = realloc(s->attrs, ncap * sizeof(*na));
        if (!na)
            return -1;
        s->attrs = na;
        s->cap = ncap;
    }
    key = dup_n(k, klen);
    val = key ? dup_n(v, vlen) : NULL;
    if (!val) {
        free(key);
        return -1;
    }
    s->attrs[s->nattrs].key = key;
    s->attrs[s->nattrs].val = val;
    s->nattrs++;
    return 0;
}

/* Continuation line: appends to the value of the last header. */
static int attr_append(mf_section *s, const unsigned char *v, size_t vlen)
{
    mf_attr *a = &s->attrs[s->nattrs - 1];
    size_t kl = strlen(a->val);
    char *nv = realloc(a->val, kl + vlen + 1);

    if (!nv)
        return -1;
    memcpy(nv + kl, v, vlen);
    nv[kl + vlen] = '\0';
    a->val = nv;
    return 0;
}

static int key_valid(const unsigned char *k, size_t n)
{
    size_t i;

    if (n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = k[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

/*
 * Splits a metadata file into sections. Lines end with LF (an optional CR is
 * accepted). Every section must end with a blank line.
 */
static int mf_parse(const unsigned char *buf, size_t len, mf_section **out, size_t *nout,
                    char *err, size_t errlen)
{
    mf_section *secs = NULL, cur;
    size_t nsecs = 0, cap = 0, pos = 0;
    int active = 0, rc = -1;

    memset(&cur, 0, sizeof(cur));
    if (len == 0) {
        pkg_seterr(err, errlen, "metadata file is empty");
        return -1;
    }
    while (pos < len) {
        const unsigned char *nl = memchr(buf + pos, '\n', len - pos);
        const unsigned char *line = buf + pos;
        size_t lend, next, llen;

        if (!nl) {
            pkg_seterr(err, errlen, "metadata line is not terminated by a newline");
            goto out;
        }
        lend = (size_t)(nl - buf);
        next = lend + 1;
        llen = lend - pos;
        if (llen && line[llen - 1] == '\r')
            llen--;
        if (memchr(line, '\0', llen)) {
            pkg_seterr(err, errlen, "metadata contains a NUL byte");
            goto out;
        }

        if (llen == 0) {
            mf_section *ns;

            if (!active || cur.nattrs == 0) {
                pkg_seterr(err, errlen, "empty section in metadata");
                goto out;
            }
            cur.end = next;
            if (nsecs == cap) {
                size_t ncap = cap ? cap * 2 : 16;

                ns = realloc(secs, ncap * sizeof(*ns));
                if (!ns) {
                    pkg_seterr(err, errlen, "out of memory");
                    goto out;
                }
                secs = ns;
                cap = ncap;
            }
            secs[nsecs++] = cur;
            memset(&cur, 0, sizeof(cur));
            active = 0;
        } else if (line[0] == ' ') {
            if (!active || cur.nattrs == 0) {
                pkg_seterr(err, errlen, "continuation line without a header");
                goto out;
            }
            if (attr_append(&cur, line + 1, llen - 1) != 0) {
                pkg_seterr(err, errlen, "out of memory");
                goto out;
            }
        } else {
            const unsigned char *colon = memchr(line, ':', llen);
            size_t klen;

            if (!colon) {
                pkg_seterr(err, errlen, "malformed metadata line");
                goto out;
            }
            klen = (size_t)(colon - line);
            if (!key_valid(line, klen) || klen + 2 > llen || colon[1] != ' ') {
                pkg_seterr(err, errlen, "malformed metadata header");
                goto out;
            }
            if (cur.nattrs == MF_ATTRS_MAX) {
                pkg_seterr(err, errlen, "metadata section has too many headers");
                goto out;
            }
            if (!active) {
                active = 1;
                cur.start = pos;
            }
            if (attr_add(&cur, line, klen, colon + 2, llen - klen - 2) != 0) {
                pkg_seterr(err, errlen, "out of memory");
                goto out;
            }
        }
        pos = next;
    }
    if (active) {
        pkg_seterr(err, errlen, "last metadata section is not terminated by a blank line");
        goto out;
    }
    if (nsecs == 0) {
        pkg_seterr(err, errlen, "metadata has no sections");
        goto out;
    }
    *out = secs;
    *nout = nsecs;
    secs = NULL;
    rc = 0;
out:
    mf_free_attrs(&cur);
    mf_free(secs, nsecs);
    return rc;
}

static int attr_is(const mf_section *s, size_t i, const char *key, const char *val)
{
    return i < s->nattrs && strcmp(s->attrs[i].key, key) == 0 &&
           (!val || strcmp(s->attrs[i].val, val) == 0);
}

/* Main section of MANIFEST.MF: Manifest-Version: 1.0, optional Created-By. */
static int check_main_mf(const mf_section *s, char *err, size_t errlen)
{
    if ((s->nattrs != 1 && s->nattrs != 2) || !attr_is(s, 0, "Manifest-Version", "1.0") ||
        (s->nattrs == 2 && !attr_is(s, 1, "Created-By", NULL))) {
        pkg_seterr(err, errlen, "MANIFEST.MF main section must be Manifest-Version: 1.0 and optional Created-By");
        return -1;
    }
    return 0;
}

/* Main section of CERT.SF: Signature-Version, optional Created-By, SHA-256-Digest-Manifest. */
static int check_main_sf(const mf_section *s, const char mfdigest[B64_LEN + 1],
                         char *err, size_t errlen)
{
    size_t k = s->nattrs;

    if ((k != 2 && k != 3) || !attr_is(s, 0, "Signature-Version", "1.0") ||
        (k == 3 && !attr_is(s, 1, "Created-By", NULL))) {
        pkg_seterr(err, errlen, "CERT.SF main section must be Signature-Version: 1.0, optional Created-By and SHA-256-Digest-Manifest");
        return -1;
    }
    if (!attr_is(s, k - 1, "SHA-256-Digest-Manifest", NULL)) {
        pkg_seterr(err, errlen, "CERT.SF must end its main section with SHA-256-Digest-Manifest");
        return -1;
    }
    if (strcmp(s->attrs[k - 1].val, mfdigest) != 0) {
        pkg_seterr(err, errlen, "CERT.SF SHA-256-Digest-Manifest does not match MANIFEST.MF");
        return -1;
    }
    return 0;
}

static int entry_shape(const mf_section *s, const char *what, char *err, size_t errlen)
{
    if (s->nattrs != 2 || !attr_is(s, 0, "Name", NULL) || !attr_is(s, 1, "SHA-256-Digest", NULL)) {
        pkg_seterr(err, errlen, "%s entry must contain only Name and SHA-256-Digest", what);
        return -1;
    }
    return 0;
}

/* Binary search in d (sorted by strcmp on name). */
static const pkg_digest *find_digest(const pkg_digest *d, size_t n, const char *name, size_t *idx)
{
    size_t lo = 0, hi = n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(d[mid].name, name);

        if (c == 0) {
            *idx = mid;
            return &d[mid];
        }
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

/*
 * Checks MANIFEST.MF and CERT.SF against the archive files d (sorted by name,
 * excluding META-INF). Both files must list exactly the files in d, with
 * digests that match, and CERT.SF must cover the exact bytes of MANIFEST.MF.
 * The caller must have verified CERT.SIG over sf first.
 */
int pkg_meta_verify(const unsigned char *mf, size_t mflen, const unsigned char *sf, size_t sflen,
                    const pkg_digest *d, size_t n, char *err, size_t errlen)
{
    mf_section *ms = NULL, *ss = NULL;
    size_t nm = 0, ns = 0, i, *mfidx = NULL;
    unsigned char *seen = NULL;
    char b64[B64_LEN + 1];
    int rc = -1;

    mfidx = calloc(n ? n : 1, sizeof(*mfidx));
    seen = calloc(n ? n : 1, 1);
    if (!mfidx || !seen) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (mf_parse(mf, mflen, &ms, &nm, err, errlen) != 0 ||
        mf_parse(sf, sflen, &ss, &ns, err, errlen) != 0)
        goto out;

    if (check_main_mf(&ms[0], err, errlen) != 0)
        goto out;
    if (nm != n + 1) {
        pkg_seterr(err, errlen, "MANIFEST.MF lists %zu files, the package has %zu", nm - 1, n);
        goto out;
    }
    for (i = 1; i < nm; i++) {
        size_t idx;

        if (entry_shape(&ms[i], "MANIFEST.MF", err, errlen) != 0)
            goto out;
        if (!find_digest(d, n, ms[i].attrs[0].val, &idx)) {
            pkg_seterr(err, errlen, "MANIFEST.MF lists '%s', which is not in the package",
                       ms[i].attrs[0].val);
            goto out;
        }
        if (seen[idx]) {
            pkg_seterr(err, errlen, "MANIFEST.MF lists '%s' twice", ms[i].attrs[0].val);
            goto out;
        }
        seen[idx] = 1;
        if (hex_b64(d[idx].hex, b64) != 0 || strcmp(ms[i].attrs[1].val, b64) != 0) {
            pkg_seterr(err, errlen, "MANIFEST.MF digest for '%s' does not match the file",
                       d[idx].name);
            goto out;
        }
        mfidx[idx] = i;
    }

    if (sha256_b64(mf, mflen, b64) != 0) {
        pkg_seterr(err, errlen, "out of memory");
        goto out;
    }
    if (check_main_sf(&ss[0], b64, err, errlen) != 0)
        goto out;
    if (ns != n + 1) {
        pkg_seterr(err, errlen, "CERT.SF lists %zu files, the package has %zu", ns - 1, n);
        goto out;
    }
    memset(seen, 0, n);
    for (i = 1; i < ns; i++) {
        size_t idx, mi;
        const mf_section *m;

        if (entry_shape(&ss[i], "CERT.SF", err, errlen) != 0)
            goto out;
        if (!find_digest(d, n, ss[i].attrs[0].val, &idx)) {
            pkg_seterr(err, errlen, "CERT.SF lists '%s', which is not in the package",
                       ss[i].attrs[0].val);
            goto out;
        }
        if (seen[idx]) {
            pkg_seterr(err, errlen, "CERT.SF lists '%s' twice", ss[i].attrs[0].val);
            goto out;
        }
        seen[idx] = 1;
        mi = mfidx[idx];
        m = &ms[mi];
        if (sha256_b64(mf + m->start, m->end - m->start, b64) != 0 ||
            strcmp(ss[i].attrs[1].val, b64) != 0) {
            pkg_seterr(err, errlen, "CERT.SF digest for '%s' does not match MANIFEST.MF",
                       d[idx].name);
            goto out;
        }
    }
    rc = 0;
out:
    mf_free(ms, nm);
    mf_free(ss, ns);
    free(mfidx);
    free(seen);
    return rc;
}
