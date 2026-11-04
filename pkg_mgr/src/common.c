/*
 * common.c - validation helpers, hashing, file helpers, digest text.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "urados_pkg.h"

void pkg_seterr(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (!err || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static int is_lower(char c) { return c >= 'a' && c <= 'z'; }
static int is_upper(char c) { return c >= 'A' && c <= 'Z'; }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

/* Linux user name rules: [a-z_][a-z0-9_-]*, length limited. */
int pkg_name_valid(const char *name)
{
    size_t i, n;

    if (!name)
        return 0;
    n = strlen(name);
    if (n == 0 || n > PKG_NAME_MAX)
        return 0;
    if (!(is_lower(name[0]) || name[0] == '_'))
        return 0;
    for (i = 1; i < n; i++) {
        char c = name[i];
        if (!(is_lower(c) || is_digit(c) || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* Versions: alphanumerics and . - + ~ _, starting with an alphanumeric. */
int pkg_version_valid(const char *v)
{
    size_t i, n;

    if (!v)
        return 0;
    n = strlen(v);
    if (n == 0 || n > PKG_VERSION_MAX)
        return 0;
    if (!(is_lower(v[0]) || is_upper(v[0]) || is_digit(v[0])))
        return 0;
    for (i = 0; i < n; i++) {
        char c = v[i];
        if (!(is_lower(c) || is_upper(c) || is_digit(c) ||
              c == '.' || c == '-' || c == '+' || c == '~' || c == '_'))
            return 0;
    }
    return 1;
}

/*
 * Safe relative path: no leading or trailing '/', no empty, '.' or '..'
 * segment, no backslash, no control characters.
 */
int pkg_path_safe(const char *p)
{
    const char *seg;
    const unsigned char *c;
    size_t len;

    if (!p)
        return 0;
    len = strlen(p);
    if (len == 0 || len >= PKG_PATH_MAX || p[0] == '/' || p[len - 1] == '/')
        return 0;
    for (c = (const unsigned char *)p; *c; c++) {
        if (*c < 0x20 || *c == 0x7f || *c == '\\')
            return 0;
    }
    seg = p;
    for (;;) {
        const char *slash = strchr(seg, '/');
        size_t sl = slash ? (size_t)(slash - seg) : strlen(seg);

        if (sl == 0)
            return 0;
        if ((sl == 1 && seg[0] == '.') || (sl == 2 && seg[0] == '.' && seg[1] == '.'))
            return 0;
        if (!slash)
            break;
        seg = slash + 1;
    }
    return 1;
}

/*
 * A manifest <entry> must be under system_cache/app/. Writes the matching
 * zip name ("app/<rest>") to out. Returns 0 on success.
 */
int pkg_entry_zipname(const char *entry, char *out, size_t outlen)
{
    size_t plen = strlen(PKG_ENTRY_PREFIX);
    int n;

    if (!entry || strncmp(entry, PKG_ENTRY_PREFIX, plen) != 0)
        return -1;
    if (!pkg_path_safe(entry + plen))
        return -1;
    n = snprintf(out, outlen, "%s%s", PKG_ZIP_APP_PREFIX, entry + plen);
    return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

int pkg_digest_cmp(const void *a, const void *b)
{
    const pkg_digest *x = a;
    const pkg_digest *y = b;

    return strcmp(x->name, y->name);
}

void pkg_hex_encode(const unsigned char *md, size_t len, char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        hex[2 * i] = digits[md[i] >> 4];
        hex[2 * i + 1] = digits[md[i] & 0x0f];
    }
    hex[2 * len] = '\0';
}

void pkg_sha256(const void *data, size_t len, char hex[65])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
    pkg_hex_encode(md, mdlen, hex);
}

/* Reads a whole regular file (no symlinks) up to max bytes. */
int pkg_read_file(const char *path, size_t max, unsigned char **out, size_t *outlen)
{
    int fd;
    struct stat st;
    unsigned char *buf;
    size_t off = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (size_t)st.st_size > max) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            free(buf);
            close(fd);
            errno = EIO;
            return -1;
        }
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *outlen = off;
    return 0;
}

int pkg_write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;

    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

/* Joins root and path ("" root means no prefix). Caller frees. */
char *pkg_join(const char *root, const char *path)
{
    size_t rl = root ? strlen(root) : 0;
    size_t pl = strlen(path);
    char *out = malloc(rl + pl + 1);

    if (!out)
        return NULL;
    if (rl)
        memcpy(out, root, rl);
    memcpy(out + rl, path, pl + 1);
    return out;
}
