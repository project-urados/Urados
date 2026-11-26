/*
 * util.c - logging, path and directory helpers shared by uinit.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "uinit.h"

int uinit_verbose;

static void vlog(const char *fmt, va_list ap)
{
    fputs("uinit: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void uinit_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vlog(fmt, ap);
    va_end(ap);
}

/* Like uinit_log, but only when -v was given. */
void uinit_debug(const char *fmt, ...)
{
    va_list ap;

    if (!uinit_verbose)
        return;
    va_start(ap, fmt);
    vlog(fmt, ap);
    va_end(ap);
}

void uinit_seterr(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (!err || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Returns root + path as a new string, or NULL when out of memory. */
char *uinit_path_under(const char *root, const char *path)
{
    size_t rl = strlen(root);
    size_t pl = strlen(path);
    char *s = malloc(rl + pl + 1);

    if (!s)
        return NULL;
    memcpy(s, root, rl);
    memcpy(s + rl, path, pl + 1);
    return s;
}

/* Creates path and any missing parents. Existing directories are fine. */
int uinit_mkdir_p(const char *path, mode_t mode)
{
    char buf[PATH_MAX];
    size_t len = strlen(path);
    char *p;

    if (len == 0 || len >= sizeof buf) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, path, len + 1);
    for (p = buf + 1; ; p++) {
        if (*p == '/' || *p == '\0') {
            char save = *p;

            *p = '\0';
            if (mkdir(buf, mode) < 0 && errno != EEXIST)
                return -1;
            *p = save;
            if (save == '\0')
                break;
        }
    }
    return 0;
}
