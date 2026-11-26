/*
 * config.c - reads the OS identity file (urados/etc/urados/init/id).
 *
 * The file holds KEY=VALUE lines, like /etc/os-release. A value may be wrapped
 * in matching " or ' quotes. Blank lines and lines starting with # are ignored.
 * NAME, VERSION and CHANNEL are required; other keys are ignored.
 *
 *   NAME="Urados"
 *   VERSION=1.0.0
 *   CHANNEL=stable
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "uinit.h"

static char *trim(char *s)
{
    char *e;

    while (*s && isspace((unsigned char)*s))
        s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

static int set_value(char *dst, size_t dstlen, const char *file, int line,
                     const char *key, const char *val, char *err, size_t errlen)
{
    const char *c;

    if (!*val) {
        uinit_seterr(err, errlen, "%s:%d: %s is empty", file, line, key);
        return -1;
    }
    if (strlen(val) >= dstlen) {
        uinit_seterr(err, errlen, "%s:%d: %s is longer than %zu bytes",
                     file, line, key, dstlen - 1);
        return -1;
    }
    for (c = val; *c; c++) {
        if (iscntrl((unsigned char)*c)) {
            uinit_seterr(err, errlen, "%s:%d: %s contains control characters",
                         file, line, key);
            return -1;
        }
    }
    memcpy(dst, val, strlen(val) + 1);
    return 0;
}

int uinit_load_ident(const char *path, struct uinit_ident *id, char *err, size_t errlen)
{
    char line[1024];
    int lineno = 0;
    FILE *f;

    memset(id, 0, sizeof *id);
    f = fopen(path, "r");
    if (!f) {
        uinit_seterr(err, errlen, "%s: %s", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        char *s, *eq, *key, *val;
        size_t vl;
        int rc;

        lineno++;
        if (len == sizeof line - 1 && line[len - 1] != '\n') {
            uinit_seterr(err, errlen, "%s:%d: line too long", path, lineno);
            goto fail;
        }
        s = trim(line);
        if (!*s || *s == '#')
            continue;

        eq = strchr(s, '=');
        if (!eq) {
            uinit_seterr(err, errlen, "%s:%d: expected KEY=VALUE", path, lineno);
            goto fail;
        }
        *eq = '\0';
        key = trim(s);
        val = trim(eq + 1);
        vl = strlen(val);
        if (vl >= 2 && (val[0] == '"' || val[0] == '\'') && val[vl - 1] == val[0]) {
            val[vl - 1] = '\0';
            val++;
        }

        if (!strcmp(key, "NAME"))
            rc = set_value(id->name, sizeof id->name, path, lineno, key, val, err, errlen);
        else if (!strcmp(key, "VERSION"))
            rc = set_value(id->version, sizeof id->version, path, lineno, key, val, err, errlen);
        else if (!strcmp(key, "CHANNEL"))
            rc = set_value(id->channel, sizeof id->channel, path, lineno, key, val, err, errlen);
        else
            continue;
        if (rc < 0)
            goto fail;
    }
    if (ferror(f)) {
        uinit_seterr(err, errlen, "%s: read error", path);
        goto fail;
    }
    fclose(f);

    if (!id->name[0] || !id->version[0] || !id->channel[0]) {
        const char *missing = !id->name[0] ? "NAME" : !id->version[0] ? "VERSION" : "CHANNEL";

        uinit_seterr(err, errlen, "%s: %s is missing", path, missing);
        return -1;
    }
    return 0;

fail:
    fclose(f);
    return -1;
}
