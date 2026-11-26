/*
 * parse.c - reads .uinit unit files into statements.
 *
 * A unit is a text file with one statement per line. Words are separated by
 * blanks. Double or single quotes keep blanks inside a word; inside double
 * quotes, \" and \\ are escapes. A '#' that starts a word begins a comment that
 * runs to the end of the line. ${NAME}, ${VERSION} and ${CHANNEL} are replaced
 * with the OS identity in every word, quoted or not. Any other ${...} is an error.
 *
 *   optional <statement>
 *       The statement may fail without stopping the unit. The failure is logged.
 *
 *   import <path> [<path>...]
 *       Run one or more other units, in order. An absolute path is taken from
 *       the root. A relative path is taken from the directory of the current
 *       unit. Paths may not contain "..". Nesting is limited to UINIT_MAX_DEPTH.
 *       If an imported unit fails, the importing unit stops, unless optional.
 *
 *   run <path>
 *       The same as import with exactly one path. Kept for existing units.
 *
 *   chmod [-R] <mode> <path>
 *       Set permission bits. mode is 1 to 4 octal digits, e.g. 0755 or 4750.
 *       path is an absolute path below / (/ itself is allowed). -R also changes
 *       everything below a directory. The last component of path is never
 *       followed: chmod on a symbolic link is an error, and -R leaves links
 *       alone. Links in the directories above path are followed as usual.
 *
 *   chown [-R] <owner>[:<group>] <path>
 *       Set the owner and/or group. Each is a name or a numeric id.
 *           chown alice /p          set the owner, keep the group
 *           chown alice:staff /p    set both
 *           chown alice: /p         set the owner and alice's login group
 *           chown :staff /p         set the group, keep the owner
 *       -R and the path rules are the same as for chmod. A link is changed
 *       itself, never its target. Names are looked up when the statement runs.
 *
 *   log <text...>
 *       Print the words, joined by single blanks, on the console.
 *
 *   mount <source> <target> [type=<fstype>] [opts=<list>] [timeout=<seconds>]
 *       <source> is one of
 *           UUID=<uuid>            the device whose file system has this UUID
 *           LABEL=<label>          the device whose file system has this label
 *           PARTNUM=<disk>:<n>     partition n (1-based) of a disk, e.g. PARTNUM=sda:2
 *           NONE                   no device; type= is required, e.g. proc, sysfs, tmpfs
 *       <target> is an absolute path below / and is created if it is missing.
 *       opts is a comma-separated list. ro, rw, nosuid, nodev, noexec, noatime,
 *       nodiratime, relatime, sync, silent and lazytime become mount flags. Any
 *       other entry, such as errors=remount-ro, is passed to the file system.
 *       timeout is how long to wait for a device to appear. The default is 5
 *       seconds and the maximum is 300. NONE mounts do not wait.
 *
 *   exec [mode=<mode>] [user=<name|uid>] [group=<name|gid>] [groups=<g1,g2,...>] [--] <cmd> [args...]
 *   spawn [user=...] [group=...] [groups=...] [--] <cmd> [args...]
 *       Run a command. Options must come before the command. Without user= or
 *       group=, the command keeps the uinit identity. spawn is the same as
 *       exec mode=spawn, and takes no mode=.
 *
 *       mode=wait (the default)
 *           Fork and wait for the command. Exit status 0 continues the unit.
 *           Any other status, or a signal, fails the statement.
 *       mode=spawn
 *           Fork and continue at once. The command is reaped later.
 *       mode=replace
 *           No fork. uinit becomes the command: same PID. Nothing after the
 *           statement runs. If the command cannot start, the statement fails.
 *           Once user= or group= has changed uinit's identity, a failure stops
 *           the boot even if the statement is optional, because uinit can no
 *           longer get back to root.
 *       mode=exit-nonzero
 *           Fork and wait. A non-zero status ends uinit with that status. Zero
 *           continues the boot.
 *       mode=exit
 *           Fork and wait. uinit ends with the command's status, including 0.
 *
 *       A command killed by a signal counts as status 128 + the signal number.
 *       exit and exit-nonzero stop the whole boot, including the importing units.
 *       As PID 1, uinit cannot exit: it logs the request and keeps reaping.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uinit.h"

#define OOM(err, errlen) \
    do { uinit_seterr((err), (errlen), "out of memory"); return -1; } while (0)

/* A list of words from one line. Each word is owned unless it was moved out. */
struct words {
    char **v;
    size_t n;
    size_t cap;
};

static void words_free(struct words *w)
{
    size_t i;

    for (i = 0; i < w->n; i++)
        free(w->v[i]);
    free(w->v);
    memset(w, 0, sizeof *w);
}

/* Takes ownership of s, even on failure. */
static int words_push(struct words *w, char *s)
{
    if (w->n == w->cap) {
        size_t ncap = w->cap ? w->cap * 2 : 8;
        char **nv = realloc(w->v, ncap * sizeof *nv);

        if (!nv) {
            free(s);
            return -1;
        }
        w->v = nv;
        w->cap = ncap;
    }
    w->v[w->n++] = s;
    return 0;
}

/* Appends n bytes of s to *dst, which may be NULL. */
static int str_append(char **dst, const char *s, size_t n)
{
    size_t dl = *dst ? strlen(*dst) : 0;
    char *nb = realloc(*dst, dl + n + 1);

    if (!nb)
        return -1;
    memcpy(nb + dl, s, n);
    nb[dl + n] = '\0';
    *dst = nb;
    return 0;
}

/* A path with no ".." component. Leading and repeated slashes are allowed. */
static int valid_path(const char *s)
{
    const char *p = s;

    if (!*s)
        return 0;
    while (*p) {
        const char *e;
        size_t cl;

        while (*p == '/')
            p++;
        if (!*p)
            break;
        e = strchr(p, '/');
        cl = e ? (size_t)(e - p) : strlen(p);
        if (cl == 2 && p[0] == '.' && p[1] == '.')
            return 0;
        p += cl;
    }
    return 1;
}

static int is_number(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return 0;
    return 1;
}

static int is_uuid(const char *s)
{
    size_t k;

    if (strlen(s) != 36)
        return 0;
    for (k = 0; k < 36; k++) {
        if (k == 8 || k == 13 || k == 18 || k == 23) {
            if (s[k] != '-')
                return 0;
        } else if (!isxdigit((unsigned char)s[k])) {
            return 0;
        }
    }
    return 1;
}

/* Splits one line into words, handling quotes and comments. */
static int tokenize(const char *line, struct words *w, char *err, size_t errlen)
{
    const char *p = line;

    for (;;) {
        char *buf;
        size_t len = 0;

        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p || *p == '#')
            return 0;

        buf = malloc(strlen(p) + 1);
        if (!buf)
            OOM(err, errlen);
        while (*p && *p != ' ' && *p != '\t') {
            if (*p == '"' || *p == '\'') {
                char q = *p++;

                for (;;) {
                    if (!*p) {
                        uinit_seterr(err, errlen, "unterminated quote");
                        free(buf);
                        return -1;
                    }
                    if (*p == q) {
                        p++;
                        break;
                    }
                    if (q == '"' && *p == '\\' && (p[1] == '"' || p[1] == '\\'))
                        p++;
                    buf[len++] = *p++;
                }
            } else {
                buf[len++] = *p++;
            }
        }
        buf[len] = '\0';
        if (words_push(w, buf) < 0)
            OOM(err, errlen);
    }
}

/* Returns a new string with ${NAME}, ${VERSION} and ${CHANNEL} replaced. */
static char *expand(const struct uinit_ctx *ctx, const char *in, char *err, size_t errlen)
{
    char *out = NULL;
    const char *p = in;

    while (*p) {
        if (p[0] == '$' && p[1] == '{') {
            const char *close = strchr(p + 2, '}');
            size_t nl;
            const char *val;

            if (!close) {
                uinit_seterr(err, errlen, "unterminated ${");
                free(out);
                return NULL;
            }
            nl = (size_t)(close - (p + 2));
            if (nl == 4 && !memcmp(p + 2, "NAME", 4))
                val = ctx->id.name;
            else if (nl == 7 && !memcmp(p + 2, "VERSION", 7))
                val = ctx->id.version;
            else if (nl == 7 && !memcmp(p + 2, "CHANNEL", 7))
                val = ctx->id.channel;
            else {
                uinit_seterr(err, errlen, "unknown variable '%.*s'", (int)nl, p + 2);
                free(out);
                return NULL;
            }
            if (str_append(&out, val, strlen(val)) < 0)
                goto oom;
            p = close + 1;
        } else {
            if (str_append(&out, p, 1) < 0)
                goto oom;
            p++;
        }
    }
    if (!out) {
        out = malloc(1);
        if (!out)
            goto oom;
        out[0] = '\0';
    }
    return out;

oom:
    uinit_seterr(err, errlen, "out of memory");
    free(out);
    return NULL;
}

/* Creates a statement at the end of the unit. The statement is zeroed. */
static struct uinit_stmt *stmt_new(struct uinit_unit *unit, enum uinit_op op,
                                   int line, int optional)
{
    struct uinit_stmt *nv = realloc(unit->stmts, (unit->nstmts + 1) * sizeof *nv);
    struct uinit_stmt *st;

    if (!nv)
        return NULL;
    unit->stmts = nv;
    st = &nv[unit->nstmts++];
    memset(st, 0, sizeof *st);
    st->op = op;
    st->line = line;
    st->optional = optional;
    return st;
}

static int parse_source(const char *s, struct uinit_source *src, char *err, size_t errlen)
{
    if (!strcmp(s, "NONE")) {
        src->kind = UINIT_SRC_NONE;
        return 0;
    }
    if (!strncmp(s, "UUID=", 5)) {
        const char *v = s + 5;
        size_t k;

        if (!is_uuid(v)) {
            uinit_seterr(err, errlen, "invalid UUID '%s'; expected 8-4-4-4-12 hex digits", v);
            return -1;
        }
        src->value = strdup(v);
        if (!src->value)
            OOM(err, errlen);
        for (k = 0; k < 36; k++)
            src->value[k] = (char)tolower((unsigned char)src->value[k]);
        src->kind = UINIT_SRC_UUID;
        return 0;
    }
    if (!strncmp(s, "LABEL=", 6)) {
        const char *v = s + 6;
        size_t k;

        if (!*v || strlen(v) > 255) {
            uinit_seterr(err, errlen, "LABEL must be 1 to 255 characters");
            return -1;
        }
        for (k = 0; v[k]; k++) {
            if (iscntrl((unsigned char)v[k])) {
                uinit_seterr(err, errlen, "LABEL contains control characters");
                return -1;
            }
        }
        src->value = strdup(v);
        if (!src->value)
            OOM(err, errlen);
        src->kind = UINIT_SRC_LABEL;
        return 0;
    }
    if (!strncmp(s, "PARTNUM=", 8)) {
        const char *v = s + 8;
        const char *colon = strrchr(v, ':');
        const char *d;
        size_t dl, k;
        unsigned long n;

        if (!colon || colon == v || !colon[1]) {
            uinit_seterr(err, errlen, "PARTNUM needs <disk>:<n>, e.g. PARTNUM=sda:2");
            return -1;
        }
        dl = (size_t)(colon - v);
        for (k = 0; k < dl; k++) {
            if (!isalnum((unsigned char)v[k]) && v[k] != '_' && v[k] != '-') {
                uinit_seterr(err, errlen, "invalid disk name in '%s'", s);
                return -1;
            }
        }
        for (d = colon + 1; *d; d++) {
            if (!isdigit((unsigned char)*d)) {
                uinit_seterr(err, errlen, "partition number in '%s' must be a number", s);
                return -1;
            }
        }
        n = strtoul(colon + 1, NULL, 10);
        if (n == 0 || n > 4096) {
            uinit_seterr(err, errlen, "partition number must be 1 to 4096");
            return -1;
        }
        src->disk = malloc(dl + 1);
        if (!src->disk)
            OOM(err, errlen);
        memcpy(src->disk, v, dl);
        src->disk[dl] = '\0';
        src->partnum = (unsigned int)n;
        src->kind = UINIT_SRC_PARTNUM;
        return 0;
    }
    uinit_seterr(err, errlen, "unknown source '%s'; use UUID=, LABEL=, PARTNUM= or NONE", s);
    return -1;
}

/* Adds the comma-separated mount options to m: known flags go to m->flags, the rest to m->data. */
static int parse_opts(struct uinit_mount *m, const char *list, char *err, size_t errlen)
{
    const char *p = list;

    if (!*p) {
        uinit_seterr(err, errlen, "empty opts=");
        return -1;
    }
    for (;;) {
        const char *c = strchr(p, ',');
        size_t n = c ? (size_t)(c - p) : strlen(p);
        char name[64];

        if (n == 0) {
            uinit_seterr(err, errlen, "empty entry in opts=");
            return -1;
        }
        if (n >= sizeof name) {
            uinit_seterr(err, errlen, "mount option is longer than %zu characters", sizeof name - 1);
            return -1;
        }
        memcpy(name, p, n);
        name[n] = '\0';
        if (!uinit_mount_opt(name, &m->flags)) {
            if (m->data && str_append(&m->data, ",", 1) < 0)
                OOM(err, errlen);
            if (str_append(&m->data, name, n) < 0)
                OOM(err, errlen);
        }
        if (!c)
            break;
        p = c + 1;
    }
    return 0;
}

static int parse_timeout(const char *s, unsigned int *out)
{
    unsigned long v;

    if (!is_number(s) || strlen(s) > 4)
        return -1;
    v = strtoul(s, NULL, 10);
    if (v > UINIT_MOUNT_TIMEOUT_MAX)
        return -1;
    *out = (unsigned int)v;
    return 0;
}

/*
 * Resolves one unit path from a run or import statement. An absolute path is
 * kept. A relative path is taken from the directory of unit, whose path is
 * absolute. Returns a new string, or NULL with err set.
 */
static char *resolve_unit_path(const struct uinit_unit *unit, const char *path,
                               char *err, size_t errlen)
{
    char *resolved;

    if (!valid_path(path)) {
        uinit_seterr(err, errlen, "invalid path '%s'", path);
        return NULL;
    }
    if (path[0] == '/') {
        resolved = strdup(path);
    } else {
        const char *slash = strrchr(unit->path, '/');
        size_t dirlen = slash ? (size_t)(slash - unit->path) : 0;

        resolved = malloc(dirlen + strlen(path) + 2);
        if (resolved) {
            memcpy(resolved, unit->path, dirlen);
            resolved[dirlen] = '/';
            strcpy(resolved + dirlen + 1, path);
        }
    }
    if (!resolved)
        uinit_seterr(err, errlen, "out of memory");
    return resolved;
}

/*
 * run <path> takes exactly one path. import takes one or more. Each path becomes
 * its own statement, run in order.
 */
static int parse_import(struct uinit_unit *unit, const struct words *w, size_t i, int line,
                        int optional, char *err, size_t errlen)
{
    int single = !strcmp(w->v[i], "run");
    size_t k;

    if (single && w->n != i + 2) {
        uinit_seterr(err, errlen, "run takes exactly one path");
        return -1;
    }
    if (!single && w->n < i + 2) {
        uinit_seterr(err, errlen, "import needs at least one path");
        return -1;
    }
    for (k = i + 1; k < w->n; k++) {
        char *resolved = resolve_unit_path(unit, w->v[k], err, errlen);
        struct uinit_stmt *st;

        if (!resolved)
            return -1;
        st = stmt_new(unit, UINIT_OP_RUN, line, optional);
        if (!st) {
            free(resolved);
            OOM(err, errlen);
        }
        st->u.run_path = resolved;
    }
    return 0;
}

static int parse_log(struct uinit_unit *unit, const struct words *w, size_t i, int line,
                     int optional, char *err, size_t errlen)
{
    struct uinit_stmt *st;
    char *text = NULL;
    size_t k;

    if (w->n < i + 2) {
        uinit_seterr(err, errlen, "log needs a message");
        return -1;
    }
    for (k = i + 1; k < w->n; k++) {
        if (k > i + 1 && str_append(&text, " ", 1) < 0)
            OOM(err, errlen);
        if (str_append(&text, w->v[k], strlen(w->v[k])) < 0) {
            free(text);
            OOM(err, errlen);
        }
    }
    st = stmt_new(unit, UINIT_OP_LOG, line, optional);
    if (!st) {
        free(text);
        OOM(err, errlen);
    }
    st->u.log_text = text;
    return 0;
}

static int parse_mount(struct uinit_unit *unit, const struct words *w, size_t i, int line,
                       int optional, char *err, size_t errlen)
{
    struct uinit_stmt *st;
    struct uinit_mount *m;
    int seen_type = 0, seen_timeout = 0;
    size_t k;

    if (w->n < i + 3) {
        uinit_seterr(err, errlen, "mount needs a source and a target");
        return -1;
    }
    st = stmt_new(unit, UINIT_OP_MOUNT, line, optional);
    if (!st)
        OOM(err, errlen);
    m = &st->u.mount;

    if (parse_source(w->v[i + 1], &m->src, err, errlen) < 0)
        return -1;

    if (w->v[i + 2][0] != '/' || !strcmp(w->v[i + 2], "/") || !valid_path(w->v[i + 2])) {
        uinit_seterr(err, errlen, "mount target '%s' must be an absolute path below /",
                     w->v[i + 2]);
        return -1;
    }
    m->target = strdup(w->v[i + 2]);
    if (!m->target)
        OOM(err, errlen);
    m->timeout = m->src.kind == UINIT_SRC_NONE ? 0 : UINIT_MOUNT_TIMEOUT_DEFAULT;

    for (k = i + 3; k < w->n; k++) {
        const char *word = w->v[k];

        if (!strncmp(word, "type=", 5)) {
            if (seen_type) {
                uinit_seterr(err, errlen, "type= given twice");
                return -1;
            }
            if (!word[5]) {
                uinit_seterr(err, errlen, "empty type=");
                return -1;
            }
            m->type = strdup(word + 5);
            if (!m->type)
                OOM(err, errlen);
            seen_type = 1;
        } else if (!strncmp(word, "opts=", 5)) {
            if (parse_opts(m, word + 5, err, errlen) < 0)
                return -1;
        } else if (!strncmp(word, "timeout=", 8)) {
            if (seen_timeout) {
                uinit_seterr(err, errlen, "timeout= given twice");
                return -1;
            }
            if (parse_timeout(word + 8, &m->timeout) < 0) {
                uinit_seterr(err, errlen, "timeout must be 0 to %d seconds",
                             UINIT_MOUNT_TIMEOUT_MAX);
                return -1;
            }
            seen_timeout = 1;
        } else {
            uinit_seterr(err, errlen, "unknown mount option '%s'", word);
            return -1;
        }
    }
    if (m->src.kind == UINIT_SRC_NONE && !m->type) {
        uinit_seterr(err, errlen, "NONE needs type=, e.g. mount NONE /proc type=proc");
        return -1;
    }
    return 0;
}

/* Parses one exec mode name. */
static int parse_exec_mode(const char *s, enum uinit_exec_mode *out)
{
    static const struct {
        const char *name;
        enum uinit_exec_mode mode;
    } names[] = {
        { "wait",         UINIT_MODE_WAIT },
        { "spawn",        UINIT_MODE_SPAWN },
        { "replace",      UINIT_MODE_REPLACE },
        { "exit-nonzero", UINIT_MODE_EXIT_NONZERO },
        { "exit",         UINIT_MODE_EXIT },
    };
    size_t k;

    for (k = 0; k < sizeof names / sizeof names[0]; k++) {
        if (!strcmp(s, names[k].name)) {
            *out = names[k].mode;
            return 0;
        }
    }
    return -1;
}

/* Parses a chmod mode: 1 to 4 octal digits, so the largest is 07777. */
static int parse_mode(const char *s, mode_t *out)
{
    size_t n = strlen(s), k;

    if (n < 1 || n > 4)
        return -1;
    for (k = 0; k < n; k++) {
        if (s[k] < '0' || s[k] > '7')
            return -1;
    }
    *out = (mode_t)strtoul(s, NULL, 8);
    return 0;
}

/* Frees the strings of an attr that has not been moved into a statement yet. */
static void attr_free(struct uinit_attr *a)
{
    free(a->path);
    free(a->owner);
    free(a->group);
    memset(a, 0, sizeof *a);
}

/*
 * Parses the chown owner spec into a->owner, a->group and a->login_group.
 * Forms: "owner", "owner:group", "owner:" and ":group".
 */
static int parse_owner_spec(const char *spec, struct uinit_attr *a, char *err, size_t errlen)
{
    const char *colon = strchr(spec, ':');
    const char *group;

    if (!*spec) {
        uinit_seterr(err, errlen, "chown needs an owner or a group");
        return -1;
    }
    if (!colon) {
        a->owner = strdup(spec);
        if (!a->owner)
            OOM(err, errlen);
        return 0;
    }
    group = colon + 1;
    if (strchr(group, ':')) {
        uinit_seterr(err, errlen, "chown takes at most one ':' in '%s'", spec);
        return -1;
    }
    if (colon == spec) {
        if (!*group) {
            uinit_seterr(err, errlen, "chown needs an owner or a group in ':'");
            return -1;
        }
        a->group = strdup(group);
        if (!a->group)
            OOM(err, errlen);
        return 0;
    }
    a->owner = strndup(spec, (size_t)(colon - spec));
    if (!a->owner)
        OOM(err, errlen);
    if (*group) {
        a->group = strdup(group);
        if (!a->group)
            OOM(err, errlen);
    } else {
        a->login_group = 1;
    }
    return 0;
}

/*
 * chmod [-R] <mode> <path> and chown [-R] <owner>[:<group>] <path>. The path
 * is absolute and below /. Names are looked up when the statement runs.
 */
static int parse_attr(struct uinit_unit *unit, const struct words *w, size_t i, int line,
                      int optional, char *err, size_t errlen)
{
    int is_chown = !strcmp(w->v[i], "chown");
    struct uinit_attr a;
    struct uinit_stmt *st;
    const char *spec, *path;
    size_t k = i + 1;

    memset(&a, 0, sizeof a);
    if (k < w->n && !strcmp(w->v[k], "-R")) {
        a.recursive = 1;
        k++;
    }
    if (w->n != k + 2) {
        uinit_seterr(err, errlen, is_chown ? "chown takes [-R] <owner[:group]> <path>"
                                           : "chmod takes [-R] <mode> <path>");
        return -1;
    }
    spec = w->v[k];
    path = w->v[k + 1];
    if (path[0] != '/' || !valid_path(path)) {
        uinit_seterr(err, errlen, "%s path '%s' must be an absolute path below /",
                     w->v[i], path);
        return -1;
    }
    a.path = strdup(path);
    if (!a.path)
        OOM(err, errlen);

    if (is_chown) {
        if (parse_owner_spec(spec, &a, err, errlen) < 0) {
            attr_free(&a);
            return -1;
        }
    } else if (parse_mode(spec, &a.mode) < 0) {
        uinit_seterr(err, errlen, "mode '%s' must be 1 to 4 octal digits, e.g. 0755", spec);
        attr_free(&a);
        return -1;
    }

    st = stmt_new(unit, is_chown ? UINIT_OP_CHOWN : UINIT_OP_CHMOD, line, optional);
    if (!st) {
        attr_free(&a);
        OOM(err, errlen);
    }
    st->u.attr = a;
    return 0;
}

/* Parses "a,b,c" into e->groups. ngroups is kept in step so a partial failure frees cleanly. */
static int split_groups(struct uinit_exec *e, const char *list, char *err, size_t errlen)
{
    size_t n = 1, j = 0;
    const char *p;

    for (p = list; *p; p++)
        if (*p == ',')
            n++;
    e->groups = calloc(n + 1, sizeof *e->groups);
    if (!e->groups)
        OOM(err, errlen);

    p = list;
    for (;;) {
        const char *c = strchr(p, ',');
        size_t len = c ? (size_t)(c - p) : strlen(p);

        if (len == 0) {
            uinit_seterr(err, errlen, "empty name in groups=");
            return -1;
        }
        e->groups[j] = strndup(p, len);
        if (!e->groups[j])
            OOM(err, errlen);
        e->ngroups = ++j;
        if (!c)
            break;
        p = c + 1;
    }
    return 0;
}

static int parse_exec(struct uinit_unit *unit, struct words *w, size_t i, int line,
                      int optional, char *err, size_t errlen)
{
    int is_spawn = !strcmp(w->v[i], "spawn");
    int seen_mode = 0;
    struct uinit_stmt *st;
    struct uinit_exec *e;
    size_t k = i + 1, argc, j;

    st = stmt_new(unit, UINIT_OP_EXEC, line, optional);
    if (!st)
        OOM(err, errlen);
    e = &st->u.exec;
    e->mode = is_spawn ? UINIT_MODE_SPAWN : UINIT_MODE_WAIT;

    for (; k < w->n; k++) {
        const char *word = w->v[k];

        if (!strncmp(word, "mode=", 5)) {
            if (is_spawn) {
                uinit_seterr(err, errlen, "spawn takes no mode=; use exec mode=%s", word + 5);
                return -1;
            }
            if (seen_mode) {
                uinit_seterr(err, errlen, "mode= given twice");
                return -1;
            }
            if (parse_exec_mode(word + 5, &e->mode) < 0) {
                uinit_seterr(err, errlen,
                             "unknown mode '%s'; use wait, spawn, replace, exit-nonzero or exit",
                             word + 5);
                return -1;
            }
            seen_mode = 1;
        } else if (!strncmp(word, "user=", 5)) {
            if (e->user) {
                uinit_seterr(err, errlen, "user= given twice");
                return -1;
            }
            if (!word[5]) {
                uinit_seterr(err, errlen, "empty user=");
                return -1;
            }
            e->user = strdup(word + 5);
            if (!e->user)
                OOM(err, errlen);
        } else if (!strncmp(word, "group=", 6)) {
            if (e->group) {
                uinit_seterr(err, errlen, "group= given twice");
                return -1;
            }
            if (!word[6]) {
                uinit_seterr(err, errlen, "empty group=");
                return -1;
            }
            e->group = strdup(word + 6);
            if (!e->group)
                OOM(err, errlen);
        } else if (!strncmp(word, "groups=", 7)) {
            if (e->groups) {
                uinit_seterr(err, errlen, "groups= given twice");
                return -1;
            }
            if (!word[7]) {
                uinit_seterr(err, errlen, "empty groups=");
                return -1;
            }
            if (split_groups(e, word + 7, err, errlen) < 0)
                return -1;
        } else {
            break;
        }
    }

    if (k < w->n && !strcmp(w->v[k], "--"))
        k++;
    if (k >= w->n) {
        uinit_seterr(err, errlen, "%s needs a command", w->v[i]);
        return -1;
    }
    argc = w->n - k;
    if (argc > UINIT_MAX_ARGS) {
        uinit_seterr(err, errlen, "%s has more than %d arguments", w->v[i], UINIT_MAX_ARGS);
        return -1;
    }
    e->argv = calloc(argc + 1, sizeof *e->argv);
    if (!e->argv)
        OOM(err, errlen);
    for (j = 0; j < argc; j++) {
        e->argv[j] = w->v[k + j];   /* moved out of w; words_free skips NULL */
        w->v[k + j] = NULL;
    }
    e->argc = argc;
    return 0;
}

/* Parses one line. Errors are reported without a file name or line number. */
static int parse_line(const struct uinit_ctx *ctx, struct uinit_unit *unit, int lineno,
                      const char *text, char *err, size_t errlen)
{
    struct words w = { NULL, 0, 0 };
    size_t i = 0, k;
    int optional = 0;
    int rc = -1;

    if (tokenize(text, &w, err, errlen) < 0)
        goto out;
    for (k = 0; k < w.n; k++) {
        char *x = expand(ctx, w.v[k], err, errlen);

        if (!x)
            goto out;
        free(w.v[k]);
        w.v[k] = x;
    }
    if (w.n == 0) {
        rc = 0;
        goto out;
    }

    if (!strcmp(w.v[0], "optional")) {
        optional = 1;
        i = 1;
        if (w.n == 1) {
            uinit_seterr(err, errlen, "optional needs a statement after it");
            goto out;
        }
    }

    if (!strcmp(w.v[i], "run") || !strcmp(w.v[i], "import"))
        rc = parse_import(unit, &w, i, lineno, optional, err, errlen);
    else if (!strcmp(w.v[i], "log"))
        rc = parse_log(unit, &w, i, lineno, optional, err, errlen);
    else if (!strcmp(w.v[i], "mount"))
        rc = parse_mount(unit, &w, i, lineno, optional, err, errlen);
    else if (!strcmp(w.v[i], "exec") || !strcmp(w.v[i], "spawn"))
        rc = parse_exec(unit, &w, i, lineno, optional, err, errlen);
    else if (!strcmp(w.v[i], "chmod") || !strcmp(w.v[i], "chown"))
        rc = parse_attr(unit, &w, i, lineno, optional, err, errlen);
    else {
        uinit_seterr(err, errlen, "unknown statement '%s'", w.v[i]);
        rc = -1;
    }

out:
    words_free(&w);
    return rc;
}

void uinit_unit_free(struct uinit_unit *unit)
{
    size_t i, j;

    for (i = 0; i < unit->nstmts; i++) {
        struct uinit_stmt *st = &unit->stmts[i];

        switch (st->op) {
        case UINIT_OP_RUN:
            free(st->u.run_path);
            break;
        case UINIT_OP_LOG:
            free(st->u.log_text);
            break;
        case UINIT_OP_MOUNT:
            free(st->u.mount.src.value);
            free(st->u.mount.src.disk);
            free(st->u.mount.target);
            free(st->u.mount.type);
            free(st->u.mount.data);
            break;
        case UINIT_OP_CHMOD:
        case UINIT_OP_CHOWN:
            free(st->u.attr.path);
            free(st->u.attr.owner);
            free(st->u.attr.group);
            break;
        case UINIT_OP_EXEC:
            free(st->u.exec.user);
            free(st->u.exec.group);
            for (j = 0; j < st->u.exec.ngroups; j++)
                free(st->u.exec.groups[j]);
            free(st->u.exec.groups);
            for (j = 0; j < st->u.exec.argc; j++)
                free(st->u.exec.argv[j]);
            free(st->u.exec.argv);
            break;
        }
    }
    free(unit->stmts);
    free(unit->path);
    memset(unit, 0, sizeof *unit);
}

int uinit_parse_text(const struct uinit_ctx *ctx, const char *path, const char *text,
                     struct uinit_unit *unit, char *err, size_t errlen)
{
    const char *p = text;
    int lineno = 0;

    memset(unit, 0, sizeof *unit);
    unit->path = strdup(path);
    if (!unit->path)
        OOM(err, errlen);

    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char *line = strndup(p, len);
        char msg[UINIT_ERRLEN];

        lineno++;
        if (!line) {
            uinit_seterr(err, errlen, "out of memory");
            uinit_unit_free(unit);
            return -1;
        }
        if (len && line[len - 1] == '\r')
            line[len - 1] = '\0';

        if (parse_line(ctx, unit, lineno, line, msg, sizeof msg) < 0) {
            uinit_seterr(err, errlen, "%s:%d: %s", path, lineno, msg);
            free(line);
            uinit_unit_free(unit);
            return -1;
        }
        free(line);
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

int uinit_parse_file(const struct uinit_ctx *ctx, const char *path,
                     struct uinit_unit *unit, char *err, size_t errlen)
{
    char *full = uinit_path_under(ctx->root, path);
    FILE *f;
    char *buf;
    size_t n;
    int rc;

    if (!full)
        OOM(err, errlen);
    f = fopen(full, "r");
    if (!f) {
        uinit_seterr(err, errlen, "%s: %s", path, strerror(errno));
        free(full);
        return -1;
    }
    free(full);

    buf = malloc(UINIT_MAX_FILE + 1);
    if (!buf) {
        fclose(f);
        OOM(err, errlen);
    }
    n = fread(buf, 1, UINIT_MAX_FILE + 1, f);
    if (ferror(f)) {
        uinit_seterr(err, errlen, "%s: read error", path);
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);
    if (n > UINIT_MAX_FILE) {
        uinit_seterr(err, errlen, "%s: larger than %d bytes", path, UINIT_MAX_FILE);
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    if (memchr(buf, '\0', n)) {
        uinit_seterr(err, errlen, "%s: contains a NUL byte", path);
        free(buf);
        return -1;
    }

    rc = uinit_parse_text(ctx, path, buf, unit, err, errlen);
    free(buf);
    return rc;
}
