/*
 * attr.c - chmod and chown for files under the root.
 *
 * Paths are resolved under ctx->root, as mount targets are. The last path
 * component is never followed: a chmod target that is a symbolic link is an
 * error, and chown changes the link itself (like chown -h). Symbolic links in
 * the directories above the last component are followed by the kernel as usual.
 * During -R, chmod leaves links alone and chown changes each link itself. The
 * walk uses lstat() and path names, so it is not safe against another writer
 * changing the tree at the same time. uinit runs these during boot.
 */
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "uinit.h"

#define WALK_MAX_DEPTH 256
#define ID_MAX         4294967294UL /* (uid_t)-1 and (gid_t)-1 mean "unchanged" */

/* Returns 1 and the value if s is a number, 0 if it is a name, -1 if it is a number out of range. */
static int numeric_id(const char *s, unsigned long *out)
{
    unsigned long v;
    char *end;

    if (!*s || strspn(s, "0123456789") != strlen(s))
        return 0;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || *end || v > ID_MAX)
        return -1;
    *out = v;
    return 1;
}

int uinit_lookup_uid(const char *s, uid_t *out, char *err, size_t errlen)
{
    unsigned long v;
    struct passwd *pw;
    int n = numeric_id(s, &v);

    if (n > 0) {
        *out = (uid_t)v;
        return 0;
    }
    if (n < 0) {
        uinit_seterr(err, errlen, "user id '%s' is out of range", s);
        return -1;
    }
    pw = getpwnam(s);
    if (!pw) {
        uinit_seterr(err, errlen, "no such user '%s'", s);
        return -1;
    }
    *out = pw->pw_uid;
    return 0;
}

int uinit_lookup_gid(const char *s, gid_t *out, char *err, size_t errlen)
{
    unsigned long v;
    struct group *gr;
    int n = numeric_id(s, &v);

    if (n > 0) {
        *out = (gid_t)v;
        return 0;
    }
    if (n < 0) {
        uinit_seterr(err, errlen, "group id '%s' is out of range", s);
        return -1;
    }
    gr = getgrnam(s);
    if (!gr) {
        uinit_seterr(err, errlen, "no such group '%s'", s);
        return -1;
    }
    *out = gr->gr_gid;
    return 0;
}

/* What one walk step changes. Only the fields for chmod or chown are used. */
struct change {
    int is_chown;
    mode_t mode;
    int conditional_exec;
    int have_uid;
    uid_t uid;
    int have_gid;
    gid_t gid;
    size_t rootlen;                  /* messages show paths without the root */
};

/* Applies the change to one entry. st is the entry's lstat() result. */
static int change_one(const struct change *c, const char *path, const struct stat *st,
                      char *err, size_t errlen)
{
    if (c->is_chown) {
        if (lchown(path, c->have_uid ? c->uid : (uid_t)-1,
                   c->have_gid ? c->gid : (gid_t)-1) < 0) {
            uinit_seterr(err, errlen, "chown %s: %s", path + c->rootlen, strerror(errno));
            return -1;
        }
        return 0;
    }
    /* A link has no mode of its own, and chmod would follow it. Leave it alone. */
    if (S_ISLNK(st->st_mode))
        return 0;
    if (c->conditional_exec) {
        mode_t mode = st->st_mode & 07777;

        if (S_ISDIR(st->st_mode) || (mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
            mode |= S_IXUSR | S_IXGRP | S_IXOTH;
        if (chmod(path, mode) < 0) {
            uinit_seterr(err, errlen, "chmod %s: %s", path + c->rootlen, strerror(errno));
            return -1;
        }
    } else if (chmod(path, c->mode) < 0) {
        uinit_seterr(err, errlen, "chmod %s: %s", path + c->rootlen, strerror(errno));
        return -1;
    }
    return 0;
}

/* Applies the change to path and, when recursive, to everything below it. */
static int walk(const struct change *c, const char *path, int recursive, int depth,
                char *err, size_t errlen)
{
    struct stat st;
    DIR *d;
    struct dirent *de;
    int rc = 0;

    if (lstat(path, &st) < 0) {
        uinit_seterr(err, errlen, "%s: %s", path + c->rootlen, strerror(errno));
        return -1;
    }
    if (depth == 0 && !c->is_chown && S_ISLNK(st.st_mode)) {
        uinit_seterr(err, errlen, "%s is a symbolic link; chmod does not follow links",
                     path + c->rootlen);
        return -1;
    }
    if (change_one(c, path, &st, err, errlen) < 0)
        return -1;
    if (!recursive || !S_ISDIR(st.st_mode))
        return 0;
    if (depth >= WALK_MAX_DEPTH) {
        uinit_seterr(err, errlen, "%s: directories nested deeper than %d",
                     path + c->rootlen, WALK_MAX_DEPTH);
        return -1;
    }

    d = opendir(path);
    if (!d) {
        uinit_seterr(err, errlen, "%s: %s", path + c->rootlen, strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        size_t pl = strlen(path), nl = strlen(de->d_name);
        char *child;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        child = malloc(pl + nl + 2);
        if (!child) {
            uinit_seterr(err, errlen, "out of memory");
            rc = -1;
            break;
        }
        memcpy(child, path, pl);
        child[pl] = '/';
        memcpy(child + pl + 1, de->d_name, nl + 1);
        rc = walk(c, child, recursive, depth + 1, err, errlen);
        free(child);
        if (rc < 0)
            break;
    }
    closedir(d);
    return rc;
}

static int run_change(const struct uinit_ctx *ctx, const struct uinit_attr *a,
                      struct change *c, char *err, size_t errlen)
{
    char *target = uinit_path_under(ctx->root, a->path);
    int rc;

    if (!target) {
        uinit_seterr(err, errlen, "out of memory");
        return -1;
    }
    c->rootlen = strlen(ctx->root);
    rc = walk(c, target, a->recursive, 0, err, errlen);
    free(target);
    return rc;
}

int uinit_do_chmod(const struct uinit_ctx *ctx, const struct uinit_attr *a,
                   char *err, size_t errlen)
{
    struct change c;

    memset(&c, 0, sizeof c);
    c.mode = a->mode;
    c.conditional_exec = a->conditional_exec;
    return run_change(ctx, a, &c, err, errlen);
}

/* The group of a user's login account, used for "user:" with no group. */
static int login_gid(uid_t uid, const char *owner, gid_t *out, char *err, size_t errlen)
{
    struct passwd *pw = getpwuid(uid);

    if (!pw) {
        uinit_seterr(err, errlen, "user %s has no passwd entry; give a group too", owner);
        return -1;
    }
    *out = pw->pw_gid;
    return 0;
}

int uinit_do_chown(const struct uinit_ctx *ctx, const struct uinit_attr *a,
                   char *err, size_t errlen)
{
    struct change c;

    memset(&c, 0, sizeof c);
    c.is_chown = 1;
    if (a->owner) {
        if (uinit_lookup_uid(a->owner, &c.uid, err, errlen) < 0)
            return -1;
        c.have_uid = 1;
    }
    if (a->group) {
        if (uinit_lookup_gid(a->group, &c.gid, err, errlen) < 0)
            return -1;
        c.have_gid = 1;
    } else if (a->login_group) {
        if (!c.have_uid || login_gid(c.uid, a->owner, &c.gid, err, errlen) < 0)
            return -1;
        c.have_gid = 1;
    }
    return run_change(ctx, a, &c, err, errlen);
}
