/*
 * apprestorecon_main.c - restore the SELinux state of installed apps.
 *
 *   apprestorecon [--root DIR] [-n] [-v] [app...]
 *
 *   --root DIR  Operate on a staging tree under DIR. Default: /.
 *   -n          Dry run: report what would change, change nothing.
 *   -v          Print every relabelled path.
 *   app...      Restore only these apps. Default: every app in /data/app.
 *
 * For each app <name>:
 *   1. Mapping. The SELinux user <name>_u exists and the login <name> maps to
 *      it (pkg_sel_register). Records that are already correct are left alone.
 *      A login that maps to some other SELinux user is reported, not changed.
 *   2. Labels. The app's data tree is relabelled from file_contexts, the same
 *      rules restorecon uses. The rules are matched against device paths, so
 *      /data/app/<name>/... is labelled the same in a staging root.
 *
 * Safety. The per-app parent is root-owned, but system_cache is app-writable;
 * nothing in the tree below it is trusted:
 *   - every directory is opened with O_NOFOLLOW, and every other entry with
 *     O_PATH|O_NOFOLLOW. A symlink is never followed and never relabelled;
 *   - labels are read and written through /proc/self/fd/N, which names the
 *     inode already opened, so a rename or swap after the open does not move
 *     the write somewhere else;
 *   - mount points are not crossed (device must match the app directory);
 *   - traversal stays beneath the opened app directory and never follows
 *     symlinks, so relabeling cannot be redirected outside the app tree.
 *
 * Exit status: 0 if every app was restored, 1 if anything failed.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "urados_pkg.h"

#define LABEL_XATTR     "security.selinux"
#define LABEL_MAX       4096
#define WALK_MAX_DEPTH  64
#define APP_CACHE_NAME PKG_CACHE_DIR

struct opts {
    const pkg_opts *po;
    struct selabel_handle *sh;
    int dry_run;
    int verbose;
};

struct counts {
    unsigned long checked;   /* entries whose label was looked at */
    unsigned long changed;   /* entries whose label differs (or was set) */
    unsigned long unmatched; /* no file_contexts rule for the path */
    unsigned long skipped;   /* symlinks and mount points, not touched */
    unsigned long errors;
};

static void errf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void errf(const char *fmt, ...)
{
    va_list ap;

    fputs("apprestorecon: error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Host path for a device path: "<root><path>". */
static int host_path(char *out, size_t outlen, const char *root, const char *path)
{
    return snprintf(out, outlen, "%s%s", root, path) < (int)outlen ? 0 : -1;
}

/* Reads the label of the inode behind fd into buf. Returns length, or -1. */
static ssize_t read_label(int fd, char *buf, size_t len)
{
    char p[64];
    ssize_t n;

    snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
    n = getxattr(p, LABEL_XATTR, buf, len - 1);
    if (n < 0)
        return -1;
    if (n > 0 && buf[n - 1] == '\0')
        n--;
    buf[n] = '\0';
    return n;
}

/*
 * Relabels the inode behind fd (device path devpath, type mode). Returns 0,
 * or -1 on error, which is counted in c->errors.
 */
static int relabel_fd(const struct opts *o, struct counts *c, int fd,
                      const char *devpath, mode_t mode)
{
    char *want = NULL, cur[LABEL_MAX], p[64];
    int rc = -1;

    if (selabel_lookup_raw(o->sh, &want, devpath, (int)mode) != 0) {
        if (errno == ENOENT) {
            c->unmatched++;
            return 0;
        }
        errf("file_contexts lookup failed for %s: %s", devpath, strerror(errno));
        c->errors++;
        return -1;
    }
    c->checked++;

    if (read_label(fd, cur, sizeof(cur)) >= 0 && strcmp(cur, want) == 0) {
        rc = 0;
        goto out;
    }
    c->changed++;
    if (o->verbose || o->dry_run)
        printf("  %s %s -> %s\n", o->dry_run ? "would relabel" : "relabel", devpath, want);
    if (o->dry_run) {
        rc = 0;
        goto out;
    }
    snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
    if (setxattr(p, LABEL_XATTR, want, strlen(want) + 1, 0) != 0) {
        errf("cannot relabel %s: %s", devpath, strerror(errno));
        c->errors++;
        goto out;
    }
    rc = 0;
out:
    free(want);
    return rc;
}

static int walk_dir(const struct opts *o, struct counts *c, int dirfd,
                    const char *devdir, dev_t dev, int depth);

/* Relabels the entry name (inside the directory dirfd). */
static void walk_entry(const struct opts *o, struct counts *c, int dirfd,
                       const char *name, const char *devdir, dev_t dev, int depth)
{
    char child[PKG_PATH_MAX];
    struct stat st;
    int fd;

    if (snprintf(child, sizeof(child), "%s/%s", devdir, name) >= (int)sizeof(child)) {
        errf("path too long under %s", devdir);
        c->errors++;
        return;
    }
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        errf("cannot stat %s: %s", child, strerror(errno));
        c->errors++;
        return;
    }
    if (S_ISLNK(st.st_mode) || st.st_dev != dev) {
        c->skipped++;
        if (o->verbose)
            printf("  skip %s (%s)\n", child, S_ISLNK(st.st_mode) ? "symlink" : "mount point");
        return;
    }

    if (S_ISDIR(st.st_mode)) {
        fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            errf("cannot open %s: %s", child, strerror(errno));
            c->errors++;
            return;
        }
        /* The entry may have been swapped after fstatat; check the inode we got. */
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_dev != dev) {
            close(fd);
            c->skipped++;
            return;
        }
        relabel_fd(o, c, fd, child, S_IFDIR);
        walk_dir(o, c, fd, child, dev, depth + 1); /* takes ownership of fd */
        return;
    }

    fd = openat(dirfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        errf("cannot open %s: %s", child, strerror(errno));
        c->errors++;
        return;
    }
    if (fstat(fd, &st) != 0 || S_ISLNK(st.st_mode) || st.st_dev != dev) {
        close(fd);
        c->skipped++;
        return;
    }
    relabel_fd(o, c, fd, child, st.st_mode & S_IFMT);
    close(fd);
}

/* Walks the readable directory fd (ownership taken) and relabels its entries. */
static int walk_dir(const struct opts *o, struct counts *c, int fd,
                    const char *devdir, dev_t dev, int depth)
{
    DIR *d;
    struct dirent *e;

    if (depth > WALK_MAX_DEPTH) {
        errf("directory tree too deep under %s", devdir);
        c->errors++;
        close(fd);
        return -1;
    }
    d = fdopendir(fd); /* takes ownership of fd */
    if (!d) {
        errf("cannot read %s: %s", devdir, strerror(errno));
        c->errors++;
        close(fd);
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        walk_entry(o, c, dirfd(d), e->d_name, devdir, dev, depth);
    }
    closedir(d);
    return 0;
}

/* Restores the mapping for app. Returns 0 on success. */
static int restore_mapping(const struct opts *o, const char *app, struct counts *c)
{
    char err[512] = "";
    pkg_sel_status cur;
    pkg_sel_state added;
    char sename[PKG_SEL_USER_MAX];

    if (pkg_sel_name(app, sename, sizeof(sename)) != 0) {
        errf("invalid app name '%s'", app);
        c->errors++;
        return -1;
    }
    if (o->dry_run) {
        if (pkg_sel_query(o->po, app, &cur, err, sizeof(err)) != 0) {
            errf("%s", err);
            c->errors++;
            return -1;
        }
        if (cur.user_exists && cur.login_exists && strcmp(cur.login_sename, sename) == 0) {
            printf("  mapping ok: %s -> %s\n", app, sename);
        } else if (cur.login_exists && strcmp(cur.login_sename, sename) != 0) {
            errf("login '%s' maps to '%s', not '%s'; left unchanged", app, cur.login_sename, sename);
            c->errors++;
            return -1;
        } else {
            printf("  would restore mapping: %s -> %s\n", app, sename);
            c->changed++;
        }
        return 0;
    }
    if (pkg_sel_register(o->po, app, &added, err, sizeof(err)) != 0) {
        errf("%s", err);
        c->errors++;
        return -1;
    }
    if (added.user_added || added.login_added) {
        printf("  mapping restored: %s -> %s\n", app, sename);
        c->changed++;
    } else {
        printf("  mapping ok: %s -> %s\n", app, sename);
    }
    return 0;
}

/* Relabels the whole tree of one app. appdata_fd is /data/app (or its copy). */
static int restore_labels(const struct opts *o, struct counts *c, int appdata_fd,
                          const char *app)
{
    char devapp[PKG_PATH_MAX];
    struct stat st;
    int app_fd, cache_fd = -1, walk_fd = -1, rc = 0;

    snprintf(devapp, sizeof(devapp), "%s/%s", PKG_APPDATA_DIR, app);
    app_fd = openat(appdata_fd, app, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (app_fd < 0) {
        errf("cannot open %s: %s", devapp, strerror(errno));
        c->errors++;
        return -1;
    }
    if (fstat(app_fd, &st) != 0 || st.st_uid != 0) {
        errf("%s is not root-owned; not relabelled", devapp);
        c->errors++;
        close(app_fd);
        return -1;
    }
    /* The app directory itself, then its tree. Its device is the boundary. */
    relabel_fd(o, c, app_fd, devapp, S_IFDIR);
    {
        int dup_fd = dup(app_fd);

        if (dup_fd < 0) {
            c->errors++;
            close(app_fd);
            return -1;
        }
        /* walk_dir closes dup_fd; app_fd stays open for the rest. */
        walk_fd = dup_fd;
    }

    /* system_cache is mutable, but it is beneath the root-owned parent. */
    cache_fd = openat(app_fd, APP_CACHE_NAME, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cache_fd < 0) {
        errf("cannot open %s/%s: %s", devapp, APP_CACHE_NAME, strerror(errno));
        c->errors++;
        rc = -1;
        goto out;
    }
    {
        char devcache[PKG_PATH_MAX * 2];
        int cfd = dup(cache_fd);

        if (snprintf(devcache, sizeof(devcache), "%s/%s", devapp, APP_CACHE_NAME) >=
            (int)sizeof(devcache)) {
            errf("path too long under %s", devapp);
            c->errors++;
            cfd = -1;
        }
        if (cfd >= 0) {
            relabel_fd(o, c, cache_fd, devcache, S_IFDIR);
            walk_dir(o, c, cfd, devcache, st.st_dev, 0);
        } else {
            c->errors++;
        }
    }
    /* The rest of the app's tree, excluding system_cache (already done). */
    {
        DIR *d;
        struct dirent *e;
        int dfd = walk_fd;

        walk_fd = -1;
        d = fdopendir(dfd);
        if (!d) {
            errf("cannot read %s: %s", devapp, strerror(errno));
            c->errors++;
            close(dfd);
            rc = -1;
        } else {
            while ((e = readdir(d)) != NULL) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                    continue;
                if (strcmp(e->d_name, APP_CACHE_NAME) == 0)
                    continue;
                walk_entry(o, c, dirfd(d), e->d_name, devapp, st.st_dev, 0);
            }
            closedir(d);
        }
    }

out:
    if (cache_fd >= 0)
        close(cache_fd);
    if (walk_fd >= 0)
        close(walk_fd);
    close(app_fd);
    return rc;
}

/* Restores one app. Returns 0 on success. */
static int restore_app(const struct opts *o, int appdata_fd, const char *app, struct counts *c)
{
    uid_t uid = 0;
    gid_t gid = 0;
    struct counts before = *c;
    int rc = 0;

    printf("app %s\n", app);
    if (pkg_lookup_passwd(o->po->root, app, &uid, &gid) != 0) {
        errf("no user '%s' in the account database", app);
        c->errors++;
        return -1;
    }
    if (restore_mapping(o, app, c) != 0)
        rc = -1;
    if (restore_labels(o, c, appdata_fd, app) != 0)
        rc = -1;
    printf("  labels: checked %lu, %s %lu, no rule %lu, skipped %lu, errors %lu\n",
           c->checked - before.checked,
           o->dry_run ? "would change" : "changed",
           c->changed - before.changed,
           c->unmatched - before.unmatched,
           c->skipped - before.skipped,
           c->errors - before.errors);
    return rc;
}

static void usage(FILE *f)
{
    fputs("usage: apprestorecon [--root DIR] [-n] [-v] [-h] [app...]\n"
          "  Restores the SELinux user mapping and file labels of installed apps.\n"
          "  -n          dry run: report only\n"
          "  -v          list every path that is relabelled\n"
          "  --root DIR  operate on a staging tree under DIR\n",
          f);
}

int main(int argc, char **argv)
{
    static char rootbuf[PKG_PATH_MAX];
    static char keysbuf[PKG_PATH_MAX];
    static char policy_path[PKG_PATH_MAX * 2];
    static char policy[64];
    static char appdata_host[PKG_PATH_MAX * 2];
    const char *root = "";
    struct selinux_opt sopt[1];
    struct opts o;
    struct counts c;
    pkg_opts po;
    int dry_run = 0, verbose = 0, i = 1, appdata_fd = -1, rc = 0;
    size_t l;

    memset(&c, 0, sizeof(c));
    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            root = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
        i++;
    }

    if (root[0] != '\0' && root[0] != '/') {
        errf("--root must be an absolute path");
        return 2;
    }
    if (strlen(root) >= sizeof(rootbuf)) {
        errf("--root is too long");
        return 2;
    }
    snprintf(rootbuf, sizeof(rootbuf), "%s", root);
    l = strlen(rootbuf);
    while (l > 0 && rootbuf[l - 1] == '/')
        rootbuf[--l] = '\0';
    root = rootbuf;

    if (geteuid() != 0) {
        errf("this command must run as root");
        return 1;
    }
    if (is_selinux_enabled() != 1) {
        errf("SELinux is not enabled on this system");
        return 1;
    }

    snprintf(keysbuf, sizeof(keysbuf), "%s%s", root, PKG_KEYS_SUBDIR);
    po.root = root;
    po.keys_dir = keysbuf;

    if (pkg_sel_policy(root, policy, sizeof(policy)) != 0) {
        errf("cannot read the SELinux policy type from %s/etc/selinux/config", root);
        return 1;
    }
    snprintf(policy_path, sizeof(policy_path), "%s/etc/selinux/%s/contexts/files/file_contexts",
             root, policy);
    sopt[0].type = SELABEL_OPT_PATH;
    sopt[0].value = policy_path;
    o.sh = selabel_open(SELABEL_CTX_FILE, sopt, 1);
    if (!o.sh) {
        errf("cannot load file contexts from %s: %s", policy_path, strerror(errno));
        return 1;
    }
    o.po = &po;
    o.dry_run = dry_run;
    o.verbose = verbose;

    if (host_path(appdata_host, sizeof(appdata_host), root, PKG_APPDATA_DIR) != 0) {
        errf("path too long");
        rc = 1;
        goto out;
    }
    appdata_fd = open(appdata_host, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (appdata_fd < 0) {
        errf("cannot open %s: %s", PKG_APPDATA_DIR, strerror(errno));
        rc = 1;
        goto out;
    }

    if (i < argc) {
        for (; i < argc; i++) {
            if (!pkg_name_valid(argv[i])) {
                errf("invalid app name '%s'", argv[i]);
                c.errors++;
                continue;
            }
            restore_app(&o, appdata_fd, argv[i], &c);
        }
    } else {
        DIR *d = NULL;
        struct dirent *e;
        int dup_fd = dup(appdata_fd);

        if (dup_fd >= 0)
            d = fdopendir(dup_fd);
        if (!d) {
            errf("cannot list %s: %s", PKG_APPDATA_DIR, strerror(errno));
            if (dup_fd >= 0)
                close(dup_fd);
            c.errors++;
        } else {
            while ((e = readdir(d)) != NULL) {
                struct stat st;

                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                    continue;
                if (!pkg_name_valid(e->d_name)) {
                    errf("skipping %s/%s: not an app name", PKG_APPDATA_DIR, e->d_name);
                    c.errors++;
                    continue;
                }
                if (fstatat(appdata_fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !S_ISDIR(st.st_mode)) {
                    errf("skipping %s/%s: not a directory", PKG_APPDATA_DIR, e->d_name);
                    c.errors++;
                    continue;
                }
                restore_app(&o, appdata_fd, e->d_name, &c);
            }
            closedir(d);
        }
    }

    printf("%s: checked %lu, %s %lu, no rule %lu, skipped %lu, errors %lu\n",
           dry_run ? "dry run" : "done", c.checked,
           dry_run ? "would change" : "changed", c.changed,
           c.unmatched, c.skipped, c.errors);
    if (c.errors)
        rc = 1;

out:
    if (appdata_fd >= 0)
        close(appdata_fd);
    selabel_close(o.sh);
    return rc;
}
