/*
 * install.c - urpkg commands: install, start, verify.
 *
 * install  Verify a package, then create its app user, private group,
 *          root-owned trusted copy in /data/app_progs/<name>/, and the app
 *          data directory /data/app/<name>/ with system_cache/ locked.
 * start    Verify the trusted copy, rebuild system_cache/app from it, and run
 *          the entry point as the app user from /data/app/<name>.
 * verify   Check a package file against the trusted keys.
 *
 * start verifies /data/app_progs/<name>/package.zip rather than anything under
 * /data/app/<name>. The app user owns that directory, so files there are not
 * trustworthy.
 *
 * Failed installs are rolled back: the account, trusted copy and app data
 * directory are removed, so a failed install leaves nothing behind.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/fs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "urados_pkg.h"

#define APP_DIR_MODE   0700  /* /data/app/<name>: owned by the app user */
#define APPS_ROOT_MODE 0711  /* /data/app: traverse only */
#define CACHE_MODE     0711  /* system_cache: root-owned, traverse only */
#define CODE_MODE      0110  /* system_cache/app: root:<name>, traverse + execute only */
#define CODE_DIR       "app"
#define APP_UID_MIN    10000 /* app uids below this could collide with real logins */

static void msg_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void msg_err(const char *fmt, ...)
{
    va_list ap;

    fputs("urpkg: error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Host path for a device path: "<root><path>". */
static void rooted(char *out, size_t outlen, const pkg_opts *o, const char *path)
{
    snprintf(out, outlen, "%s%s", o->root, path);
}

static int require_root(void)
{
    if (geteuid() != 0) {
        msg_err("this command must run as root");
        return -1;
    }
    return 0;
}

static int open_dir_at(int base, const char *name)
{
    return openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

/* Opens base/name as a directory that must be owned by owner (no symlinks). */
static int open_owned_at(int base, const char *name, uid_t owner)
{
    struct stat st;
    int fd = open_dir_at(base, name);

    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != owner) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

/* Opens <root>/data, creating it (root:root 0755) only if it is missing. */
static int open_data_root(const pkg_opts *o)
{
    char p[PKG_PATH_MAX];
    int fd;

    rooted(p, sizeof(p), o, PKG_DATA_DIR);
    fd = open(p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        if (mkdir(p, 0755) != 0)
            return -1;
        fd = open(p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0 && (fchown(fd, 0, 0) != 0 || fchmod(fd, 0755) != 0)) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

/* Opens base/name as a root-owned directory, creating it with mode if needed. */
static int ensure_root_dir(int base, const char *name, mode_t mode)
{
    int fd = pkg_open_subdir(base, name, mode, 0, 0);

    if (fd < 0)
        return -1;
    if (fchown(fd, 0, 0) != 0 || fchmod(fd, mode) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Runs a shadow-utils tool against the root prefix (-R when root is set). */
static int run_acct(const pkg_opts *o, const char *tool, const char *const *args, size_t nargs)
{
    char *argv[PKG_ARGS_MAX];
    size_t n = 0, i;

    argv[n++] = (char *)tool;
    if (o->root[0] != '\0') {
        argv[n++] = "-R";
        argv[n++] = (char *)o->root;
    }
    for (i = 0; i < nargs && n < PKG_ARGS_MAX - 1; i++)
        argv[n++] = (char *)args[i];
    argv[n] = NULL;
    return pkg_run(argv);
}

/* True if a user or group called name already exists in the root. */
static int account_exists(const pkg_opts *o, const char *name)
{
    uid_t u;
    gid_t g;

    return pkg_lookup_passwd(o->root, name, &u, &g) == 0 ||
           pkg_lookup_group(o->root, name, &g) == 0;
}

/*
 * Creates the app's private group <name> and user <name>. The primary group is
 * 'users'. The user is also a member of its private group, which is what gives
 * it read access to system_cache/app.
 */
static int create_account(const pkg_opts *o, const char *name, const char *home)
{
    /* App ids come from 10000+ so they never collide with real logins. */
    const char *g[] = { "-K", "GID_MIN=10000", "-K", "GID_MAX=59999", name };
    const char *gd[] = { name };
    const char *u[] = { "-K", "UID_MIN=10000", "-K", "UID_MAX=59999",
                        "-M", "-N", "-d", home, "-s", "/usr/sbin/nologin",
                        "-g", PKG_APP_GROUP, "-G", name, name };

    if (run_acct(o, "/usr/sbin/groupadd", g, sizeof(g) / sizeof(g[0])) != 0) {
        msg_err("groupadd %s failed", name);
        return -1;
    }
    if (run_acct(o, "/usr/sbin/useradd", u, sizeof(u) / sizeof(u[0])) != 0) {
        msg_err("useradd %s failed", name);
        run_acct(o, "/usr/sbin/groupdel", gd, 1);
        return -1;
    }
    return 0;
}

static void remove_account(const pkg_opts *o, const char *name)
{
    const char *a[] = { name };

    run_acct(o, "/usr/sbin/userdel", a, 1);
    run_acct(o, "/usr/sbin/groupdel", a, 1);
}

/*
 * Sets (locked = 1) or clears (locked = 0) the immutable flag on
 * <name>/system_cache inside appdata_fd. Returns 0 on success.
 */
static int set_cache_lock(int appdata_fd, const char *name, int locked)
{
    int app = open_dir_at(appdata_fd, name);
    int cache = -1, rc = -1;

    if (app < 0)
        return -1;
    cache = open_owned_at(app, PKG_CACHE_DIR, 0);
    if (cache >= 0)
        rc = pkg_set_immutable_fd(cache, locked);
    if (cache >= 0)
        close(cache);
    close(app);
    return rc;
}

int pkg_cmd_verify(const char *zip, const pkg_opts *o)
{
    char err[512] = "";
    pkg_verified v;

    memset(&v, 0, sizeof(v));
    if (pkg_verify(zip, o->keys_dir, &v, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        return 1;
    }
    printf("OK %s %s, entry %s, %zu files\n", v.manifest.name, v.manifest.version,
           v.manifest.entry, v.ndigests);
    pkg_verified_free(&v);
    return 0;
}

int pkg_cmd_install(const char *source, const pkg_opts *o)
{
    char err[512] = "";
    char progs_path[PKG_PATH_MAX];
    char stage_tmpl[PKG_PATH_MAX * 2];
    char name[PKG_NAME_MAX + 1] = "";
    char home[PKG_PATH_MAX];
    const char *stage_name = NULL;
    pkg_verified v;
    struct stat st;
    int data_fd = -1, progs_fd = -1, stage_fd = -1, pkgdir_fd = -1;
    int appdata_fd = -1, app_fd = -1, cache_fd = -1;
    int staged = 0, pkgdir_made = 0, acct_made = 0, app_made = 0;
    int tfd, rc = 1;
    uid_t uid = 0, pgid = 0;
    gid_t usersgid = 0;

    memset(&v, 0, sizeof(v));
    if (require_root() != 0)
        return 1;

    rooted(progs_path, sizeof(progs_path), o, PKG_PROGS_DIR);

    data_fd = open_data_root(o);
    if (data_fd < 0) {
        msg_err("cannot open data directory: %s", strerror(errno));
        goto out;
    }
    progs_fd = ensure_root_dir(data_fd, "app_progs", 0700);
    if (progs_fd < 0) {
        msg_err("cannot prepare %s: %s", PKG_PROGS_DIR, strerror(errno));
        goto out;
    }
    stage_fd = ensure_root_dir(progs_fd, PKG_STAGING_DIR, 0700);
    if (stage_fd < 0) {
        msg_err("cannot prepare the staging area: %s", strerror(errno));
        goto out;
    }
    appdata_fd = ensure_root_dir(data_fd, "app", APPS_ROOT_MODE);
    if (appdata_fd < 0) {
        msg_err("cannot prepare %s: %s", PKG_APPDATA_DIR, strerror(errno));
        goto out;
    }

    /* Copy the source into a private staging file, then verify that copy. */
    snprintf(stage_tmpl, sizeof(stage_tmpl), "%s/%s/incoming-XXXXXX", progs_path, PKG_STAGING_DIR);
    tfd = mkstemp(stage_tmpl);
    if (tfd < 0) {
        msg_err("cannot create a staging file: %s", strerror(errno));
        goto out;
    }
    staged = 1;
    stage_name = strrchr(stage_tmpl, '/') + 1;
    if (pkg_fetch(source, tfd, PKG_ARCHIVE_MAX, err, sizeof(err)) != 0 || fsync(tfd) != 0) {
        msg_err("%s", err[0] ? err : "cannot store the package");
        close(tfd);
        goto out;
    }
    close(tfd);

    if (pkg_verify(stage_tmpl, o->keys_dir, &v, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }
    snprintf(name, sizeof(name), "%s", v.manifest.name);

    if (fstatat(progs_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        msg_err("'%s' is already installed", name);
        goto out;
    }
    if (fstatat(appdata_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        msg_err("%s/%s already exists", PKG_APPDATA_DIR, name);
        goto out;
    }
    if (account_exists(o, name)) {
        msg_err("a user or group named '%s' already exists", name);
        goto out;
    }
    if (pkg_lookup_group(o->root, PKG_APP_GROUP, &usersgid) != 0) {
        msg_err("group '%s' does not exist", PKG_APP_GROUP);
        goto out;
    }

    /* 1. Root-owned trusted copy: /data/app_progs/<name>/package.zip. */
    if (mkdirat(progs_fd, name, 0700) != 0) {
        msg_err("cannot create %s/%s: %s", PKG_PROGS_DIR, name, strerror(errno));
        goto out;
    }
    pkgdir_made = 1;
    pkgdir_fd = open_dir_at(progs_fd, name);
    if (pkgdir_fd < 0 || fchown(pkgdir_fd, 0, 0) != 0 || fchmod(pkgdir_fd, 0700) != 0) {
        msg_err("cannot secure %s/%s", PKG_PROGS_DIR, name);
        goto out;
    }
    if (renameat(stage_fd, stage_name, pkgdir_fd, PKG_ARCHIVE_FILE) != 0) {
        msg_err("cannot store the package: %s", strerror(errno));
        goto out;
    }
    staged = 0;
    if (fchownat(pkgdir_fd, PKG_ARCHIVE_FILE, 0, 0, AT_SYMLINK_NOFOLLOW) != 0 ||
        fchmodat(pkgdir_fd, PKG_ARCHIVE_FILE, 0600, 0) != 0) {
        msg_err("cannot secure the trusted copy: %s", strerror(errno));
        goto out;
    }

    /* 2. Account: user <name>, primary group 'users', private group <name>. */
    snprintf(home, sizeof(home), "%s/%s", PKG_APPDATA_DIR, name);
    if (create_account(o, name, home) != 0)
        goto out;
    acct_made = 1;
    if (pkg_lookup_passwd(o->root, name, &uid, &pgid) != 0 || pgid != usersgid) {
        msg_err("new user '%s' does not have primary group '%s'", name, PKG_APP_GROUP);
        goto out;
    }
    if (uid < APP_UID_MIN) {
        msg_err("app user '%s' got uid %u, below %d; set UID_MIN in login.defs",
                name, (unsigned)uid, APP_UID_MIN);
        goto out;
    }

    /* 3. App data: /data/app/<name> owned by the app user, group 'users'. */
    app_made = 1;
    app_fd = pkg_open_subdir(appdata_fd, name, APP_DIR_MODE, uid, usersgid);
    if (app_fd < 0) {
        msg_err("cannot create %s: %s", home, strerror(errno));
        goto out;
    }
    cache_fd = pkg_open_subdir(app_fd, PKG_CACHE_DIR, CACHE_MODE, 0, 0);
    if (cache_fd < 0 || fchown(cache_fd, 0, 0) != 0 || fchmod(cache_fd, CACHE_MODE) != 0) {
        msg_err("cannot create %s/%s", home, PKG_CACHE_DIR);
        goto out;
    }
    if (pkg_set_immutable_fd(cache_fd, 1) != 0) {
        msg_err("cannot lock %s/%s: %s", home, PKG_CACHE_DIR, strerror(errno));
        goto out;
    }

    printf("installed %s %s: app user '%s' (uid %u), data in %s\n",
           v.manifest.name, v.manifest.version, name, (unsigned)uid, home);
    rc = 0;

out:
    if (rc != 0) {
        if (app_made) {
            set_cache_lock(appdata_fd, name, 0);
            pkg_rm_entry_at(appdata_fd, name, 0);
        }
        if (pkgdir_made)
            pkg_rm_entry_at(progs_fd, name, 0);
        if (acct_made)
            remove_account(o, name);
    }
    if (staged && stage_fd >= 0)
        unlinkat(stage_fd, stage_name, 0);
    pkg_verified_free(&v);
    if (cache_fd >= 0) close(cache_fd);
    if (app_fd >= 0) close(app_fd);
    if (pkgdir_fd >= 0) close(pkgdir_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (stage_fd >= 0) close(stage_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    return rc;
}

/*
 * Runs the entry point as the app user and returns its exit status.
 * Group membership is read on the host, before chroot, so no NSS modules are
 * needed inside the app's root.
 */
static int run_entry(const pkg_opts *o, const char *name, uid_t uid, gid_t gid,
                     const char *entry, int argc, char **argv)
{
    char home[PKG_PATH_MAX], path[PKG_PATH_MAX];
    char userenv[PKG_NAME_MAX + 8], homeenv[PKG_PATH_MAX + 8];
    char *cargv[PKG_ARGS_MAX + 2];
    char *envp[5];
    gid_t groups[PKG_GROUPS_MAX];
    size_t ngroups = 0, i;
    int n = 0, status = 0;
    pid_t pid;

    if (argc > PKG_ARGS_MAX) {
        msg_err("too many arguments (max %d)", PKG_ARGS_MAX);
        return -1;
    }
    if (pkg_supp_groups(o->root, name, gid, groups, PKG_GROUPS_MAX, &ngroups) != 0) {
        msg_err("cannot read the group list for '%s'", name);
        return -1;
    }

    snprintf(home, sizeof(home), "%s/%s", PKG_APPDATA_DIR, name);
    snprintf(path, sizeof(path), "./%s", entry);
    snprintf(userenv, sizeof(userenv), "USER=%s", name);
    snprintf(homeenv, sizeof(homeenv), "HOME=%s", home);
    cargv[n++] = path;
    for (i = 0; i < (size_t)argc; i++)
        cargv[n++] = argv[i];
    cargv[n] = NULL;
    envp[0] = "PATH=/usr/bin:/bin";
    envp[1] = userenv;
    envp[2] = homeenv;
    envp[3] = "LANG=C";
    envp[4] = NULL;

    pid = fork();
    if (pid < 0) {
        msg_err("fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        if (o->root[0] != '\0' && chroot(o->root) != 0)
            _exit(125);
        if (chdir(home) != 0)
            _exit(125);
        if (setgroups(ngroups, groups) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
            _exit(125);
        if (setuid(0) == 0)   /* the app must not be able to get root back */
            _exit(125);
        umask(0077);
        execve(path, cargv, envp);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            msg_err("waitpid failed: %s", strerror(errno));
            return -1;
        }
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);

        if (code == 125)
            msg_err("could not switch to app user '%s'", name);
        else if (code == 127)
            msg_err("cannot execute %s", entry);
        return code;
    }
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

int pkg_cmd_start(const char *name, int argc, char **argv, const pkg_opts *o)
{
    char err[512] = "";
    char zip[PKG_PATH_MAX];
    pkg_verified v;
    struct stat st;
    int data_fd = -1, appdata_fd = -1, app_fd = -1, cache_fd = -1, code_fd = -1;
    int unlocked = 0, rc = 1;
    uid_t uid = 0, pgid = 0;
    gid_t usersgid = 0, codegid = 0;

    memset(&v, 0, sizeof(v));
    if (require_root() != 0)
        return 1;
    if (!pkg_name_valid(name)) {
        msg_err("invalid package name '%s'", name);
        return 1;
    }
    if (pkg_lookup_passwd(o->root, name, &uid, &pgid) != 0) {
        msg_err("no app user '%s': install the package first", name);
        return 1;
    }
    if (pkg_lookup_group(o->root, PKG_APP_GROUP, &usersgid) != 0 || pgid != usersgid) {
        msg_err("app user '%s' is not in group '%s'", name, PKG_APP_GROUP);
        return 1;
    }
    if (pkg_lookup_group(o->root, name, &codegid) != 0) {
        msg_err("private group '%s' is missing", name);
        return 1;
    }

    /* 1. Verify the root-owned trusted copy, never the app's own files. */
    snprintf(zip, sizeof(zip), "%s%s/%s/%s", o->root, PKG_PROGS_DIR, name, PKG_ARCHIVE_FILE);
    if (pkg_verify(zip, o->keys_dir, &v, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }
    if (strcmp(v.manifest.name, name) != 0) {
        msg_err("the trusted copy is for '%s', not '%s'", v.manifest.name, name);
        goto out;
    }

    /* 2. Enter /data/app/<name>, which must belong to the app user. */
    data_fd = open_data_root(o);
    if (data_fd < 0) {
        msg_err("cannot open the data directory: %s", strerror(errno));
        goto out;
    }
    appdata_fd = open_dir_at(data_fd, "app");
    if (appdata_fd < 0) {
        msg_err("cannot open %s%s", o->root, PKG_APPDATA_DIR);
        goto out;
    }
    app_fd = open_owned_at(appdata_fd, name, uid);
    if (app_fd < 0) {
        msg_err("%s/%s is missing or not owned by its app user", PKG_APPDATA_DIR, name);
        goto out;
    }
    cache_fd = open_owned_at(app_fd, PKG_CACHE_DIR, 0);
    if (cache_fd < 0) {
        msg_err("%s/%s/%s is missing or not owned by root", PKG_APPDATA_DIR, name, PKG_CACHE_DIR);
        goto out;
    }

    /* 3. Rebuild system_cache/app from the verified package. */
    if (pkg_set_immutable_fd(cache_fd, 0) != 0) {
        msg_err("cannot unlock %s: %s", PKG_CACHE_DIR, strerror(errno));
        goto out;
    }
    unlocked = 1;
    if (fstatat(cache_fd, CODE_DIR, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        pkg_rm_entry_at(cache_fd, CODE_DIR, 0) != 0) {
        msg_err("cannot clear the old code: %s", strerror(errno));
        goto out;
    }
    code_fd = pkg_open_subdir(cache_fd, CODE_DIR, CODE_MODE, 0, codegid);
    if (code_fd < 0 || fchown(code_fd, 0, codegid) != 0 || fchmod(code_fd, CODE_MODE) != 0) {
        msg_err("cannot create %s/%s/%s/%s: %s", PKG_APPDATA_DIR, name, PKG_CACHE_DIR, CODE_DIR,
                strerror(errno));
        goto out;
    }
    if (pkg_extract(zip, code_fd, codegid, &v, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }
    close(code_fd);
    code_fd = -1;
    if (pkg_set_immutable_fd(cache_fd, 1) != 0) {
        msg_err("cannot lock %s again: %s", PKG_CACHE_DIR, strerror(errno));
        goto out;
    }
    unlocked = 0;

    /* 4. Run the entry point as the app user. */
    rc = run_entry(o, name, uid, usersgid, v.manifest.entry, argc, argv);
    if (rc < 0)
        rc = 1;

out:
    if (code_fd >= 0)
        close(code_fd);
    if (unlocked && cache_fd >= 0) {
        /* Partial code must not stay runnable: remove it and relock. */
        pkg_rm_entry_at(cache_fd, CODE_DIR, 0);
        pkg_set_immutable_fd(cache_fd, 1);
    }
    if (cache_fd >= 0) close(cache_fd);
    if (app_fd >= 0) close(app_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (data_fd >= 0) close(data_fd);
    pkg_verified_free(&v);
    return rc;
}
