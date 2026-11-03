/*
 * install.c - urpkg commands: install, start, verify.
 *
 * install  Verify a certificate-signed package, create its app identity and
 *          separate data/cache directories, then extract its initial code.
 * start    Verify the root-owned package copy, refresh package code and run it.
 * verify   Check a package file against trusted X.509 CA certificates.
 *
 * start verifies /data/app_progs/<name>.zip rather than anything under
 * /data/app/<name>/system_cache. The separate root-owned data subtree is
 * writable by its app UID through ACLs; the mutable code cache is writable and
 * executable by the app but is not trusted as signed package content.
 * system_cache/user remains mutable across starts.
 *
 * Failed installs are rolled back: the account, trusted copy and protected app
 * tree are removed, so a failed install leaves no partial installation.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/fs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "urados_pkg.h"

#define APP_DIR_MODE   0710  /* root:users; app users can traverse, not list */
#define APPS_ROOT_MODE 0711  /* /data/app: traverse only */
#define APP_DATA_MODE  0770  /* root:users; ACL gives app RWX, group ACL is empty */
#define CACHE_MODE     02730 /* root:users; ACL gives owning app WX, root RWX */
#define CODE_MODE      02770 /* root:users; ACL gives owning app RWX */
#define CODE_DIR       "app"
#define APP_UID_MIN    10000 /* app uids below this could collide with real logins */
#define LOCKS_DIR      ".locks"

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

/* Opens and exclusively locks the root-only lock file for one app name. */
static int lock_app_at(int locks_fd, const char *name)
{
    char lock_name[PKG_NAME_MAX + 16];
    struct stat st;
    int fd;

    if (snprintf(lock_name, sizeof(lock_name), "app-%s.lock", name) >=
        (int)sizeof(lock_name)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = openat(locks_fd, lock_name,
                O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    if (fchown(fd, 0, 0) != 0 || fchmod(fd, 0600) != 0 || flock(fd, LOCK_EX) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (st.st_gid != 0 || (st.st_mode & 07777) != 0600) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

/* Creates a randomized sibling directory for a fully verified package extract. */
static int create_code_staging_dir(int cache_fd, uid_t uid, gid_t gid,
                                   char *name, size_t namelen)
{
    char path[128];
    const char *base;
    int fd;

    if (snprintf(path, sizeof(path), "/proc/self/fd/%d/.urpkg-new-XXXXXX", cache_fd) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!mkdtemp(path))
        return -1;
    base = strrchr(path, '/') + 1;
    if (strlen(base) >= namelen) {
        unlinkat(cache_fd, base, AT_REMOVEDIR);
        errno = ENAMETOOLONG;
        return -1;
    }
    snprintf(name, namelen, "%s", base);
    fd = openat(cache_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fchown(fd, 0, gid) != 0 || fchmod(fd, CODE_MODE) != 0 ||
        pkg_set_app_uid_acl(fd, uid, 1) != 0) {
        int saved = errno;
        if (fd >= 0)
            close(fd);
        pkg_rm_entry_at(cache_fd, name, 0);
        errno = saved;
        return -1;
    }
    return fd;
}

/* Atomically publishes the extracted tree, preserving the old tree on failure. */
static int publish_code_staging_dir(int cache_fd, const char *staging_name)
{
    int exchanged = 0, i;

    for (i = 0; i < 4; i++) {
        if (renameat2(cache_fd, staging_name, cache_fd, CODE_DIR, RENAME_EXCHANGE) == 0) {
            exchanged = 1;
            break;
        }
        if (errno == ENOENT) {
            if (renameat2(cache_fd, staging_name, cache_fd, CODE_DIR, RENAME_NOREPLACE) == 0)
                break;
            if (errno == EEXIST)
                continue;
        }
        return -1;
    }
    if (i == 4) {
        errno = EBUSY;
        return -1;
    }
    /* After exchange, staging_name is the old tree; cleanup is best effort. */
    if (exchanged)
        pkg_rm_entry_at(cache_fd, staging_name, 0);
    return 0;
}

/* Runs a shadow-utils tool against the root prefix (-R when root is set). */
static int run_acct(const pkg_opts *o, const char *tool, const char *const *args, size_t nargs)
{
    char *argv[PKG_ARGS_MAX];
    size_t n = 0, i;

    argv[n++] = (char *)tool;
    if (o->root[0] != '\0') {
        /* -P (prefix), not -R (chroot): -R fails in staging trees. */
        argv[n++] = "-P";
        argv[n++] = (char *)o->root;
    }
    for (i = 0; i < nargs && n < PKG_ARGS_MAX - 1; i++)
        argv[n++] = (char *)args[i];
    argv[n] = NULL;
    return pkg_run(argv);
}

/* App names identify users; the shared users group is not per-app. */
static int account_exists(const pkg_opts *o, const char *name)
{
    uid_t u;
    gid_t g;

    return pkg_lookup_passwd(o->root, name, &u, &g) == 0;
}

/* Creates exactly one app account with the shared global primary group. */
static int create_account(const pkg_opts *o, const char *name, const char *home)
{
    /* App ids come from 10000+ so they never collide with real logins. */
    const char *u[] = { "-K", "UID_MIN=10000", "-K", "UID_MAX=59999",
                        "-M", "-N", "-d", home, "-s", "/usr/sbin/nologin",
                        "-g", PKG_APP_GROUP, name };

    if (run_acct(o, "/usr/sbin/useradd", u, sizeof(u) / sizeof(u[0])) != 0) {
        msg_err("useradd %s failed", name);
        return -1;
    }
    return 0;
}

static void remove_account(const pkg_opts *o, const char *name)
{
    const char *a[] = { name };

    run_acct(o, "/usr/sbin/userdel", a, 1);
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
    char archive_name[PKG_NAME_MAX + sizeof(PKG_ARCHIVE_SUFFIX)];
    char *trusted_zip = NULL;
    char name[PKG_NAME_MAX + 1] = "";
    char home[PKG_PATH_MAX];
    const char *stage_name = NULL;
    pkg_verified v;
    struct stat st;
    int data_fd = -1, progs_fd = -1, locks_fd = -1, stage_fd = -1, app_lock_fd = -1;
    int appdata_fd = -1, app_fd = -1, app_data_fd = -1, cache_fd = -1;
    int code_fd = -1, user_code_fd = -1;
    int staged = 0, trusted_copy_made = 0, acct_made = 0, app_made = 0;
    int tfd, rc = 1;
    uid_t uid = 0, pgid = 0;
    gid_t usersgid = 0;
    pkg_sel_state sel;

    memset(&v, 0, sizeof(v));
    memset(&sel, 0, sizeof(sel));
    archive_name[0] = '\0';
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
    locks_fd = ensure_root_dir(progs_fd, LOCKS_DIR, 0700);
    if (locks_fd < 0) {
        msg_err("cannot prepare the per-app lock directory: %s", strerror(errno));
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
    snprintf(archive_name, sizeof(archive_name), "%s%s", name, PKG_ARCHIVE_SUFFIX);

    app_lock_fd = lock_app_at(locks_fd, name);
    if (app_lock_fd < 0) {
        msg_err("cannot lock app '%s' for installation: %s", name, strerror(errno));
        goto out;
    }
    if (fstatat(progs_fd, archive_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        msg_err("'%s' is already installed", name);
        goto out;
    }
    if (errno != ENOENT) {
        msg_err("cannot check for an existing package '%s': %s", name, strerror(errno));
        goto out;
    }
    if (fstatat(appdata_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        msg_err("%s/%s already exists", PKG_APPDATA_DIR, name);
        goto out;
    }
    if (account_exists(o, name)) {
        msg_err("a user named '%s' already exists", name);
        goto out;
    }
    if (pkg_lookup_group(o->root, PKG_APP_GROUP, &usersgid) != 0) {
        msg_err("group '%s' does not exist", PKG_APP_GROUP);
        goto out;
    }

    /* 1. Root-owned trusted copy: /data/app_progs/<name>.zip. */
    if (linkat(stage_fd, stage_name, progs_fd, archive_name, 0) != 0) {
        msg_err("cannot reserve trusted package path: %s", strerror(errno));
        goto out;
    }
    trusted_copy_made = 1;
    if (unlinkat(stage_fd, stage_name, 0) != 0) {
        msg_err("cannot remove the staged package link: %s", strerror(errno));
        goto out;
    }
    staged = 0;
    if (fchownat(progs_fd, archive_name, 0, 0, AT_SYMLINK_NOFOLLOW) != 0 ||
        fchmodat(progs_fd, archive_name, 0600, 0) != 0) {
        msg_err("cannot secure the trusted copy: %s", strerror(errno));
        goto out;
    }

    /* 2. Account: the home is writable data, not the protected app parent. */
    snprintf(home, sizeof(home), "%s/%s/%s", PKG_APPDATA_DIR, name,
             PKG_APP_DATA_SUBDIR);
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
    /*
     * 3. SELinux: SELinux user <name>_u, and the login <name> mapped to it.
     * On failure pkg_sel_register undoes its own partial work. The rollback
     * below undoes the rest, using the record of what was added.
     */
    if (pkg_sel_register(o, name, &sel, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }

    /* 4. Protect the app parent so the app cannot replace system_cache. */
    app_made = 1;
    app_fd = pkg_open_subdir(appdata_fd, name, APP_DIR_MODE, 0, usersgid);
    if (app_fd < 0) {
        msg_err("cannot create %s: %s", home, strerror(errno));
        goto out;
    }
    app_data_fd = pkg_open_subdir(app_fd, PKG_APP_DATA_SUBDIR, APP_DATA_MODE, 0, usersgid);
    if (app_data_fd < 0 || fchown(app_data_fd, 0, usersgid) != 0 ||
        fchmod(app_data_fd, APP_DATA_MODE) != 0 || pkg_set_app_uid_acl(app_data_fd, uid, 1) != 0) {
        msg_err("cannot create app data directory %s: %s", home, strerror(errno));
        goto out;
    }
    cache_fd = pkg_open_subdir(app_fd, PKG_CACHE_DIR, CACHE_MODE, 0, usersgid);
    if (cache_fd < 0 || fchown(cache_fd, 0, usersgid) != 0 ||
        fchmod(cache_fd, CACHE_MODE) != 0 || pkg_set_app_uid_acl(cache_fd, uid, 0) != 0) {
        msg_err("cannot create %s/%s: %s", home, PKG_CACHE_DIR, strerror(errno));
        goto out;
    }
    code_fd = pkg_open_subdir(cache_fd, CODE_DIR, CODE_MODE, 0, usersgid);
    user_code_fd = pkg_open_subdir(cache_fd, PKG_CACHE_USER_DIR, CODE_MODE, 0, usersgid);
    if (code_fd < 0 || user_code_fd < 0 || fchown(code_fd, 0, usersgid) != 0 ||
        fchmod(code_fd, CODE_MODE) != 0 || pkg_set_app_uid_acl(code_fd, uid, 1) != 0 ||
        fchown(user_code_fd, 0, usersgid) != 0 || fchmod(user_code_fd, CODE_MODE) != 0 ||
        pkg_set_app_uid_acl(user_code_fd, uid, 1) != 0) {
        msg_err("cannot prepare writable program directories under %s/%s: %s",
                home, PKG_CACHE_DIR, strerror(errno));
        goto out;
    }
    if (asprintf(&trusted_zip, "%s/%s", progs_path, archive_name) < 0) {
        trusted_zip = NULL;
        msg_err("out of memory building trusted package path");
        goto out;
    }
    if (pkg_extract(trusted_zip, code_fd, usersgid, &v, err, sizeof(err)) != 0) {
        msg_err("cannot extract the verified package: %s", err);
        goto out;
    }

    printf("installed %s %s: app user '%s' (uid %u), SELinux user '%s_u', data in %s\n",
           v.manifest.name, v.manifest.version, name, (unsigned)uid, name, home);
    rc = 0;

out:
    if (rc != 0) {
        char uerr[512] = "";

        if (app_made)
            pkg_rm_entry_at(appdata_fd, name, 0);
        if (trusted_copy_made)
            unlinkat(progs_fd, archive_name, 0);
        if (acct_made) {
            if (pkg_sel_unregister(o, name, &sel, uerr, sizeof(uerr)) != 0)
                msg_err("%s", uerr);
            remove_account(o, name);
        }
    }
    if (staged && stage_fd >= 0)
        unlinkat(stage_fd, stage_name, 0);
    pkg_verified_free(&v);
    if (app_lock_fd >= 0) close(app_lock_fd);
    if (user_code_fd >= 0) close(user_code_fd);
    if (code_fd >= 0) close(code_fd);
    if (cache_fd >= 0) close(cache_fd);
    if (app_data_fd >= 0) close(app_data_fd);
    if (app_fd >= 0) close(app_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (stage_fd >= 0) close(stage_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    free(trusted_zip);
    return rc;
}

/* Runs an app under its account. Production uses the SELinux-transitioning
 * helper; --root staging runs keep the direct path for E2E tests. */
static int run_entry(const pkg_opts *o, const char *name, uid_t uid, gid_t gid,
                     const char *entry, int argc, char **argv)
{
    char home[PKG_PATH_MAX], path[PKG_PATH_MAX], seluser[PKG_SEL_USER_MAX];
    char uidbuf[32], gidbuf[32], countbuf[32], groupbuf[PKG_GROUPS_MAX][32];
    char userenv[PKG_NAME_MAX + 8], homeenv[PKG_PATH_MAX + 8];
    char *app_argv[PKG_ARGS_MAX + 2], *run_argv[PKG_GROUPS_MAX + PKG_ARGS_MAX + 12];
    char *envp[] = { "PATH=" PKG_USER_UTILS, userenv, homeenv, "LANG=C", NULL };
    gid_t groups[PKG_GROUPS_MAX];
    size_t ngroups = 0, i;
    int n = 0, rn = 0, status = 0;
    pid_t pid;

    if (argc > PKG_ARGS_MAX) {
        msg_err("too many arguments (max %d)", PKG_ARGS_MAX);
        return -1;
    }
    /* App processes receive exactly their shared primary users group; do not
     * inherit unrelated supplementary groups from host account configuration. */
    groups[0] = gid;
    ngroups = 1;
    if (pkg_sel_name(name, seluser, sizeof(seluser)) != 0) {
        msg_err("cannot construct SELinux user for '%s'", name);
        return -1;
    }
    snprintf(home, sizeof(home), "%s/%s/%s", PKG_APPDATA_DIR, name,
             PKG_APP_DATA_SUBDIR);
    snprintf(path, sizeof(path), "%s/%s/%s", PKG_APPDATA_DIR, name, entry);
    snprintf(userenv, sizeof(userenv), "USER=%s", name);
    snprintf(homeenv, sizeof(homeenv), "HOME=%s", home);
    app_argv[n++] = path;
    for (i = 0; i < (size_t)argc; i++)
        app_argv[n++] = argv[i];
    app_argv[n] = NULL;

    if (o->root[0] != '\0') {
        /* Staging chroots have no active Urados SELinux policy; this path is
         * used only by the integration test's synthetic root. */
        pid = fork();
        if (pid < 0) {
            msg_err("fork failed: %s", strerror(errno));
            return -1;
        }
        if (pid == 0) {
            if (chroot(o->root) != 0 || chdir(home) != 0 ||
                setgroups(ngroups, groups) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
                _exit(125);
            if (setuid(0) == 0)
                _exit(125);
            umask(0077);
            execve(path, app_argv, envp);
            _exit(127);
        }
    } else {
        snprintf(uidbuf, sizeof(uidbuf), "%lu", (unsigned long)uid);
        snprintf(gidbuf, sizeof(gidbuf), "%lu", (unsigned long)gid);
        snprintf(countbuf, sizeof(countbuf), "%lu", (unsigned long)ngroups);
        run_argv[rn++] = PKG_RUNNER_PATH;
        run_argv[rn++] = uidbuf;
        run_argv[rn++] = gidbuf;
        run_argv[rn++] = countbuf;
        for (i = 0; i < ngroups; i++) {
            snprintf(groupbuf[i], sizeof(groupbuf[i]), "%lu", (unsigned long)groups[i]);
            run_argv[rn++] = groupbuf[i];
        }
        run_argv[rn++] = seluser;
        run_argv[rn++] = home;
        run_argv[rn++] = path;
        for (i = 0; i < (size_t)argc; i++)
            run_argv[rn++] = argv[i];
        run_argv[rn] = NULL;
        pid = fork();
        if (pid < 0) {
            msg_err("fork failed: %s", strerror(errno));
            return -1;
        }
        if (pid == 0) {
            execv(PKG_RUNNER_PATH, run_argv);
            _exit(127);
        }
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
            msg_err("could not establish the confined app context for '%s'", name);
        else if (code == 127)
            msg_err("cannot execute %s", entry);
        return code;
    }
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

int pkg_cmd_start(const char *name, int argc, char **argv, const pkg_opts *o)
{
    char err[512] = "";
    char archive_name[PKG_NAME_MAX + sizeof(PKG_ARCHIVE_SUFFIX)];
    char zip_fd_path[64], code_tmp_name[64] = "";
    pkg_verified v;
    struct stat st;
    int data_fd = -1, progs_fd = -1, locks_fd = -1, lock_fd = -1;
    int appdata_fd = -1, app_fd = -1, app_data_fd = -1, cache_fd = -1;
    int code_fd = -1, zip_fd = -1, code_tmp_created = 0;
    int rc = 1;
    uid_t uid = 0, pgid = 0;
    gid_t usersgid = 0;

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
    snprintf(archive_name, sizeof(archive_name), "%s%s", name, PKG_ARCHIVE_SUFFIX);
    data_fd = open_data_root(o);
    if (data_fd < 0) {
        msg_err("cannot open the data directory: %s", strerror(errno));
        goto out;
    }
    progs_fd = open_owned_at(data_fd, "app_progs", 0);
    if (progs_fd < 0 || fstat(progs_fd, &st) != 0 || st.st_gid != 0 ||
        (st.st_mode & 07777) != 0700) {
        msg_err("%s is missing or has unsafe ownership/permissions", PKG_PROGS_DIR);
        goto out;
    }
    locks_fd = open_owned_at(progs_fd, LOCKS_DIR, 0);
    if (locks_fd < 0 || fstat(locks_fd, &st) != 0 || st.st_gid != 0 ||
        (st.st_mode & 07777) != 0700) {
        msg_err("per-app lock directory is missing or unsafe");
        goto out;
    }
    lock_fd = lock_app_at(locks_fd, name);
    if (lock_fd < 0) {
        msg_err("cannot lock app '%s' for start: %s", name, strerror(errno));
        goto out;
    }

    /* Open the archive without following symlinks and verify through this FD. */
    zip_fd = openat(progs_fd, archive_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (zip_fd < 0 || fstat(zip_fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_gid != 0 || (st.st_mode & 07777) != 0600) {
        msg_err("trusted archive is missing or has unsafe ownership/permissions");
        goto out;
    }
    if (snprintf(zip_fd_path, sizeof(zip_fd_path), "/proc/self/fd/%d", zip_fd) >=
        (int)sizeof(zip_fd_path)) {
        msg_err("cannot construct pinned trusted archive path");
        goto out;
    }
    if (pkg_verify(zip_fd_path, o->keys_dir, &v, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }
    if (strcmp(v.manifest.name, name) != 0) {
        msg_err("the trusted copy is for '%s', not '%s'", v.manifest.name, name);
        goto out;
    }

    /* 2. Validate the root-protected parent and the distinct app data home. */
    appdata_fd = open_dir_at(data_fd, "app");
    if (appdata_fd < 0) {
        msg_err("cannot open %s%s", o->root, PKG_APPDATA_DIR);
        goto out;
    }
    app_fd = open_owned_at(appdata_fd, name, 0);
    if (app_fd < 0) {
        msg_err("%s/%s is missing or not root-owned", PKG_APPDATA_DIR, name);
        goto out;
    }
    if (fstat(app_fd, &st) != 0 || st.st_gid != usersgid ||
        (st.st_mode & 07777) != APP_DIR_MODE) {
        msg_err("%s/%s has unsafe ownership or permissions", PKG_APPDATA_DIR, name);
        goto out;
    }
    app_data_fd = open_owned_at(app_fd, PKG_APP_DATA_SUBDIR, 0);
    if (app_data_fd < 0 || fstat(app_data_fd, &st) != 0 || st.st_gid != usersgid ||
        (st.st_mode & 07777) != APP_DATA_MODE) {
        msg_err("%s/%s/%s has unsafe ownership or permissions",
                PKG_APPDATA_DIR, name, PKG_APP_DATA_SUBDIR);
        goto out;
    }
    cache_fd = open_owned_at(app_fd, PKG_CACHE_DIR, 0);
    if (cache_fd < 0) {
        msg_err("%s/%s/%s is missing or not owned by root", PKG_APPDATA_DIR, name, PKG_CACHE_DIR);
        goto out;
    }
    if (fstat(cache_fd, &st) != 0 || st.st_gid != usersgid ||
        (st.st_mode & 07777) != CACHE_MODE) {
        msg_err("%s/%s/%s has unsafe ownership or permissions",
                PKG_APPDATA_DIR, name, PKG_CACHE_DIR);
        goto out;
    }

    /* 3. Extract into a hidden sibling, then atomically publish the complete
     * verified tree. Failed extraction leaves the prior tree untouched. */
    code_fd = create_code_staging_dir(cache_fd, uid, usersgid,
                                      code_tmp_name, sizeof(code_tmp_name));
    if (code_fd < 0) {
        msg_err("cannot create package-code staging directory: %s", strerror(errno));
        goto out;
    }
    code_tmp_created = 1;
    if (pkg_extract(zip_fd_path, code_fd, usersgid, &v, err, sizeof(err)) != 0) {
        msg_err("cannot extract the verified package: %s", err);
        goto out;
    }
    close(code_fd);
    code_fd = -1;
    if (publish_code_staging_dir(cache_fd, code_tmp_name) != 0) {
        msg_err("cannot atomically publish the refreshed package code: %s", strerror(errno));
        goto out;
    }
    code_tmp_created = 0;

    /* 4. Run the manifest entry only after the signed payload is extracted. */
    rc = run_entry(o, name, uid, usersgid, v.manifest.entry, argc, argv);
    if (rc < 0)
        rc = 1;

out:
    if (code_fd >= 0) close(code_fd);
    if (code_tmp_created && cache_fd >= 0)
        pkg_rm_entry_at(cache_fd, code_tmp_name, 0);
    if (zip_fd >= 0) close(zip_fd);
    if (lock_fd >= 0) close(lock_fd);
    if (cache_fd >= 0) close(cache_fd);
    if (app_data_fd >= 0) close(app_data_fd);
    if (app_fd >= 0) close(app_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    pkg_verified_free(&v);
    return rc;
}
