/*
 * install.c - urpkg commands: install, start, verify, stop, update, uninstall.
 *
 * install    Verify a certificate-signed package, create its app identity and
 *            private data home, and store the trusted archive.
 * start      Verify the root-owned package copy, extract it under /run/app and run it.
 * verify     Check a package file against trusted X.509 CA certificates.
 * stop       Terminate every process the app is running, escalating to SIGKILL.
 * update     Replace an installed app with a newer package from the same publisher.
 * uninstall  Stop the app, then remove its account, runtime, package and data.
 *
 * start verifies /data/app_progs/<name>.zip, then extracts a new runtime tree
 * under /run/app/<name> and executes its verified manifest entry. Persistent
 * state lives only in the app-UID-owned /data/app/<name>/data directory.
 *
 * Failed installs are rolled back: the account, trusted copy and protected app
 * tree are removed, so a failed install leaves no partial installation.
 *
 * Stopping: `start` holds the per-app lock while its app runs. stop, update and
 * uninstall therefore signal the app first and then take the lock, which is
 * only granted once no process of the app UID remains in the target root.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "urados_pkg.h"

#define DATA_ROOT_MODE 0711  /* root:root; traverse-only, no directory listing */
#define APP_DIR_MODE   0710  /* root:users; app users can traverse, not list */
#define APPS_ROOT_MODE 0711  /* /data/app: traverse only */
#define APP_DATA_MODE  0700  /* app UID:root; no group or other access */
#define RUN_ROOT_MODE  0711  /* root:root; runtime parent, traverse only */
#define RUNTIME_MODE   0570  /* app UID:root; owner r-x, root group rwx */
#define PKG_BUSYBOX    "/bin/busybox"
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

/* Opens <root>/data, creating it as root:root DATA_ROOT_MODE if it is missing.
 * Existing mounts keep their group/mode but must be root-owned and not writable
 * by group or others. */
static int open_data_root(const pkg_opts *o, int create)
{
    char p[PKG_PATH_MAX];
    struct stat st;
    int fd;

    rooted(p, sizeof(p), o, PKG_DATA_DIR);
    fd = open(p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && create) {
        if (mkdir(p, DATA_ROOT_MODE) != 0)
            return -1;
        fd = open(p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0 && (fchown(fd, 0, 0) != 0 || fchmod(fd, DATA_ROOT_MODE) != 0)) {
            close(fd);
            return -1;
        }
    }
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0) {
        close(fd);
        errno = EPERM;
        return -1;
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

/* Opens the init-managed /run/app directory without creating or chmodding it. */
static int open_runtime_root(const pkg_opts *o)
{
    const char *root = o->root[0] ? o->root : "/";
    struct stat st;
    int root_fd = -1, run_fd = -1, app_fd = -1;

    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0)
        return -1;
    run_fd = openat(root_fd, "run", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (run_fd < 0 || fstat(run_fd, &st) != 0 || st.st_uid != 0 || st.st_gid != 0 ||
        (st.st_mode & S_IXOTH) == 0 || (st.st_mode & 0022) != 0) {
        if (run_fd >= 0) close(run_fd);
        close(root_fd);
        errno = EPERM;
        return -1;
    }
    app_fd = openat(run_fd, "app", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (app_fd >= 0 &&
        (fstat(app_fd, &st) != 0 || st.st_uid != 0 || st.st_gid != 0 ||
         (st.st_mode & 07777) != RUN_ROOT_MODE)) {
        close(app_fd);
        app_fd = -1;
        errno = EPERM;
    }
    close(run_fd);
    close(root_fd);
    return app_fd;
}

/* Opens the root-only lock file for one app name and applies lock_op (flock). */
static int open_app_lock(int locks_fd, const char *name, int setup_permissions, int lock_op)
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
                O_RDWR | (setup_permissions ? O_CREAT : 0) |
                O_NOFOLLOW | O_CLOEXEC, 0600);
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
    if (setup_permissions && (fchown(fd, 0, 0) != 0 || fchmod(fd, 0600) != 0)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (!setup_permissions &&
        (st.st_gid != 0 || (st.st_mode & 07777) != 0600)) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    if (flock(fd, lock_op) != 0) {
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

/* Opens and exclusively (blocking) locks the per-app lock file. */
static int lock_app_at(int locks_fd, const char *name, int setup_permissions)
{
    return open_app_lock(locks_fd, name, setup_permissions, LOCK_EX);
}

/* Creates a randomized sibling directory for a fully verified runtime extract. */
static int create_runtime_staging_dir(int runtime_fd, uid_t uid, gid_t gid,
                                      char *name, size_t namelen)
{
    char path[128];
    const char *base;
    int fd;

    if (snprintf(path, sizeof(path), "/proc/self/fd/%d/.urpkg-new-XXXXXX", runtime_fd) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!mkdtemp(path))
        return -1;
    base = strrchr(path, '/') + 1;
    if (strlen(base) >= namelen) {
        unlinkat(runtime_fd, base, AT_REMOVEDIR);
        errno = ENAMETOOLONG;
        return -1;
    }
    snprintf(name, namelen, "%s", base);
    fd = openat(runtime_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fchown(fd, uid, gid) != 0 || fchmod(fd, RUNTIME_MODE) != 0) {
        int saved = errno;
        if (fd >= 0)
            close(fd);
        pkg_rm_entry_at(runtime_fd, name, 0);
        errno = saved;
        return -1;
    }
    return fd;
}

/* Atomically publishes the extracted tree, preserving the old tree on failure. */
static int publish_code_staging_dir(int runtime_fd, const char *staging_name,
                                    const char *target_name)
{
    int exchanged = 0, i;

    for (i = 0; i < 4; i++) {
        if (renameat2(runtime_fd, staging_name, runtime_fd, target_name, RENAME_EXCHANGE) == 0) {
            exchanged = 1;
            break;
        }
        if (errno == ENOENT) {
            if (renameat2(runtime_fd, staging_name, runtime_fd, target_name, RENAME_NOREPLACE) == 0)
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
        pkg_rm_entry_at(runtime_fd, staging_name, 0);
    return 0;
}

/* Runs a shadow-utils tool against an explicit staging root for tests only. */
static int run_stage_acct(const pkg_opts *o, const char *tool,
                          const char *const *args, size_t nargs)
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

/* Runs a BusyBox account applet on the live device. */
static int run_busybox_acct(const char *applet,
                            const char *const *args, size_t nargs)
{
    char *argv[PKG_ARGS_MAX];
    size_t n = 0, i;

    if (nargs > PKG_ARGS_MAX - 3) {
        errno = E2BIG;
        return -1;
    }
    argv[n++] = PKG_BUSYBOX;
    argv[n++] = (char *)applet;
    for (i = 0; i < nargs; i++)
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
    if (o->root[0] != '\0') {
        /* Staged test roots use host shadow-utils from PATH; BusyBox has no prefix mode. */
        const char *u[] = { "-M", "-N", "-d", home, "-s", "/urados/sbin/nologin",
                            "-g", PKG_APP_GROUP, name };

        if (run_stage_acct(o, "useradd", u,
                           sizeof(u) / sizeof(u[0])) != 0) {
            msg_err("staged useradd %s failed", name);
            return -1;
        }
        return 0;
    }

    /* BusyBox uses -G for the primary group and -h/-s for passwd fields. */
    {
        const char *u[] = { "-D", "-H", "-h", home, "-s", "/urados/sbin/nologin",
                            "-G", PKG_APP_GROUP, name };

        if (run_busybox_acct("adduser", u, sizeof(u) / sizeof(u[0])) != 0) {
            msg_err("BusyBox adduser %s failed", name);
            return -1;
        }
    }
    return 0;
}

static void remove_account(const pkg_opts *o, const char *name)
{
    const char *a[] = { name };

    if (o->root[0] != '\0') {
        run_stage_acct(o, "userdel", a, 1);
    } else if (run_busybox_acct("deluser", a, 1) != 0) {
        msg_err("BusyBox deluser %s failed during install rollback", name);
    }
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
    char name[PKG_NAME_MAX + 1] = "";
    char home[PKG_PATH_MAX];
    const char *stage_name = NULL;
    pkg_verified v;
    struct stat st;
    int data_fd = -1, progs_fd = -1, locks_fd = -1, stage_fd = -1, app_lock_fd = -1;
    int appdata_fd = -1, app_fd = -1, app_data_fd = -1;
    int staged = 0, trusted_copy_made = 0, acct_made = 0, app_made = 0;
    int tfd, rc = 1;
    uid_t uid = 0, pgid = 0;
    gid_t usersgid = 0;

    memset(&v, 0, sizeof(v));
    archive_name[0] = '\0';
    if (require_root() != 0)
        return 1;

    rooted(progs_path, sizeof(progs_path), o, PKG_PROGS_DIR);

    data_fd = open_data_root(o, 1);
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

    app_lock_fd = lock_app_at(locks_fd, name, 1);
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
    /* 3. Protect the app parent; the app owns only its private data home. */
    app_made = 1;
    app_fd = pkg_open_subdir(appdata_fd, name, APP_DIR_MODE, 0, usersgid);
    if (app_fd < 0) {
        msg_err("cannot create %s: %s", home, strerror(errno));
        goto out;
    }
    app_data_fd = pkg_open_subdir(app_fd, PKG_APP_DATA_SUBDIR, APP_DATA_MODE, uid, 0);
    if (app_data_fd < 0 || fchown(app_data_fd, uid, 0) != 0 ||
        fchmod(app_data_fd, APP_DATA_MODE) != 0) {
        msg_err("cannot create app data directory %s: %s", home, strerror(errno));
        goto out;
    }

    printf("installed %s %s: app user '%s' (uid %u), data in %s\n",
           v.manifest.name, v.manifest.version, name, (unsigned)uid, home);
    rc = 0;

out:
    if (rc != 0) {
        if (app_made)
            pkg_rm_entry_at(appdata_fd, name, 0);
        if (trusted_copy_made)
            unlinkat(progs_fd, archive_name, 0);
        if (acct_made)
            remove_account(o, name);
    }
    if (staged && stage_fd >= 0)
        unlinkat(stage_fd, stage_name, 0);
    pkg_verified_free(&v);
    if (app_lock_fd >= 0) close(app_lock_fd);
    if (app_data_fd >= 0) close(app_data_fd);
    if (app_fd >= 0) close(app_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (stage_fd >= 0) close(stage_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    return rc;
}

/*
 * Runs an app under its own account. The forked child is the only process that
 * holds root, and it gives that up irreversibly before exec:
 *   1. --root staging only: chroot into the staging tree;
 *   2. supplementary groups = {users}, then setgid, then setuid;
 *   3. confirm root cannot be regained;
 *   4. set no_new_privs, so setuid/setgid binaries cannot raise privilege;
 *   5. enter the app data home, clear the environment, exec the verified
 *      package entry under /run/app/<name>.
 * no_new_privs is a plain kernel flag; no MAC policy is involved.
 */
static int run_entry(const pkg_opts *o, const char *name, uid_t uid, gid_t gid,
                     const char *entry, int argc, char **argv)
{
    char home[PKG_PATH_MAX], path[PKG_PATH_MAX];
    char userenv[PKG_NAME_MAX + 8], homeenv[PKG_PATH_MAX + 8];
    char *app_argv[PKG_ARGS_MAX + 2];
    char *envp[] = { "PATH=" PKG_USER_UTILS, userenv, homeenv, "LANG=C", NULL };
    gid_t groups[1];
    int n = 0, i, status = 0;
    pid_t pid;

    if (argc > PKG_ARGS_MAX) {
        msg_err("too many arguments (max %d)", PKG_ARGS_MAX);
        return -1;
    }
    /* The app process gets exactly its shared users group, nothing else from
     * host account configuration. */
    groups[0] = gid;
    snprintf(home, sizeof(home), "%s/%s/%s", PKG_APPDATA_DIR, name, PKG_APP_DATA_SUBDIR);
    snprintf(path, sizeof(path), "%s/%s/%s", PKG_RUN_DIR, name,
             entry + strlen(PKG_ENTRY_PREFIX));
    snprintf(userenv, sizeof(userenv), "USER=%s", name);
    snprintf(homeenv, sizeof(homeenv), "HOME=%s", home);
    app_argv[n++] = path;
    for (i = 0; i < argc; i++)
        app_argv[n++] = argv[i];
    app_argv[n] = NULL;

    pid = fork();
    if (pid < 0) {
        msg_err("fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        if ((o->root[0] != '\0' && chroot(o->root) != 0) ||
            setgroups(1, groups) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
            _exit(125);
        /* Root must be unrecoverable: setuid(0) has to fail. */
        if (setuid(0) == 0)
            _exit(125);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(125);
        if (chdir(home) != 0)
            _exit(125);
        umask(0077);
        execve(path, app_argv, envp);
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
            msg_err("could not switch '%s' to its app account or confine it", name);
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
    int appdata_fd = -1, app_fd = -1, app_data_fd = -1, runtime_fd = -1;
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
    data_fd = open_data_root(o, 0);
    if (data_fd < 0) {
        msg_err("cannot open the data directory (must be root-owned and not writable by group/others): %s",
                strerror(errno));
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
    lock_fd = lock_app_at(locks_fd, name, 0);
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

    /* 2. Validate the protected parent and UID-owned private data home. */
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
    app_data_fd = open_owned_at(app_fd, PKG_APP_DATA_SUBDIR, uid);
    if (app_data_fd < 0 || fstat(app_data_fd, &st) != 0 || st.st_gid != 0 ||
        (st.st_mode & 07777) != APP_DATA_MODE) {
        msg_err("%s/%s/%s has unsafe ownership or permissions",
                PKG_APPDATA_DIR, name, PKG_APP_DATA_SUBDIR);
        goto out;
    }
    runtime_fd = open_runtime_root(o);
    if (runtime_fd < 0) {
        msg_err("cannot open init-managed %s (expected root:root mode 0711): %s",
                PKG_RUN_DIR, strerror(errno));
        goto out;
    }

    /* 3. Extract into a hidden sibling, then atomically publish the complete
     * verified tree as /run/app/<name>. Failed extraction leaves the prior tree intact. */
    code_fd = create_runtime_staging_dir(runtime_fd, uid, 0,
                                         code_tmp_name, sizeof(code_tmp_name));
    if (code_fd < 0) {
        msg_err("cannot create runtime staging directory: %s", strerror(errno));
        goto out;
    }
    code_tmp_created = 1;
    if (pkg_extract(zip_fd_path, code_fd, uid, 0, &v, err, sizeof(err)) != 0) {
        msg_err("cannot extract the verified package to %s: %s", PKG_RUN_DIR, err);
        goto out;
    }
    close(code_fd);
    code_fd = -1;
    if (publish_code_staging_dir(runtime_fd, code_tmp_name, name) != 0) {
        msg_err("cannot atomically publish the runtime tree: %s", strerror(errno));
        goto out;
    }
    code_tmp_created = 0;

    /* 4. Run the manifest entry only after signature and payload verification. */
    rc = run_entry(o, name, uid, usersgid, v.manifest.entry, argc, argv);
    if (rc < 0)
        rc = 1;

out:
    if (code_fd >= 0) close(code_fd);
    if (code_tmp_created && runtime_fd >= 0)
        pkg_rm_entry_at(runtime_fd, code_tmp_name, 0);
    if (zip_fd >= 0) close(zip_fd);
    if (lock_fd >= 0) close(lock_fd);
    if (runtime_fd >= 0) close(runtime_fd);
    if (app_data_fd >= 0) close(app_data_fd);
    if (app_fd >= 0) close(app_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    pkg_verified_free(&v);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* stop, update and uninstall                                               */
/* ------------------------------------------------------------------------ */

#define STOP_POLL_US       50000 /* poll interval while waiting for processes to exit */
#define STOP_HARD_EXTRA_MS 10000 /* extra wait past the grace period, for SIGKILL */

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * 1 when the app account exists (uid is stored), 0 when it does not, -1 when
 * the name maps to uid 0. Root is never an app, so stop and uninstall must not
 * ever signal root's processes.
 */
static int find_app_uid(const pkg_opts *o, const char *name, uid_t *uid)
{
    gid_t gid = 0;

    if (pkg_lookup_passwd(o->root, name, uid, &gid) != 0)
        return 0;
    if (*uid == 0) {
        msg_err("'%s' maps to uid 0 and is not an app account", name);
        return -1;
    }
    return 1;
}

/*
 * True when pid runs with the app's real UID, is not a zombie, and lives inside
 * the target root. The UID test keeps signals on this app's processes only; the
 * root test keeps staged runs from touching processes of other roots.
 */
static int proc_is_app_process(pid_t pid, uid_t uid, const struct stat *rootst)
{
    char path[64], line[256];
    unsigned long ruid = 0;
    int have_uid = 0;
    char state = '?';
    struct stat st;
    FILE *f;

    if (uid == (uid_t)-1)
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            ruid = strtoul(line + 4, NULL, 10);
            have_uid = 1;
        } else if (strncmp(line, "State:", 6) == 0) {
            const char *p = line + 6;

            while (*p == ' ' || *p == '\t')
                p++;
            state = *p;
        }
    }
    fclose(f);
    if (!have_uid || ruid != (unsigned long)uid || state == 'Z' || state == 'X')
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/root", (long)pid);
    if (stat(path, &st) != 0)
        return 0;
    return st.st_dev == rootst->st_dev && st.st_ino == rootst->st_ino;
}

/*
 * Sends sig to every app process in the target root (sig 0 only counts them).
 * *count, when given, receives the number of live app processes seen.
 */
static int signal_app_processes(const pkg_opts *o, uid_t uid, int sig, int *count)
{
    struct stat rootst;
    DIR *d;
    struct dirent *e;
    pid_t self = getpid();
    int n = 0, failed = 0;

    if (stat(o->root[0] != '\0' ? o->root : "/", &rootst) != 0)
        return -1;
    d = opendir("/proc");
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL) {
        unsigned long v;
        char *end = NULL;
        pid_t pid;

        if (e->d_name[0] < '1' || e->d_name[0] > '9')
            continue;
        errno = 0;
        v = strtoul(e->d_name, &end, 10);
        if (errno != 0 || *end != '\0' || v > INT_MAX)
            continue;
        pid = (pid_t)v;
        if (pid == self || !proc_is_app_process(pid, uid, &rootst))
            continue;
        n++;
        if (sig > 0 && kill(pid, sig) != 0 && errno != ESRCH)
            failed = 1;
    }
    closedir(d);
    if (count)
        *count = n;
    return failed ? -1 : 0;
}

/*
 * Stops every process of an app and holds its per-app lock while none remain.
 *
 * `start` keeps the lock for as long as its app runs, so the lock can only be
 * taken after the app and every process it left behind have gone. Each round:
 * try the lock without blocking, count the app's processes, send SIGTERM once,
 * and send SIGKILL after the grace period (or at once with force). On success
 * *lock_fd is the held lock, or -1 when the app has no lock file.
 */
static int stop_app(const pkg_opts *o, const pkg_stop_opts *so, const char *name,
                    uid_t uid, int locks_fd, int *lock_fd, int *running)
{
    long long start = now_ms(), term_at = 0;
    int term_sent = 0, lock_missing = 0, count = 0;

    *lock_fd = -1;
    *running = 0;
    if (locks_fd < 0)
        lock_missing = 1;
    for (;;) {
        long long now = now_ms();

        if (*lock_fd < 0 && !lock_missing) {
            int fd = open_app_lock(locks_fd, name, 0, LOCK_EX | LOCK_NB);

            if (fd >= 0)
                *lock_fd = fd;
            else if (errno == ENOENT)
                lock_missing = 1;
            else if (errno != EWOULDBLOCK) {
                msg_err("cannot lock app '%s': %s", name, strerror(errno));
                break;
            }
        }
        if (signal_app_processes(o, uid, 0, &count) != 0) {
            msg_err("cannot list the processes of '%s'", name);
            break;
        }
        if (count > 0)
            *running = 1;
        if (count == 0 && (*lock_fd >= 0 || lock_missing))
            return 0;
        if (count > 0) {
            if (so->force || (term_sent && now - term_at >= so->timeout_ms)) {
                if (signal_app_processes(o, uid, SIGKILL, NULL) != 0) {
                    msg_err("cannot signal the processes of '%s'", name);
                    break;
                }
            } else if (!term_sent) {
                if (signal_app_processes(o, uid, SIGTERM, NULL) != 0) {
                    msg_err("cannot signal the processes of '%s'", name);
                    break;
                }
                term_sent = 1;
                term_at = now;
            }
        }
        if (now - start > (long long)so->timeout_ms + STOP_HARD_EXTRA_MS) {
            if (count == 0)
                msg_err("'%s' is busy: another urpkg operation holds its lock", name);
            else
                msg_err("'%s' did not stop: %d process(es) remain", name, count);
            break;
        }
        usleep(STOP_POLL_US);
    }
    if (*lock_fd >= 0) {
        close(*lock_fd);
        *lock_fd = -1;
    }
    return -1;
}

/* Opens base/name as a directory owned by owner. *fd is -1 when it is absent. */
static int open_optional_owned_at(int base, const char *name, uid_t owner, int *fd)
{
    struct stat st;
    int f;

    *fd = -1;
    f = open_dir_at(base, name);
    if (f < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(f, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != owner) {
        close(f);
        errno = EPERM;
        return -1;
    }
    *fd = f;
    return 0;
}

/*
 * Verifies the installed archive through a descriptor pinned to the root-only
 * file, exactly as start does, so the result describes the file start would run.
 */
static int verify_installed(int progs_fd, const char *archive_name, const pkg_opts *o,
                            pkg_verified *v, char *err, size_t errlen)
{
    char fdpath[64];
    struct stat st;
    int zfd, rc;

    zfd = openat(progs_fd, archive_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (zfd < 0) {
        pkg_seterr(err, errlen, "trusted package %s is missing", archive_name);
        return -1;
    }
    if (fstat(zfd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
        (st.st_mode & 07777) != 0600) {
        close(zfd);
        pkg_seterr(err, errlen, "trusted package %s has unsafe ownership or permissions",
                   archive_name);
        return -1;
    }
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", zfd);
    rc = pkg_verify(fdpath, o->keys_dir, v, err, errlen);
    close(zfd);
    return rc;
}

/*
 * An update must be a newer version of the same app, signed by the same publisher
 * key. Downgrades are refused, so an old signed release cannot replace a newer one.
 */
static int check_upgrade(const pkg_verified *old, const pkg_verified *nw, char *err, size_t errlen)
{
    int cmp;

    if (strcmp(old->manifest.name, nw->manifest.name) != 0) {
        pkg_seterr(err, errlen, "package is for '%s', not the installed app '%s'",
                   nw->manifest.name, old->manifest.name);
        return -1;
    }
    if (strcmp(old->signer, nw->signer) != 0) {
        pkg_seterr(err, errlen, "package is signed by a different publisher key than the installed version");
        return -1;
    }
    cmp = pkg_version_compare(nw->manifest.version, old->manifest.version);
    if (cmp == 0) {
        pkg_seterr(err, errlen, "version %s is already installed", old->manifest.version);
        return -1;
    }
    if (cmp < 0) {
        pkg_seterr(err, errlen, "version %s is older than installed %s; downgrades are refused",
                   nw->manifest.version, old->manifest.version);
        return -1;
    }
    return 0;
}

/* Removes /run/app/<name>. An absent /run/app or payload is not an error. */
static int remove_runtime(const pkg_opts *o, const char *name)
{
    char p[PKG_PATH_MAX];
    struct stat st;
    int runtime_fd, rc;

    rooted(p, sizeof(p), o, PKG_RUN_DIR);
    if (lstat(p, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    runtime_fd = open_runtime_root(o);
    if (runtime_fd < 0)
        return -1;
    rc = pkg_rm_entry_at(runtime_fd, name, 0);
    close(runtime_fd);
    return rc;
}

/* Deletes the app account. Staged roots use userdel, the device uses deluser. */
static int delete_account(const pkg_opts *o, const char *name)
{
    const char *a[] = { name };

    if (o->root[0] != '\0')
        return run_stage_acct(o, "userdel", a, 1) == 0 ? 0 : -1;
    return run_busybox_acct("deluser", a, 1) == 0 ? 0 : -1;
}

/* Opens the app's package store, lock and staging directories. Returns 0 or -1. */
static int open_store(const pkg_opts *o, int *data_fd, int *progs_fd, int *locks_fd, int *stage_fd)
{
    *data_fd = open_data_root(o, 0);
    if (*data_fd < 0)
        return -1;
    *progs_fd = open_owned_at(*data_fd, "app_progs", 0);
    if (*progs_fd < 0)
        return -1;
    *locks_fd = open_owned_at(*progs_fd, LOCKS_DIR, 0);
    *stage_fd = open_owned_at(*progs_fd, PKG_STAGING_DIR, 0);
    return (*locks_fd < 0 || *stage_fd < 0) ? -1 : 0;
}

int pkg_cmd_stop(const char *name, const pkg_stop_opts *so, const pkg_opts *o)
{
    uid_t uid = (uid_t)-1;
    int data_fd = -1, progs_fd = -1, locks_fd = -1, stage_fd = -1, lock_fd = -1;
    int running = 0, rc = 1, r;

    if (require_root() != 0)
        return 1;
    if (!pkg_name_valid(name)) {
        msg_err("invalid package name '%s'", name);
        return 1;
    }
    r = find_app_uid(o, name, &uid);
    if (r <= 0) {
        if (r == 0)
            msg_err("no app user '%s': the app is not installed", name);
        return 1;
    }
    if (open_store(o, &data_fd, &progs_fd, &locks_fd, &stage_fd) != 0) {
        msg_err("the package store is missing or unsafe: %s", strerror(errno));
        goto out;
    }
    if (stop_app(o, so, name, uid, locks_fd, &lock_fd, &running) != 0)
        goto out;
    if (running)
        printf("stopped %s\n", name);
    else
        printf("%s is not running\n", name);
    rc = 0;

out:
    if (lock_fd >= 0) close(lock_fd);
    if (stage_fd >= 0) close(stage_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    return rc;
}

int pkg_cmd_update(const char *source, const pkg_stop_opts *so, const pkg_opts *o)
{
    char err[512] = "";
    char progs_path[PKG_PATH_MAX];
    char stage_tmpl[PKG_PATH_MAX * 2];
    char archive_name[PKG_NAME_MAX + sizeof(PKG_ARCHIVE_SUFFIX)];
    char lock_name[PKG_NAME_MAX + 16];
    char name[PKG_NAME_MAX + 1] = "";
    const char *stage_name = NULL;
    pkg_verified nv, ov;
    struct stat st;
    uid_t uid = (uid_t)-1;
    int data_fd = -1, progs_fd = -1, locks_fd = -1, stage_fd = -1, lock_fd = -1;
    int staged = 0, running = 0, tfd, r, rc = 1;

    memset(&nv, 0, sizeof(nv));
    memset(&ov, 0, sizeof(ov));
    if (require_root() != 0)
        return 1;

    rooted(progs_path, sizeof(progs_path), o, PKG_PROGS_DIR);
    if (open_store(o, &data_fd, &progs_fd, &locks_fd, &stage_fd) != 0) {
        msg_err("the package store is missing or unsafe; reinstall the app: %s", strerror(errno));
        goto out;
    }

    /* 1. Fetch and verify the new package before anything is stopped. */
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
    if (pkg_verify(stage_tmpl, o->keys_dir, &nv, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }
    snprintf(name, sizeof(name), "%s", nv.manifest.name);
    snprintf(archive_name, sizeof(archive_name), "%s%s", name, PKG_ARCHIVE_SUFFIX);
    snprintf(lock_name, sizeof(lock_name), "app-%s.lock", name);

    /* 2. Check the update against the installed package, still without stopping anything. */
    if (verify_installed(progs_fd, archive_name, o, &ov, err, sizeof(err)) != 0) {
        msg_err("'%s' is not installed or its package is unusable: %s", name, err);
        goto out;
    }
    if (check_upgrade(&ov, &nv, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }
    pkg_verified_free(&ov);
    r = find_app_uid(o, name, &uid);
    if (r != 1) {
        msg_err("no app user '%s': the app is not installed", name);
        goto out;
    }
    if (fstatat(locks_fd, lock_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        msg_err("app '%s' has no lock file; reinstall it", name);
        goto out;
    }

    /* 3. Stop the app and hold its lock. Re-check under the lock, since the installed
     * package could have changed between steps 2 and 3. */
    if (stop_app(o, so, name, uid, locks_fd, &lock_fd, &running) != 0)
        goto out;
    if (lock_fd < 0) {
        msg_err("app '%s' has no lock file; reinstall it", name);
        goto out;
    }
    if (verify_installed(progs_fd, archive_name, o, &ov, err, sizeof(err)) != 0 ||
        check_upgrade(&ov, &nv, err, sizeof(err)) != 0) {
        msg_err("%s", err);
        goto out;
    }

    /* 4. Atomically replace the trusted archive. The staged file is root-only. */
    if (renameat(stage_fd, stage_name, progs_fd, archive_name) != 0) {
        msg_err("cannot store the new package: %s", strerror(errno));
        goto out;
    }
    staged = 0;

    /* 5. Drop the old runtime tree. The next start extracts the new package. */
    if (remove_runtime(o, name) != 0)
        fprintf(stderr, "urpkg: warning: could not remove the old runtime tree of '%s'; "
                        "the next start replaces it\n", name);

    printf("updated %s from %s to %s", name, ov.manifest.version, nv.manifest.version);
    if (running)
        printf(" (the running instance was stopped)");
    printf("\nstart it with: urpkg start %s\n", name);
    rc = 0;

out:
    if (staged && stage_fd >= 0)
        unlinkat(stage_fd, stage_name, 0);
    pkg_verified_free(&nv);
    pkg_verified_free(&ov);
    if (lock_fd >= 0) close(lock_fd);
    if (stage_fd >= 0) close(stage_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    return rc;
}

int pkg_cmd_uninstall(const char *name, const pkg_stop_opts *so, const pkg_opts *o)
{
    char archive_name[PKG_NAME_MAX + sizeof(PKG_ARCHIVE_SUFFIX)];
    char lock_name[PKG_NAME_MAX + 16];
    struct stat st;
    uid_t uid = (uid_t)-1;
    int data_fd = -1, progs_fd = -1, locks_fd = -1, stage_fd = -1;
    int appdata_fd = -1, lock_fd = -1;
    int has_acct, has_archive = 0, has_data = 0, running = 0, rc = 1, r;

    if (require_root() != 0)
        return 1;
    if (!pkg_name_valid(name)) {
        msg_err("invalid package name '%s'", name);
        return 1;
    }
    r = find_app_uid(o, name, &uid);
    if (r < 0)
        return 1;
    has_acct = r;
    snprintf(archive_name, sizeof(archive_name), "%s%s", name, PKG_ARCHIVE_SUFFIX);
    snprintf(lock_name, sizeof(lock_name), "app-%s.lock", name);

    /* Find what is left. A partial earlier uninstall is completed by running again. */
    data_fd = open_data_root(o, 0);
    if (data_fd < 0) {
        msg_err("cannot open the data directory: %s", strerror(errno));
        goto out;
    }
    if (open_optional_owned_at(data_fd, "app_progs", 0, &progs_fd) != 0 ||
        open_optional_owned_at(data_fd, "app", 0, &appdata_fd) != 0) {
        msg_err("the package store is unsafe: %s", strerror(errno));
        goto out;
    }
    if (progs_fd >= 0) {
        if (open_optional_owned_at(progs_fd, LOCKS_DIR, 0, &locks_fd) != 0) {
            msg_err("the per-app lock directory is unsafe: %s", strerror(errno));
            goto out;
        }
        has_archive = fstatat(progs_fd, archive_name, &st, AT_SYMLINK_NOFOLLOW) == 0;
    }
    has_data = appdata_fd >= 0 && fstatat(appdata_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0;
    if (!has_acct && !has_archive && !has_data) {
        msg_err("'%s' is not installed", name);
        goto out;
    }

    /* Stop the app first. It is only removed once no process of it remains. */
    if (stop_app(o, so, name, uid, locks_fd, &lock_fd, &running) != 0)
        goto out;

    /* Remove in an order that keeps a failed step retryable: the account goes
     * first, so the app cannot run again while the rest is removed. */
    if (has_acct && delete_account(o, name) != 0) {
        msg_err("cannot remove app user '%s'; the app is still installed", name);
        goto out;
    }
    if (remove_runtime(o, name) != 0) {
        msg_err("cannot remove the runtime tree of '%s'", name);
        goto out;
    }
    if (appdata_fd >= 0 && pkg_rm_entry_at(appdata_fd, name, 0) != 0) {
        msg_err("cannot remove the data of '%s': %s", name, strerror(errno));
        goto out;
    }
    if (progs_fd >= 0 && unlinkat(progs_fd, archive_name, 0) != 0 && errno != ENOENT) {
        msg_err("cannot remove the trusted package of '%s': %s", name, strerror(errno));
        goto out;
    }
    /* The lock is held here, so no start can run while its file is removed. */
    if (locks_fd >= 0 && lock_fd >= 0 && unlinkat(locks_fd, lock_name, 0) != 0 && errno != ENOENT) {
        msg_err("cannot remove the lock file of '%s': %s", name, strerror(errno));
        goto out;
    }

    printf("uninstalled %s", name);
    if (running)
        printf(" (the running instance was stopped)");
    printf("\n");
    rc = 0;

out:
    if (lock_fd >= 0) close(lock_fd);
    if (stage_fd >= 0) close(stage_fd);
    if (appdata_fd >= 0) close(appdata_fd);
    if (locks_fd >= 0) close(locks_fd);
    if (progs_fd >= 0) close(progs_fd);
    if (data_fd >= 0) close(data_fd);
    return rc;
}
