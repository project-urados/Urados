/*
 * exec.c - runs commands as a given user and group, in one of five modes.
 *
 * A command gets the identity named by its user= and group= options (see
 * make_plan). A change to a non-root uid is permanent, so the command cannot
 * get root back. A command starts with an empty signal mask, default signal
 * dispositions, a clean environment, and no descriptors above stderr.
 *
 * Modes (see enum uinit_exec_mode in uinit.h):
 *   wait, spawn, exit-nonzero, exit
 *       fork(). The child sets its identity and calls execvp(). If that fails,
 *       the errno comes back through a close-on-exec pipe.
 *   replace
 *       No fork. uinit sets its identity and calls execve() itself, so the
 *       command keeps uinit's PID. This function returns only on failure.
 *
 * Return values of uinit_exec_run():
 *   0   the command ran. st says how it ended. spawn returns 0 before it ends.
 *   -1  the command could not be started. uinit's identity is unchanged.
 *   -2  replace changed uinit's identity and then could not run the command.
 *       uinit cannot get back to root, so the caller must stop booting.
 *
 * spawned commands are reaped by uinit_supervise() when uinit is PID 1, and
 * otherwise by whichever process they are re-parented to.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "uinit.h"

#define CHILD_PATH "/urados/sbin:/urados/bin:/sbin:/bin"

extern char **environ;

/* Everything a command needs, prepared in the parent before fork() or exec(). */
struct plan {
    int apply;                       /* 0: keep the current identity */
    int have_uid;
    int have_gid;
    uid_t uid;
    gid_t gid;
    gid_t *groups;
    size_t ngroups;
    char *dir;                       /* working directory of the command */
    char *envp[6];                   /* NULL-terminated, strings owned */
};

static void plan_free(struct plan *p)
{
    size_t i;

    free(p->groups);
    free(p->dir);
    for (i = 0; p->envp[i]; i++)
        free(p->envp[i]);
    memset(p, 0, sizeof *p);
}

/* Supplementary groups of a user, as initgroups() would set them. */
static int user_groups(const char *name, gid_t gid, gid_t **out, size_t *nout,
                       char *err, size_t errlen)
{
    int n = 16;
    gid_t *g = NULL;
    int attempt;

    for (attempt = 0; attempt < 8; attempt++) {
        gid_t *ng = realloc(g, (size_t)n * sizeof *g);

        if (!ng) {
            free(g);
            uinit_seterr(err, errlen, "out of memory");
            return -1;
        }
        g = ng;
        if (getgrouplist(name, gid, g, &n) >= 0) {
            *out = g;
            *nout = (size_t)n;
            return 0;
        }
    }
    free(g);
    uinit_seterr(err, errlen, "cannot read the groups of '%s'", name);
    return -1;
}

static char *dup_env(const char *key, const char *val)
{
    size_t kl = strlen(key), vl = strlen(val);
    char *s = malloc(kl + vl + 2);

    if (!s)
        return NULL;
    memcpy(s, key, kl);
    s[kl] = '=';
    memcpy(s + kl + 1, val, vl + 1);
    return s;
}

/* Works out ids, groups, directory and environment for one exec. */
static int make_plan(const struct uinit_exec *e, struct plan *p, char *err, size_t errlen)
{
    const struct passwd *pw = NULL;
    size_t k = 0;

    memset(p, 0, sizeof *p);
    p->apply = e->user || e->group || e->groups;

    if (e->user) {
        if (e->user[0] && strspn(e->user, "0123456789") == strlen(e->user)) {
            p->uid = (uid_t)strtoul(e->user, NULL, 10);
            pw = getpwuid(p->uid);
        } else {
            pw = getpwnam(e->user);
            if (!pw) {
                uinit_seterr(err, errlen, "no such user '%s'", e->user);
                return -1;
            }
            p->uid = pw->pw_uid;
        }
        p->have_uid = 1;
    }

    if (e->group) {
        if (uinit_lookup_gid(e->group, &p->gid, err, errlen) < 0)
            return -1;
        p->have_gid = 1;
    } else if (pw) {
        p->gid = pw->pw_gid;
        p->have_gid = 1;
    } else if (e->user) {
        uinit_seterr(err, errlen, "user %s has no passwd entry; give group= too", e->user);
        return -1;
    }

    if (e->groups) {
        p->groups = calloc(e->ngroups ? e->ngroups : 1, sizeof *p->groups);
        if (!p->groups) {
            uinit_seterr(err, errlen, "out of memory");
            return -1;
        }
        for (k = 0; k < e->ngroups; k++) {
            if (uinit_lookup_gid(e->groups[k], &p->groups[k], err, errlen) < 0) {
                p->ngroups = k;
                plan_free(p);
                return -1;
            }
        }
        p->ngroups = e->ngroups;
    } else if (pw) {
        if (user_groups(pw->pw_name, p->gid, &p->groups, &p->ngroups, err, errlen) < 0) {
            plan_free(p);
            return -1;
        }
    } else if (p->have_gid) {
        p->groups = malloc(sizeof *p->groups);
        if (!p->groups) {
            uinit_seterr(err, errlen, "out of memory");
            plan_free(p);
            return -1;
        }
        p->groups[0] = p->gid;
        p->ngroups = 1;
    }

    /* Environment: a fixed PATH, plus the account's home and name when there is one. */
    p->envp[0] = dup_env("PATH", CHILD_PATH);
    p->envp[1] = dup_env("HOME", pw && pw->pw_dir ? pw->pw_dir : "/");
    if (pw) {
        p->envp[2] = dup_env("USER", pw->pw_name);
        p->envp[3] = dup_env("LOGNAME", pw->pw_name);
    }
    if (!p->envp[0] || !p->envp[1] || (pw && (!p->envp[2] || !p->envp[3]))) {
        uinit_seterr(err, errlen, "out of memory");
        plan_free(p);
        return -1;
    }
    p->dir = strdup(pw && pw->pw_dir ? pw->pw_dir : "/");
    if (!p->dir) {
        uinit_seterr(err, errlen, "out of memory");
        plan_free(p);
        return -1;
    }
    return 0;
}

/*
 * Closes every descriptor above stderr except keep, so a command does not
 * inherit uinit's own files. close_range() is used when the kernel has it.
 */
static void close_others(int keep)
{
    int fd;

#ifdef SYS_close_range
    if (keep > 3 &&
        syscall(SYS_close_range, 3U, (unsigned int)(keep - 1), 0) != 0)
        goto fallback;
    if (syscall(SYS_close_range, (unsigned int)(keep + 1), ~0U, 0) == 0)
        return;
fallback:
#endif
    for (fd = 3; fd < 1024; fd++) {
        if (fd != keep)
            close(fd);
    }
}

/*
 * Marks every descriptor above stderr close-on-exec. Used by replace, where a
 * failed exec must leave uinit's descriptors open and usable, while a successful
 * exec must not pass them on.
 */
static void mark_cloexec_all(void)
{
    int fd;

    for (fd = 3; fd < 1024; fd++) {
        int flags = fcntl(fd, F_GETFD);

        if (flags >= 0 && !(flags & FD_CLOEXEC))
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

/* Empty signal mask and default dispositions, as a new program expects. */
static void reset_signals(void)
{
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);
    for (sig = 1; sig < NSIG; sig++) {
        if (sig != SIGKILL && sig != SIGSTOP)
            signal(sig, SIG_DFL);
    }
}

/*
 * Changes groups, gid and uid, in that order, while still root. Returns 0, or
 * -1 with errno set. *changed is set once any id has been changed, so the
 * caller knows whether the process is still in its old identity.
 */
static int apply_identity(const struct plan *p, int *changed)
{
    *changed = 0;
    if (setgroups(p->ngroups, p->groups) != 0)
        return -1;
    *changed = 1;
    if (p->have_gid && setgid(p->gid) != 0)
        return -1;
    if (p->have_uid && setuid(p->uid) != 0)
        return -1;
    return 0;
}

static void child_fail(int fd, int err) __attribute__((noreturn));
static void child_fail(int fd, int err)
{
    ssize_t r = write(fd, &err, sizeof err);

    (void)r;
    _exit(127);
}

/* Runs in the forked child. Never returns. */
static void child_exec(struct plan *p, char *const argv[], int errfd)
{
    close_others(errfd);
    reset_signals();

    if (p->apply) {
        int changed;

        if (apply_identity(p, &changed) != 0)
            child_fail(errfd, errno);
    }

    if (chdir(p->dir) != 0 && chdir("/") != 0)
        child_fail(errfd, errno);

    environ = p->envp;
    execvp(argv[0], argv);
    child_fail(errfd, errno);
}

/* 0 if path is a regular file that can be executed, else -1 with errno set. */
static int check_runnable(const char *path)
{
    struct stat st;

    if (stat(path, &st) < 0)
        return -1;
    if (S_ISDIR(st.st_mode)) {
        errno = EISDIR;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        errno = EACCES;
        return -1;
    }
    return access(path, X_OK);
}

/*
 * Finds the file replace will execute, before any identity change, so a
 * missing command is reported while uinit can still go on. Returns a new
 * string, or NULL with err set.
 */
static char *resolve_command(const char *cmd, char *err, size_t errlen)
{
    const char *p = CHILD_PATH;
    size_t cl = strlen(cmd);

    if (strchr(cmd, '/')) {
        char *out;

        if (check_runnable(cmd) < 0) {
            uinit_seterr(err, errlen, "cannot run %s: %s", cmd, strerror(errno));
            return NULL;
        }
        out = strdup(cmd);
        if (!out)
            uinit_seterr(err, errlen, "out of memory");
        return out;
    }

    for (;;) {
        const char *c = strchr(p, ':');
        size_t dl = c ? (size_t)(c - p) : strlen(p);
        char *out = malloc(dl + cl + 2);

        if (!out) {
            uinit_seterr(err, errlen, "out of memory");
            return NULL;
        }
        memcpy(out, p, dl);
        out[dl] = '/';
        memcpy(out + dl + 1, cmd, cl + 1);
        if (check_runnable(out) == 0)
            return out;
        free(out);
        if (!c)
            break;
        p = c + 1;
    }
    uinit_seterr(err, errlen, "cannot run %s: %s", cmd, strerror(ENOENT));
    return NULL;
}

/*
 * replace: uinit becomes the command. Returns only on failure.
 *
 * A failure before the identity change returns -1 and uinit carries on. Once
 * the identity has been changed, uinit cannot get root back, so any failure
 * after that point returns -2 and the caller must stop.
 */
static int exec_replace(struct plan *p, const struct uinit_exec *e, char *err, size_t errlen)
{
    char *path = resolve_command(e->argv[0], err, errlen);
    int apply = p->apply;
    int cerr;

    if (!path) {
        plan_free(p);
        return -1;
    }

    fflush(NULL);
    reset_signals();
    if (apply) {
        int changed;

        if (apply_identity(p, &changed) != 0) {
            cerr = errno;
            if (changed)
                uinit_seterr(err, errlen, "uinit changed its identity and cannot run %s: %s",
                             e->argv[0], strerror(cerr));
            else
                uinit_seterr(err, errlen, "cannot change identity to run %s: %s",
                             e->argv[0], strerror(cerr));
            free(path);
            plan_free(p);
            return changed ? -2 : -1;
        }
    }
    if (chdir(p->dir) != 0)
        (void)chdir("/");
    mark_cloexec_all();

    /* envp is passed directly, so environ is not touched. */
    execve(path, e->argv, p->envp);
    cerr = errno;

    if (apply)
        uinit_seterr(err, errlen, "uinit changed its identity and cannot run %s: %s",
                     e->argv[0], strerror(cerr));
    else
        uinit_seterr(err, errlen, "cannot run %s: %s", e->argv[0], strerror(cerr));
    free(path);
    plan_free(p);
    return apply ? -2 : -1;
}

static int wait_pid(pid_t pid, int *status)
{
    pid_t r;

    do {
        r = waitpid(pid, status, 0);
    } while (r < 0 && errno == EINTR);
    return r < 0 ? -1 : 0;
}

int uinit_exec_run(const struct uinit_exec *e, struct uinit_status *st, char *err, size_t errlen)
{
    struct plan p;
    int pfd[2];
    pid_t pid;
    int cerr = 0, status = 0;
    ssize_t n;

    memset(st, 0, sizeof *st);
    if (make_plan(e, &p, err, errlen) < 0)
        return -1;
    if (e->mode == UINIT_MODE_REPLACE)
        return exec_replace(&p, e, err, errlen);

    /* The write end is close-on-exec, so a successful exec() closes it and read() returns 0. */
    if (pipe2(pfd, O_CLOEXEC) < 0) {
        uinit_seterr(err, errlen, "pipe: %s", strerror(errno));
        plan_free(&p);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        uinit_seterr(err, errlen, "fork: %s", strerror(errno));
        close(pfd[0]);
        close(pfd[1]);
        plan_free(&p);
        return -1;
    }
    if (pid == 0) {
        close(pfd[0]);
        child_exec(&p, e->argv, pfd[1]);
    }

    close(pfd[1]);
    plan_free(&p);
    do {
        n = read(pfd[0], &cerr, sizeof cerr);
    } while (n < 0 && errno == EINTR);
    close(pfd[0]);

    if (n == (ssize_t)sizeof cerr) {
        wait_pid(pid, &status);
        uinit_seterr(err, errlen, "cannot run %s: %s", e->argv[0], strerror(cerr));
        return -1;
    }

    if (e->mode == UINIT_MODE_SPAWN) {
        uinit_debug("spawned %s as pid %d", e->argv[0], (int)pid);
        return 0;
    }
    if (wait_pid(pid, &status) < 0) {
        uinit_seterr(err, errlen, "waiting for %s: %s", e->argv[0], strerror(errno));
        return -1;
    }
    if (WIFEXITED(status)) {
        st->code = WEXITSTATUS(status);
        uinit_debug("%s exited with status %d", e->argv[0], st->code);
        return 0;
    }
    if (WIFSIGNALED(status)) {
        st->sig = WTERMSIG(status);
        uinit_debug("%s killed by signal %d", e->argv[0], st->sig);
        return 0;
    }
    uinit_seterr(err, errlen, "%s ended in an unknown state", e->argv[0]);
    return -1;
}

/* A killed command ends with 128 + signal number, the shell convention. */
int uinit_status_exit_code(const struct uinit_status *st)
{
    return st->sig ? 128 + st->sig : st->code;
}

/* Reaps every child, forever. PID 1 must never exit: that panics the kernel. */
void uinit_supervise(void)
{
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, 0);

        if (pid < 0 && errno == EINTR)
            continue;
        if (pid < 0)
            sleep(1);       /* ECHILD: nothing to reap yet, so look again shortly */
    }
}
