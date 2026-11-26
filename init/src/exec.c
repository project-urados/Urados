/*
 * exec.c - runs commands as a given user and group, in their own process.
 *
 * Each command is started with fork(). The child sets its supplementary groups,
 * gid and uid, and then calls execvp(). Changing to a non-root uid is permanent,
 * so the command cannot get root back. The child starts with an empty signal
 * mask, default signal dispositions, and a clean environment.
 *
 * exec waits for the command and reports a non-zero exit status as an error.
 * spawn returns once exec has succeeded. A spawned command is reaped by
 * uinit_supervise() when uinit is PID 1, and otherwise by whichever process
 * it is re-parented to.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "uinit.h"

#define CHILD_PATH "/urados/sbin:/urados/bin:/sbin:/bin"

extern char **environ;

/* Everything the child needs, prepared in the parent before fork(). */
struct plan {
    int apply;                       /* 0: keep the current identity */
    int have_uid;
    int have_gid;
    uid_t uid;
    gid_t gid;
    gid_t *groups;
    size_t ngroups;
    char *dir;                       /* working directory of the child */
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

static int lookup_group(const char *s, gid_t *out, char *err, size_t errlen)
{
    struct group *gr;

    if (*s && strspn(s, "0123456789") == strlen(s)) {
        *out = (gid_t)strtoul(s, NULL, 10);
        return 0;
    }
    gr = getgrnam(s);
    if (!gr) {
        uinit_seterr(err, errlen, "no such group '%s'", s);
        return -1;
    }
    *out = gr->gr_gid;
    return 0;
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

/* Works out ids, groups, directory and environment for one exec or spawn. */
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
        if (lookup_group(e->group, &p->gid, err, errlen) < 0)
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
            if (lookup_group(e->groups[k], &p->groups[k], err, errlen) < 0) {
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

static void child_fail(int fd, int err) __attribute__((noreturn));
static void child_fail(int fd, int err)
{
    ssize_t r = write(fd, &err, sizeof err);

    (void)r;
    _exit(127);
}

/* Runs in the child. Never returns. */
static void child_exec(struct plan *p, char *const argv[], int errfd)
{
    sigset_t set;
    int sig;

    close_others(errfd);
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);
    for (sig = 1; sig < NSIG; sig++) {
        if (sig != SIGKILL && sig != SIGSTOP)
            signal(sig, SIG_DFL);
    }

    if (p->apply) {
        /* Order matters: groups and gid must be changed while still root. */
        if (setgroups(p->ngroups, p->groups) != 0)
            child_fail(errfd, errno);
        if (p->have_gid && setgid(p->gid) != 0)
            child_fail(errfd, errno);
        if (p->have_uid && setuid(p->uid) != 0)
            child_fail(errfd, errno);
    }

    if (chdir(p->dir) != 0 && chdir("/") != 0)
        child_fail(errfd, errno);

    environ = p->envp;
    execvp(argv[0], argv);
    child_fail(errfd, errno);
}

static int wait_pid(pid_t pid, int *status)
{
    pid_t r;

    do {
        r = waitpid(pid, status, 0);
    } while (r < 0 && errno == EINTR);
    return r < 0 ? -1 : 0;
}

int uinit_exec_run(const struct uinit_exec *e, int wait, char *err, size_t errlen)
{
    struct plan p;
    int pfd[2];
    pid_t pid;
    int cerr = 0, status = 0;
    ssize_t n;

    if (make_plan(e, &p, err, errlen) < 0)
        return -1;

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

    if (!wait) {
        uinit_debug("spawned %s as pid %d", e->argv[0], (int)pid);
        return 0;
    }
    if (wait_pid(pid, &status) < 0) {
        uinit_seterr(err, errlen, "waiting for %s: %s", e->argv[0], strerror(errno));
        return -1;
    }
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            uinit_debug("%s finished", e->argv[0]);
            return 0;
        }
        uinit_seterr(err, errlen, "%s exited with status %d", e->argv[0], WEXITSTATUS(status));
        return -1;
    }
    if (WIFSIGNALED(status)) {
        uinit_seterr(err, errlen, "%s killed by signal %d", e->argv[0], WTERMSIG(status));
        return -1;
    }
    uinit_seterr(err, errlen, "%s ended in an unknown state", e->argv[0]);
    return -1;
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
