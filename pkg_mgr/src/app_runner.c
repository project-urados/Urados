#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <selinux/context.h>
#include <selinux/selinux.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "urados_pkg.h"

static int parse_ulong(const char *s, unsigned long long max, unsigned long long *out)
{
    char *end = NULL;
    unsigned long long n;

    if (!s || !*s || *s == '-')
        return -1;
    errno = 0;
    n = strtoull(s, &end, 10);
    if (errno || !end || *end || n > max)
        return -1;
    *out = n;
    return 0;
}

static int valid_selinux_user(const char *s)
{
    size_t i, n;

    if (!s || (n = strlen(s)) < 3 || n >= PKG_SEL_USER_MAX ||
        strcmp(s + n - 2, "_u") != 0)
        return 0;
    for (i = 0; i < n - 2; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int require_launcher_context(void)
{
    char *raw = NULL;
    context_t ctx = NULL;
    const char *type;
    int rc = -1;

    if (!is_selinux_enabled() || security_getenforce() != 1) {
        fprintf(stderr, "urapp-runner: enforcing SELinux is required to start apps\n");
        return -1;
    }
    if (getcon(&raw) != 0 || !(ctx = context_new(raw))) {
        fprintf(stderr, "urapp-runner: cannot read the SELinux launch context\n");
        goto out;
    }
    type = context_type_get(ctx);
    if (!type || strcmp(type, "urados_launcher_t") != 0) {
        fprintf(stderr, "urapp-runner: not running in the trusted launcher domain\n");
        goto out;
    }
    rc = 0;
out:
    context_free(ctx);
    freecon(raw);
    return rc;
}

int main(int argc, char **argv)
{
    unsigned long long uid_n, gid_n, count_n, group_n;
    gid_t groups[PKG_GROUPS_MAX];
    char target[PKG_SEL_USER_MAX + 64], username[PKG_NAME_MAX + 1];
    char **child_argv;
    const char *seluser, *home, *program;
    int i, pos;

    if (argc < 8) {
        fprintf(stderr, "urapp-runner: invalid internal invocation\n");
        return 125;
    }
    if (parse_ulong(argv[1], (unsigned long long)(uid_t)-1, &uid_n) != 0 ||
        parse_ulong(argv[2], (unsigned long long)(gid_t)-1, &gid_n) != 0 ||
        parse_ulong(argv[3], PKG_GROUPS_MAX, &count_n) != 0 ||
        uid_n == 0 || gid_n == 0 || count_n == 0) {
        fprintf(stderr, "urapp-runner: invalid app identity\n");
        return 125;
    }
    if (argc < (int)(4 + count_n + 3)) {
        fprintf(stderr, "urapp-runner: incomplete internal invocation\n");
        return 125;
    }
    for (i = 0; i < (int)count_n; i++) {
        if (parse_ulong(argv[4 + i], (unsigned long long)(gid_t)-1, &group_n) != 0) {
            fprintf(stderr, "urapp-runner: invalid supplementary group\n");
            return 125;
        }
        groups[i] = (gid_t)group_n;
    }
    pos = 4 + (int)count_n;
    seluser = argv[pos++];
    home = argv[pos++];
    program = argv[pos++];
    if (!valid_selinux_user(seluser) || home[0] != '/' || program[0] != '/') {
        fprintf(stderr, "urapp-runner: invalid target context or path\n");
        return 125;
    }
    if (strlen(seluser) - 2 > PKG_NAME_MAX) {
        fprintf(stderr, "urapp-runner: app user name is too long\n");
        return 125;
    }
    memcpy(username, seluser, strlen(seluser) - 2);
    username[strlen(seluser) - 2] = '\0';
    if (require_launcher_context() != 0)
        return 125;
    if (snprintf(target, sizeof(target), "%s:urados_app_r:urados_app_t:s0", seluser) >=
        (int)sizeof(target)) {
        fprintf(stderr, "urapp-runner: target context is too long\n");
        return 125;
    }
    if (setexeccon(target) != 0) {
        fprintf(stderr, "urapp-runner: cannot select app SELinux context: %s\n", strerror(errno));
        return 125;
    }
    if (setgroups((size_t)count_n, groups) != 0 ||
        setresgid((gid_t)gid_n, (gid_t)gid_n, (gid_t)gid_n) != 0 ||
        setresuid((uid_t)uid_n, (uid_t)uid_n, (uid_t)uid_n) != 0) {
        fprintf(stderr, "urapp-runner: cannot drop to app uid/gid: %s\n", strerror(errno));
        return 125;
    }
    if (getuid() != (uid_t)uid_n || geteuid() != (uid_t)uid_n || setuid(0) == 0) {
        fprintf(stderr, "urapp-runner: failed to irreversibly drop root identity\n");
        return 125;
    }
    /* Do not set no_new_privs before this exec. On kernels whose SELinux
     * nnp_nosuid_transition policy capability is disabled, that flag turns
     * the launcher -> app domain transition into a bounded-transition check,
     * and a correctly more-restricted app domain is not bounded by the
     * launcher. The UID/GID drop above is irreversible, and SELinux denies
     * app execution of all non-cache/non-utility file types. */
    if (chdir(home) != 0) {
        fprintf(stderr, "urapp-runner: cannot enter app data home: %s\n", strerror(errno));
        return 125;
    }
    umask(0077);
    if (clearenv() != 0 || setenv("PATH", PKG_USER_UTILS, 1) != 0 ||
        setenv("HOME", home, 1) != 0 || setenv("USER", username, 1) != 0 ||
        setenv("LANG", "C", 1) != 0) {
        fprintf(stderr, "urapp-runner: cannot create a clean app environment\n");
        return 125;
    }
    child_argv = calloc((size_t)(argc - pos + 2), sizeof(*child_argv));
    if (!child_argv) {
        fprintf(stderr, "urapp-runner: out of memory\n");
        return 125;
    }
    child_argv[0] = (char *)program;
    for (i = pos; i < argc; i++)
        child_argv[i - pos + 1] = argv[i];
    execv(program, child_argv);
    fprintf(stderr, "urapp-runner: cannot execute %s: %s\n", program, strerror(errno));
    free(child_argv);
    return 127;
}
