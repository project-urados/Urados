/*
 * sys.c - filesystem and account helpers.
 *
 * Anything under an app's data directory is owned by the app user, so those
 * operations go through directory file descriptors with O_NOFOLLOW. That
 * stops the app from redirecting a root operation with a symlink.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "urados_pkg.h"

#define RM_MAX_DEPTH 64

int pkg_run(char *const argv[])
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (strchr(argv[0], '/') != NULL) {
            execv(argv[0], argv);
        } else {
            /* Bare names are only used for staged host account tools. */
            setenv("PATH", "/sbin:/bin", 1);
            execvp(argv[0], argv);
        }
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/*
 * Removes `name` (file, symlink or directory tree) relative to `base`. Never
 * follows symlinks. Returns 0 on success, and also 0 if the name is absent.
 */
int pkg_rm_entry_at(int base, const char *name, int depth)
{
    struct stat st;
    DIR *d;
    struct dirent *e;
    int fd, rc = 0;

    if (fstatat(base, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(base, name, 0);
    if (depth > RM_MAX_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    fd = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    d = fdopendir(fd); /* takes ownership of fd */
    if (!d) {
        close(fd);
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (pkg_rm_entry_at(dirfd(d), e->d_name, depth + 1) != 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc != 0)
        return -1;
    return unlinkat(base, name, AT_REMOVEDIR);
}

/*
 * Opens base/name as a directory, creating it with `mode` if it is missing.
 * A new directory gets owner uid and group gid. An existing one keeps its
 * attributes. Symlinks are rejected. Returns an fd, or -1.
 */
int pkg_open_subdir(int base, const char *name, mode_t mode, uid_t uid, gid_t gid)
{
    int fd;

    if (mkdirat(base, name, mode) == 0) {
        fd = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            return -1;
        if (fchown(fd, uid, gid) != 0 || fchmod(fd, mode) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    }
    if (errno != EEXIST)
        return -1;
    return openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

/* Looks up a passwd entry through libc/NSS, or in a staged root's passwd file. */
int pkg_lookup_passwd(const char *root, const char *name, uid_t *uid, gid_t *gid)
{
    if (!root || !root[0]) {
        struct passwd pw, *result = NULL;
        long hint = sysconf(_SC_GETPW_R_SIZE_MAX);
        size_t size = hint > 0 ? (size_t)hint : 1024;
        char *buf;
        int rc;

        if (size < 1024)
            size = 1024;
        for (;;) {
            buf = malloc(size);
            if (!buf)
                return -1;
            rc = getpwnam_r(name, &pw, buf, size, &result);
            if (rc != ERANGE)
                break;
            free(buf);
            if (size > (size_t)-1 / 2)
                return -1;
            size *= 2;
        }
        if (rc == 0 && result) {
            *uid = result->pw_uid;
            *gid = result->pw_gid;
            free(buf);
            return 0;
        }
        free(buf);
        return -1;
    }

    char *path = pkg_join(root, "/etc/passwd");
    FILE *fp;
    char line[1024];
    int found = -1;

    if (!path)
        return -1;
    fp = fopen(path, "r");
    free(path);
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *f[7], *p = line;
        int i;

        line[strcspn(line, "\n")] = '\0';
        for (i = 0; i < 7 && p; i++) {
            f[i] = p;
            p = strchr(p, ':');
            if (p)
                *p++ = '\0';
        }
        if (i < 4 || strcmp(f[0], name) != 0)
            continue;
        *uid = (uid_t)strtoul(f[2], NULL, 10);
        *gid = (gid_t)strtoul(f[3], NULL, 10);
        found = 0;
        break;
    }
    fclose(fp);
    return found;
}

/* Looks up a group through libc/NSS, or in a staged root's group file. */
int pkg_lookup_group(const char *root, const char *name, gid_t *gid)
{
    if (!root || !root[0]) {
        struct group gr, *result = NULL;
        long hint = sysconf(_SC_GETGR_R_SIZE_MAX);
        size_t size = hint > 0 ? (size_t)hint : 1024;
        char *buf;
        int rc;

        if (size < 1024)
            size = 1024;
        for (;;) {
            buf = malloc(size);
            if (!buf)
                return -1;
            rc = getgrnam_r(name, &gr, buf, size, &result);
            if (rc != ERANGE)
                break;
            free(buf);
            if (size > (size_t)-1 / 2)
                return -1;
            size *= 2;
        }
        if (rc == 0 && result) {
            *gid = result->gr_gid;
            free(buf);
            return 0;
        }
        free(buf);
        return -1;
    }

    char *path = pkg_join(root, "/etc/group");
    FILE *fp;
    char line[1024];
    int found = -1;

    if (!path)
        return -1;
    fp = fopen(path, "r");
    free(path);
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *f[4], *p = line;
        int i;

        line[strcspn(line, "\n")] = '\0';
        for (i = 0; i < 4 && p; i++) {
            f[i] = p;
            p = strchr(p, ':');
            if (p)
                *p++ = '\0';
        }
        if (i < 3 || strcmp(f[0], name) != 0)
            continue;
        *gid = (gid_t)strtoul(f[2], NULL, 10);
        found = 0;
        break;
    }
    fclose(fp);
    return found;
}
