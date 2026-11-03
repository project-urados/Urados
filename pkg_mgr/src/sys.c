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
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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
        execv(argv[0], argv);
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

/* Returns 1 if the immutable flag is set, 0 if not, -1 on error. */
int pkg_get_immutable_fd(int fd)
{
    long flags = 0;

    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != 0)
        return -1;
    return (flags & FS_IMMUTABLE_FL) ? 1 : 0;
}

/* Sets or clears the immutable flag (chattr +i/-i) on an open file or dir. */
int pkg_set_immutable_fd(int fd, int on)
{
    /* The kernel reads and writes a native long here (8 bytes on 64-bit). */
    long flags = 0;

    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != 0)
        return -1;
    if (on)
        flags |= FS_IMMUTABLE_FL;
    else
        flags &= ~FS_IMMUTABLE_FL;
    return ioctl(fd, FS_IOC_SETFLAGS, &flags);
}

/* Looks up a passwd entry in <root>/etc/passwd. Returns 0 if found. */
int pkg_lookup_passwd(const char *root, const char *name, uid_t *uid, gid_t *gid)
{
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

/*
 * Collects the gids a user belongs to: the primary gid first, then every group
 * in <root>/etc/group that lists `user` as a member. Reads files only, so it
 * works before chroot and needs no NSS modules.
 */
int pkg_supp_groups(const char *root, const char *user, gid_t primary,
                    gid_t *out, size_t max, size_t *n)
{
    char *path = pkg_join(root, "/etc/group");
    FILE *fp;
    char line[2048];
    int rc = 0;

    *n = 0;
    if (!path)
        return -1;
    fp = fopen(path, "r");
    free(path);
    if (!fp)
        return -1;
    if (max == 0)
        goto out;
    out[(*n)++] = primary;
    while (fgets(line, sizeof(line), fp)) {
        char *f[4], *p = line, *save = NULL, *tok;
        int i;
        unsigned long gid;

        line[strcspn(line, "\n")] = '\0';
        for (i = 0; i < 4 && p; i++) {
            f[i] = p;
            p = strchr(p, ':');
            if (p)
                *p++ = '\0';
        }
        if (i < 4)
            continue;
        gid = strtoul(f[2], NULL, 10);
        if ((gid_t)gid == primary)
            continue;
        for (tok = strtok_r(f[3], ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            if (strcmp(tok, user) == 0) {
                if (*n >= max) {
                    rc = -1;
                    goto out;
                }
                out[(*n)++] = (gid_t)gid;
                break;
            }
        }
    }
out:
    fclose(fp);
    return rc;
}

/* Looks up a group entry in <root>/etc/group. Returns 0 if found. */
int pkg_lookup_group(const char *root, const char *name, gid_t *gid)
{
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
