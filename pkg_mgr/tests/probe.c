/*
 * probe.c - test helper for the end-to-end suite.
 *
 * Built static so it runs inside the staging chroot with no libraries.
 *
 *   probe                    self-check, run as the app by `urpkg start`.
 *                            Exit 0 only if every expectation holds.
 *   probe --op read PATH     exit 0 if PATH can be opened for reading
 *   probe --op write PATH    exit 0 if PATH can be created for writing
 *   probe --op list DIR      exit 0 if DIR can be listed
 *
 * In the --op forms a denial prints "denied" and exits 1, so a failure to run
 * the probe at all is never mistaken for a denial.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int one_op(const char *op, const char *path)
{
    int fd;
    DIR *d;

    if (strcmp(op, "read") == 0) {
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            printf("read %s: denied (%s)\n", path, strerror(errno));
            return 1;
        }
        close(fd);
    } else if (strcmp(op, "write") == 0) {
        fd = open(path, O_WRONLY | O_CREAT, 0600);
        if (fd < 0) {
            printf("write %s: denied (%s)\n", path, strerror(errno));
            return 1;
        }
        close(fd);
    } else if (strcmp(op, "list") == 0) {
        d = opendir(path);
        if (!d) {
            printf("list %s: denied (%s)\n", path, strerror(errno));
            return 1;
        }
        closedir(d);
    } else {
        fprintf(stderr, "probe: unknown op '%s'\n", op);
        return 2;
    }
    printf("%s %s: ok\n", op, path);
    return 0;
}

static int self_check(int argc, char **argv)
{
    gid_t groups[64];
    char cwd[512];
    int ng, i, ok = 1, fd;

    printf("uid=%u gid=%u euid=%u\n", (unsigned)getuid(), (unsigned)getgid(),
           (unsigned)geteuid());
    ng = getgroups(64, groups);
    printf("groups=");
    for (i = 0; i < ng; i++)
        printf("%s%u", i ? "," : "", (unsigned)groups[i]);
    printf("\n");
    if (getcwd(cwd, sizeof(cwd)))
        printf("cwd=%s\n", cwd);
    printf("args=%d\n", argc - 1);
    for (i = 1; i < argc; i++)
        printf("arg=%s\n", argv[i]);

    /* The code folder must not be writable by the app. */
    fd = open("system_cache/app/planted", O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) {
        close(fd);
        unlink("system_cache/app/planted");
        printf("cache_write=ALLOWED\n");
        ok = 0;
    } else {
        printf("cache_write=denied (%s)\n", strerror(errno));
    }

    /* The app must not be able to move or delete system_cache. */
    if (rename("system_cache", "stolen") == 0) {
        printf("rename_cache=ALLOWED\n");
        ok = 0;
    } else {
        printf("rename_cache=denied (%s)\n", strerror(errno));
    }

    /* A non-entry payload file must not be readable by the app. */
    fd = open("system_cache/app/extra.txt", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        printf("read_extra=ALLOWED\n");
        ok = 0;
    } else {
        printf("read_extra=denied (%s)\n", strerror(errno));
    }

    /* The app must not be able to get root back. */
    if (setuid(0) == 0) {
        printf("setuid0=ALLOWED\n");
        ok = 0;
    } else {
        printf("setuid0=denied\n");
    }

    /* App data must be writable. */
    fd = open("probe-data.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0 && write(fd, "ok\n", 3) == 3) {
        printf("data_write=ok\n");
    } else {
        printf("data_write=FAILED (%s)\n", strerror(errno));
        ok = 0;
    }
    if (fd >= 0)
        close(fd);

    printf("probe=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "--op") == 0)
        return one_op(argv[2], argv[3]);
    return self_check(argc, argv);
}
