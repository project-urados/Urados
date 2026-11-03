/*
 * probe.c - static integration-test app used to check the DAC layout.
 * SELinux execution denials are additionally asserted by policy neverallows;
 * staging-root tests do not emulate kernel SELinux enforcement.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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
    } else if (strcmp(op, "chmod") == 0) {
        if (chmod(path, 0755) != 0) {
            printf("chmod %s: denied (%s)\n", path, strerror(errno));
            return 1;
        }
    } else {
        fprintf(stderr, "probe: unknown op '%s'\n", op);
        return 2;
    }
    printf("%s %s: ok\n", op, path);
    return 0;
}

static int copy_self_and_exec(const char *self)
{
    const char *generated = "../system_cache/user/generated-probe";
    char buf[16384];
    char *child_argv[] = { (char *)generated, "--op", "write",
                           "../system_cache/user/generated-marker", NULL };
    int in = -1, out = -1, rc = -1;
    ssize_t n;
    pid_t pid;
    int status;

    in = open(self, O_RDONLY | O_CLOEXEC);
    out = open(generated, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (in < 0 || out < 0)
        goto done;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0)
                goto done;
            off += w;
        }
    }
    if (n < 0 || fchmod(out, 0700) != 0)
        goto done;
    close(in);
    close(out);
    in = out = -1;
    pid = fork();
    if (pid < 0)
        goto done;
    if (pid == 0) {
        execv(generated, child_argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            goto done;
    }
    rc = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
done:
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    printf("cache_generated_exec=%s\n", rc == 0 ? "ok" : "FAILED");
    return rc;
}

static int self_check(int argc, char **argv)
{
    gid_t groups[64];
    char cwd[512];
    int ng, i, ok = 1, fd;
    DIR *d;

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

    /* The app can add or replace programs beneath its own mutable cache. */
    fd = open("../system_cache/user/probe-created", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        close(fd);
        printf("cache_write=ok\n");
    } else {
        printf("cache_write=FAILED (%s)\n", strerror(errno));
        ok = 0;
    }

    /* The top-level cache grants this UID WX but not read/list permission. */
    d = opendir("../system_cache");
    if (d) {
        closedir(d);
        printf("cache_list=ALLOWED\n");
        ok = 0;
    } else {
        printf("cache_list=denied (%s)\n", strerror(errno));
    }

    /* The app cannot rename/replace the cache entry in its root-owned parent. */
    if (rename("../system_cache", "../stolen") == 0) {
        printf("rename_cache=ALLOWED\n");
        ok = 0;
    } else {
        printf("rename_cache=denied (%s)\n", strerror(errno));
    }

    /* Package payload is readable to the app within its own cache. */
    fd = open("../system_cache/app/extra.txt", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        printf("read_extra=ok\n");
    } else {
        printf("read_extra=FAILED (%s)\n", strerror(errno));
        ok = 0;
    }

    /* App-created code in its own cache can be chmod'd and executed. */
    if (copy_self_and_exec(argv[0]) != 0)
        ok = 0;

    if (setuid(0) == 0) {
        printf("setuid0=ALLOWED\n");
        ok = 0;
    } else {
        printf("setuid0=denied\n");
    }

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
