/*
 * probe.c - static integration-test app for the /run/app runtime model.
 * The package entry is freshly verified and extracted before each launch.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
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

static int self_check(int argc, char **argv)
{
    gid_t groups[64];
    char cwd[512], runtime[512], extra[600], newfile[600];
    int ng, i, ok = 1, fd;
    DIR *d;
    struct stat st;

    printf("uid=%u gid=%u euid=%u\n", (unsigned)getuid(), (unsigned)getgid(),
           (unsigned)geteuid());
    ng = getgroups(64, groups);
    printf("groups=");
    for (i = 0; i < ng; i++)
        printf("%s%u", i ? "," : "", (unsigned)groups[i]);
    printf("\n");
    if (getcwd(cwd, sizeof(cwd)))
        printf("cwd=%s\n", cwd);
    printf("no_new_privs=%d\n", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    printf("args=%d\n", argc - 1);
    for (i = 1; i < argc; i++)
        printf("arg=%s\n", argv[i]);

    snprintf(runtime, sizeof(runtime), "%s", argv[0]);
    {
        char *slash = strrchr(runtime, '/');
        if (!slash) {
            fprintf(stderr, "probe: entry path is not absolute\n");
            return 1;
        }
        *slash = '\0';
    }
    snprintf(extra, sizeof(extra), "%s/extra.txt", runtime);
    snprintf(newfile, sizeof(newfile), "%s/created-by-app", runtime);

    if (stat(runtime, &st) == 0 && st.st_uid == getuid() && st.st_gid == 0 &&
        (st.st_mode & 07777) == 0570)
        printf("runtime_dir=appuid:root 570\n");
    else {
        printf("runtime_dir=FAILED\n");
        ok = 0;
    }
    if (stat(argv[0], &st) == 0 && st.st_uid == getuid() && st.st_gid == 0 &&
        (st.st_mode & 07777) == 0570)
        printf("runtime_file=appuid:root 570\n");
    else {
        printf("runtime_file=FAILED\n");
        ok = 0;
    }

    /* The app can read and execute its payload, but cannot write it by default. */
    fd = open(extra, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        printf("read_extra=ok\n");
    } else {
        printf("read_extra=FAILED (%s)\n", strerror(errno));
        ok = 0;
    }
    fd = open(argv[0], O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        close(fd);
        printf("runtime_file_write=ALLOWED\n");
        ok = 0;
    } else {
        printf("runtime_file_write=denied (%s)\n", strerror(errno));
    }
    fd = open(newfile, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        close(fd);
        printf("runtime_create=ALLOWED\n");
        ok = 0;
    } else {
        printf("runtime_create=denied (%s)\n", strerror(errno));
    }

    /* The app owns its runtime directory, but cannot replace its /run/app entry. */
    if (rename(runtime, "/run/app/stolen") == 0) {
        printf("rename_runtime=ALLOWED\n");
        ok = 0;
    } else {
        printf("rename_runtime=denied (%s)\n", strerror(errno));
    }
    d = opendir(runtime);
    if (d) {
        closedir(d);
        printf("runtime_list=ok\n");
    } else {
        printf("runtime_list=FAILED (%s)\n", strerror(errno));
        ok = 0;
    }

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
