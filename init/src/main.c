/*
 * main.c - uinit entry point.
 *
 *   uinit [--root DIR] [--check] [-v]
 *
 *   --root DIR  Read everything from DIR instead of /. For development and tests.
 *   --check     Parse the id file and every reachable unit, and run nothing.
 *   -v          Trace each unit, mount and command.
 *
 * As PID 1, uinit never exits. After the entry unit it reaps orphaned processes
 * forever, because exiting PID 1 panics the kernel. Otherwise it exits 0 when
 * the entry unit succeeded and 1 when it failed.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uinit.h"

static void usage(FILE *f)
{
    fprintf(f, "usage: uinit [--root DIR] [--check] [-v]\n");
}

int main(int argc, char **argv)
{
    struct uinit_ctx ctx;
    char err[UINIT_ERRLEN];
    char *idpath;
    const char *root = "";
    size_t len;
    int pid1 = (getpid() == 1);
    int rc = 0;
    int i;

    memset(&ctx, 0, sizeof ctx);
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--root") && i + 1 < argc)
            root = argv[++i];
        else if (!strncmp(argv[i], "--root=", 7))
            root = argv[i] + 7;
        else if (!strcmp(argv[i], "--check"))
            ctx.check_only = 1;
        else if (!strcmp(argv[i], "-v"))
            uinit_verbose = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
    }

    /* Keep the root without a trailing slash. "/" becomes "", which is the device root. */
    len = strlen(root);
    if (len >= sizeof ctx.root) {
        uinit_log("--root path is too long");
        return 2;
    }
    memcpy(ctx.root, root, len + 1);
    while (len > 0 && ctx.root[len - 1] == '/')
        ctx.root[--len] = '\0';

    idpath = uinit_path_under(ctx.root, UINIT_ID_PATH);
    if (!idpath) {
        uinit_log("out of memory");
        rc = 1;
    } else if (uinit_load_ident(idpath, &ctx.id, err, sizeof err) < 0) {
        uinit_log("%s", err);
        rc = 1;
    } else {
        uinit_log("starting %s %s (%s)", ctx.id.name, ctx.id.version, ctx.id.channel);
        if (uinit_run_unit(&ctx, UINIT_ENTRY_PATH) < 0) {
            uinit_log("boot failed");
            rc = 1;
        }
    }
    free(idpath);

    if (pid1 && !ctx.check_only) {
        if (rc)
            uinit_log("staying up as PID 1 to reap processes");
        uinit_supervise();
    }
    return rc ? 1 : 0;
}
