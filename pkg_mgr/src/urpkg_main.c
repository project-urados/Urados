/*
 * urpkg_main.c - command-line entry point for the package manager.
 *
 *   urpkg [--root DIR] [--keys DIR] install <source>
 *   urpkg [--root DIR] [--keys DIR] start <name> [args...]
 *   urpkg [--root DIR] [--keys DIR] verify <package.zip>
 *
 *   --root DIR  Prefix every device path (staging and tests). Default: /.
 *   --keys DIR  Administrator-installed PEM X.509 CA root certificates (*.crt).
 *               Default: <root>/etc/urados/keys.
 *   <source>    A local path or an http(s) URL.
 */
#include <stdio.h>
#include <string.h>

#include "urados_pkg.h"

static void usage(FILE *f)
{
    fputs("usage: urpkg [--root DIR] [--keys DIR] <command>\n"
          "  install <source>         install a signed package (path or http(s) URL)\n"
          "  start <name> [args...]   verify, extract and run an installed app\n"
          "  verify <package.zip>     validate its signer certificate chain and signature\n",
          f);
}

int main(int argc, char **argv)
{
    static char rootbuf[PKG_PATH_MAX];
    static char keysbuf[PKG_PATH_MAX];
    const char *root = "";
    const char *keys = NULL;
    const char *cmd;
    pkg_opts o;
    size_t l;
    int i = 1;

    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "--root") == 0 && i + 1 < argc)
            root = argv[++i];
        else if (strcmp(argv[i], "--keys") == 0 && i + 1 < argc)
            keys = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
        i++;
    }
    if (i >= argc) {
        usage(stderr);
        return 2;
    }
    cmd = argv[i++];

    if (root[0] != '\0' && root[0] != '/') {
        fputs("urpkg: error: --root must be an absolute path\n", stderr);
        return 2;
    }
    if (strlen(root) >= sizeof(rootbuf)) {
        fputs("urpkg: error: --root is too long\n", stderr);
        return 2;
    }
    snprintf(rootbuf, sizeof(rootbuf), "%s", root);
    l = strlen(rootbuf);
    while (l > 0 && rootbuf[l - 1] == '/')
        rootbuf[--l] = '\0';
    o.root = rootbuf;

    if (!keys) {
        snprintf(keysbuf, sizeof(keysbuf), "%s%s", rootbuf, PKG_KEYS_SUBDIR);
        keys = keysbuf;
    }
    o.keys_dir = keys;

    if (strcmp(cmd, "install") == 0) {
        if (i != argc - 1) {
            usage(stderr);
            return 2;
        }
        return pkg_cmd_install(argv[i], &o);
    }
    if (strcmp(cmd, "start") == 0) {
        if (i >= argc) {
            usage(stderr);
            return 2;
        }
        return pkg_cmd_start(argv[i], argc - i - 1, argv + i + 1, &o);
    }
    if (strcmp(cmd, "verify") == 0) {
        if (i != argc - 1) {
            usage(stderr);
            return 2;
        }
        return pkg_cmd_verify(argv[i], &o);
    }
    usage(stderr);
    return 2;
}
