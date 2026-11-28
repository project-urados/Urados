/*
 * urpkg_main.c - command-line entry point for the package manager.
 *
 *   urpkg [--root DIR] [--keys DIR] install <source>
 *   urpkg [--root DIR] [--keys DIR] start <name> [args...]
 *   urpkg [--root DIR] [--keys DIR] verify <package.zip>
 *   urpkg [--root DIR] [--keys DIR] stop [--force] [--timeout SEC] <name>
 *   urpkg [--root DIR] [--keys DIR] update [--force] [--timeout SEC] <source>
 *   urpkg [--root DIR] [--keys DIR] uninstall [--force] [--timeout SEC] <name>
 *
 *   --root DIR    Prefix every device path (staging and tests). Default: /.
 *   --keys DIR    Administrator-installed PEM X.509 CA root certificates (*.crt).
 *                 Default: <root>/etc/urados/keys.
 *   <source>      A local path or an http(s) URL.
 *   --force       stop/update/uninstall: SIGKILL the app at once, no SIGTERM first.
 *   --timeout SEC stop/update/uninstall: seconds to wait after SIGTERM before
 *                 SIGKILL (default 5, range 0-600).
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "urados_pkg.h"

#define STOP_DEFAULT_TIMEOUT_SEC 5
#define STOP_MAX_TIMEOUT_SEC     600

static void usage(FILE *f)
{
    fputs("usage: urpkg [--root DIR] [--keys DIR] <command>\n"
          "  install <source>         install a signed package (path or http(s) URL)\n"
          "  start <name> [args...]   verify, extract and run an installed app\n"
          "  verify <package.zip>     validate its signer certificate chain and signature\n"
          "  stop [--force] [--timeout SEC] <name>\n"
          "                           stop every process of an app (SIGTERM, then SIGKILL)\n"
          "  update [--force] [--timeout SEC] <source>\n"
          "                           replace an installed app with a newer signed version\n"
          "  uninstall [--force] [--timeout SEC] <name>\n"
          "                           stop an app and remove its account, runtime and data\n",
          f);
}

/*
 * Parses the options of stop, update and uninstall. Options must come before
 * the single operand. On success *i is advanced past them and the operand is
 * the remaining argument. Returns 0, or -1 after printing a usage error.
 */
static int parse_stop_options(int argc, char **argv, int *i, pkg_stop_opts *so)
{
    so->force = 0;
    so->timeout_ms = STOP_DEFAULT_TIMEOUT_SEC * 1000;

    while (*i < argc && argv[*i][0] == '-') {
        if (strcmp(argv[*i], "--force") == 0) {
            so->force = 1;
            (*i)++;
        } else if (strcmp(argv[*i], "--timeout") == 0 && *i + 1 < argc) {
            char *end = NULL;
            long sec;

            errno = 0;
            sec = strtol(argv[*i + 1], &end, 10);
            if (errno != 0 || end == argv[*i + 1] || *end != '\0' || sec < 0 ||
                sec > STOP_MAX_TIMEOUT_SEC) {
                fprintf(stderr, "urpkg: error: --timeout must be 0-%d seconds\n",
                        STOP_MAX_TIMEOUT_SEC);
                return -1;
            }
            so->timeout_ms = (int)sec * 1000;
            *i += 2;
        } else {
            return -1;
        }
    }
    return 0;
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
    if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "update") == 0 ||
        strcmp(cmd, "uninstall") == 0) {
        pkg_stop_opts so;

        if (parse_stop_options(argc, argv, &i, &so) != 0 || i != argc - 1) {
            usage(stderr);
            return 2;
        }
        if (strcmp(cmd, "stop") == 0)
            return pkg_cmd_stop(argv[i], &so, &o);
        if (strcmp(cmd, "update") == 0)
            return pkg_cmd_update(argv[i], &so, &o);
        return pkg_cmd_uninstall(argv[i], &so, &o);
    }
    usage(stderr);
    return 2;
}
