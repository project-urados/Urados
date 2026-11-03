#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "urados_pkg.h"

int main(int argc, char **argv)
{
    static const char *names[] = { "app/one", "app/two", "app/three" };
    unsigned char zeros[32768] = { 0 };
    pkg_verified v;
    char err[512] = "";
    int appfd, rc = 1;
    size_t i;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <zip> <empty-app-directory>\n", argv[0]);
        return 2;
    }
    memset(&v, 0, sizeof(v));
    v.digests = calloc(sizeof(names) / sizeof(names[0]), sizeof(*v.digests));
    if (!v.digests)
        return 2;
    v.ndigests = sizeof(names) / sizeof(names[0]);
    snprintf(v.manifest.entry, sizeof(v.manifest.entry), "system_cache/app/one");
    for (i = 0; i < v.ndigests; i++) {
        v.digests[i].name = strdup(names[i]);
        if (!v.digests[i].name) {
            pkg_verified_free(&v);
            return 2;
        }
        pkg_sha256(zeros, sizeof(zeros), v.digests[i].hex);
    }
    appfd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (appfd < 0) {
        perror("open output directory");
        pkg_verified_free(&v);
        return 2;
    }
    if (pkg_extract(argv[1], appfd, getgid(), &v, err, sizeof(err)) != 0 &&
        strstr(err, "configured size limit"))
        rc = 0;
    else if (err[0])
        fprintf(stderr, "unexpected extraction result: %s\n", err);
    close(appfd);
    pkg_verified_free(&v);
    return rc;
}
