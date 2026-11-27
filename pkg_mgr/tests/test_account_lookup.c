#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "urados_pkg.h"

int main(void)
{
    const struct passwd *pw = getpwuid(getuid());
    const struct group *gr = getgrgid(getgid());
    uid_t uid;
    gid_t primary_gid, gid;

    if (!pw || pkg_lookup_passwd("", pw->pw_name, &uid, &primary_gid) != 0 ||
        uid != pw->pw_uid || primary_gid != pw->pw_gid) {
        fputs("libc/NSS passwd lookup did not match getpwuid()\n", stderr);
        return 1;
    }
    if (!gr || pkg_lookup_group("", gr->gr_name, &gid) != 0 || gid != gr->gr_gid) {
        fputs("libc/NSS group lookup did not match getgrgid()\n", stderr);
        return 1;
    }
    puts("libc/NSS passwd and group lookups passed");
    return 0;
}
