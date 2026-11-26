/*
 * mount.c - mounts file systems named by UUID, LABEL, PARTNUM, or NONE.
 *
 * Devices are found by scanning /sys/class/block (and /sys/block/<disk> for
 * partitions) and probing each device node with libblkid. A device that is not
 * there yet is retried every 100 ms until the statement's timeout expires, so
 * a slow USB or MMC device does not fail the boot straight away. A UUID or LABEL
 * that matches more than one device is an error, because the choice would
 * otherwise depend on probe order.
 */
#include <blkid/blkid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mount.h>
#include <time.h>
#include <unistd.h>

#include "uinit.h"

struct mount_opt {
    const char *name;
    unsigned long set;
    unsigned long clear;
};

static const struct mount_opt mount_opts[] = {
    { "ro",         MS_RDONLY,      0 },
    { "rw",         0,              MS_RDONLY },
    { "nosuid",     MS_NOSUID,      0 },
    { "nodev",      MS_NODEV,       0 },
    { "noexec",     MS_NOEXEC,      0 },
    { "noatime",    MS_NOATIME,     0 },
    { "nodiratime", MS_NODIRATIME,  0 },
    { "relatime",   MS_RELATIME,    0 },
    { "sync",       MS_SYNCHRONOUS, 0 },
    { "silent",     MS_SILENT,      0 },
    { "lazytime",   MS_LAZYTIME,    0 },
};

/* Sets or clears the MS_* bits for a generic option name. Returns 0 if name is not a flag. */
int uinit_mount_opt(const char *name, unsigned long *flags)
{
    size_t i;

    for (i = 0; i < sizeof mount_opts / sizeof mount_opts[0]; i++) {
        if (!strcmp(name, mount_opts[i].name)) {
            *flags = (*flags | mount_opts[i].set) & ~mount_opts[i].clear;
            return 1;
        }
    }
    return 0;
}

/* What was found for a source. path is always set when a device was found. */
struct devinfo {
    char path[PATH_MAX];
    char uuid[64];
    char label[256];
    char type[64];
};

/*
 * Probes one device. Returns 0 if a file system or partition table was seen,
 * 1 if the device holds no signature, and -1 if it cannot be opened or probed.
 */
static int probe_dev(const char *name, struct devinfo *di)
{
    /* Copy the name first: callers may pass di->path itself. */
    char devpath[PATH_MAX];
    blkid_probe pr;
    const char *val;
    size_t len;
    int rc = -1;

    snprintf(devpath, sizeof devpath, "%s", name);
    pr = blkid_new_probe_from_filename(devpath);
    if (!pr)
        return -1;
    if (blkid_probe_enable_superblocks(pr, 1) != 0)
        goto out;
    if (blkid_probe_set_superblocks_flags(pr, BLKID_SUBLKS_UUID | BLKID_SUBLKS_LABEL |
                                              BLKID_SUBLKS_TYPE) != 0)
        goto out;

    switch (blkid_do_safeprobe(pr)) {
    case 0:
        break;
    case 1:
        rc = 1;
        goto out;
    default:
        goto out;
    }

    di->uuid[0] = '\0';
    di->label[0] = '\0';
    di->type[0] = '\0';
    snprintf(di->path, sizeof di->path, "%s", devpath);
    if (blkid_probe_lookup_value(pr, "UUID", &val, &len) == 0)
        snprintf(di->uuid, sizeof di->uuid, "%s", val);
    if (blkid_probe_lookup_value(pr, "LABEL", &val, &len) == 0)
        snprintf(di->label, sizeof di->label, "%s", val);
    if (blkid_probe_lookup_value(pr, "TYPE", &val, &len) == 0)
        snprintf(di->type, sizeof di->type, "%s", val);
    rc = 0;

out:
    blkid_free_probe(pr);
    return rc;
}

/* Scans every block device for a matching UUID or LABEL. Returns 0 found, 1 not yet, -1 error. */
static int locate_by_id(const struct uinit_source *src, struct devinfo *found,
                        char *err, size_t errlen)
{
    DIR *d = opendir("/sys/class/block");
    struct dirent *de;
    int matches = 0;

    if (!d) {
        uinit_seterr(err, errlen, "cannot read /sys/class/block: %s (mount sysfs first)",
                     strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        struct devinfo di;
        char path[PATH_MAX];
        int hit;

        if (de->d_name[0] == '.')
            continue;
        snprintf(path, sizeof path, "/dev/%s", de->d_name);
        if (probe_dev(path, &di) != 0)
            continue;

        if (src->kind == UINIT_SRC_UUID)
            hit = !strcasecmp(di.uuid, src->value) && di.uuid[0];
        else
            hit = !strcmp(di.label, src->value) && di.label[0];
        if (!hit)
            continue;
        if (matches == 0)
            *found = di;
        matches++;
    }
    closedir(d);

    if (matches > 1) {
        uinit_seterr(err, errlen, "more than one device matches %s",
                     src->kind == UINIT_SRC_UUID ? "UUID" : "LABEL");
        return -1;
    }
    return matches ? 0 : 1;
}

/* Finds partition n of a disk through sysfs. Returns 0 found, 1 not yet, -1 error. */
static int locate_partnum(const struct uinit_source *src, struct devinfo *found,
                          char *err, size_t errlen)
{
    char dir[PATH_MAX];
    DIR *d;
    struct dirent *de;

    snprintf(dir, sizeof dir, "/sys/block/%s", src->disk);
    d = opendir(dir);
    if (!d) {
        if (errno == ENOENT)
            return 1;
        uinit_seterr(err, errlen, "cannot read %s: %s", dir, strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char pf[2 * PATH_MAX + NAME_MAX], num[32];
        FILE *f;

        if (de->d_name[0] == '.')
            continue;
        snprintf(pf, sizeof pf, "%s/%s/partition", dir, de->d_name);
        f = fopen(pf, "r");
        if (!f)
            continue;
        if (!fgets(num, sizeof num, f))
            num[0] = '\0';
        fclose(f);

        if (strtoul(num, NULL, 10) != src->partnum)
            continue;
        closedir(d);
        {
            char dev[PATH_MAX];

            snprintf(dev, sizeof dev, "/dev/%s", de->d_name);
            /*
             * The node can appear before it is readable, so an unreadable node
             * means "not yet". A readable node with no signature is still found:
             * the mount then needs type=, which uinit_do_mount checks.
             */
            if (probe_dev(dev, found) < 0)
                return 1;
        }
        return 0;
    }
    closedir(d);
    return 1;
}

/* Polls until the source is found or the timeout expires. Returns 0 found, -1 failed. */
static int wait_for(const struct uinit_mount *m, struct devinfo *found, char *err, size_t errlen)
{
    struct timespec start, now;
    const char *what = m->src.kind == UINIT_SRC_UUID ? "UUID" :
                       m->src.kind == UINIT_SRC_LABEL ? "LABEL" : "PARTNUM";

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        int rc = m->src.kind == UINIT_SRC_PARTNUM
                     ? locate_partnum(&m->src, found, err, errlen)
                     : locate_by_id(&m->src, found, err, errlen);
        long long waited_ms;

        if (rc <= 0)
            return rc == 0 ? 0 : -1;

        clock_gettime(CLOCK_MONOTONIC, &now);
        waited_ms = (now.tv_sec - start.tv_sec) * 1000LL +
                    (now.tv_nsec - start.tv_nsec) / 1000000LL;
        if (waited_ms >= (long long)m->timeout * 1000LL) {
            if (m->src.kind == UINIT_SRC_PARTNUM)
                uinit_seterr(err, errlen, "no partition %u on disk %s after %u s",
                             m->src.partnum, m->src.disk, m->timeout);
            else
                uinit_seterr(err, errlen, "no device with %s=%s after %u s", what,
                             m->src.value, m->timeout);
            return -1;
        }
        usleep(100 * 1000);
    }
}

int uinit_do_mount(const struct uinit_ctx *ctx, const struct uinit_mount *m,
                   char *err, size_t errlen)
{
    struct devinfo found;
    const char *src = "none";
    const char *type = m->type;
    char *target;
    int rc = -1;

    memset(&found, 0, sizeof found);
    if (m->src.kind != UINIT_SRC_NONE) {
        if (wait_for(m, &found, err, errlen) < 0)
            return -1;
        src = found.path;
        if (!type) {
            if (!found.type[0]) {
                uinit_seterr(err, errlen, "no file system found on %s", src);
                return -1;
            }
            type = found.type;
        }
    }

    target = uinit_path_under(ctx->root, m->target);
    if (!target) {
        uinit_seterr(err, errlen, "out of memory");
        return -1;
    }
    if (uinit_mkdir_p(target, 0755) < 0) {
        uinit_seterr(err, errlen, "cannot create %s: %s", m->target, strerror(errno));
        goto out;
    }
    if (mount(src, target, type, m->flags, m->data) < 0) {
        uinit_seterr(err, errlen, "mount %s on %s (%s): %s", src, m->target, type,
                     strerror(errno));
        goto out;
    }
    uinit_debug("mounted %s on %s (%s)", src, m->target, type);
    rc = 0;

out:
    free(target);
    return rc;
}
