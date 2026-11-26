/*
 * uinit.h - shared definitions for uinit, the Urados init system.
 *
 *   uinit reads the OS identity file  <root>/urados/etc/urados/init/id
 *   and runs exactly one entry unit   <root>/urados/etc/urados/init/hw/init.uinit
 *
 * A unit is a text file of statements. Statements can import other units
 * (import), mount file systems (mount), change modes and owners (chmod, chown),
 * print text (log), and run commands in one of several modes (exec). The
 * grammar is documented in src/parse.c, and a complete example tree is in
 * examples/.
 *
 * <root> is empty on a device. --root DIR stages the whole tree under DIR for
 * development and tests. A staging root is not a security boundary.
 */
#ifndef URADOS_UINIT_H
#define URADOS_UINIT_H

#include <limits.h>
#include <stddef.h>
#include <sys/types.h>

/* Config paths, relative to the root. */
#define UINIT_ID_PATH    "/urados/etc/urados/init/id"
#define UINIT_ENTRY_PATH "/urados/etc/urados/init/hw/init.uinit"

#define UINIT_MAX_DEPTH          16        /* nesting limit for import and run */
#define UINIT_MAX_FILE           (256 * 1024) /* largest unit file accepted */
#define UINIT_MAX_ARGS           256       /* largest argv for exec */
#define UINIT_MOUNT_TIMEOUT_DEFAULT 5      /* seconds to wait for a device */
#define UINIT_MOUNT_TIMEOUT_MAX  300
#define UINIT_ERRLEN             512

/* OS identity from the id file. Units see it as ${NAME}, ${VERSION} and ${CHANNEL}. */
struct uinit_ident {
    char name[128];
    char version[64];
    char channel[64];
};

struct uinit_ctx {
    char root[PATH_MAX];             /* "" on a device, else the staging directory */
    struct uinit_ident id;
    int depth;                       /* current import nesting level */
    int check_only;                  /* parse and follow imports, but execute nothing */
    int exit_requested;              /* an exec mode=exit* ended uinit; see exit_code */
    int exit_code;                   /* uinit's exit status when exit_requested is set */
};

enum uinit_op {
    UINIT_OP_RUN,                    /* import, run */
    UINIT_OP_MOUNT,                  /* mount */
    UINIT_OP_EXEC,                   /* exec, spawn: see enum uinit_exec_mode */
    UINIT_OP_CHMOD,                  /* chmod */
    UINIT_OP_CHOWN,                  /* chown */
    UINIT_OP_LOG,                    /* log */
};

enum uinit_src_kind {
    UINIT_SRC_UUID,                  /* UUID=<uuid> */
    UINIT_SRC_LABEL,                 /* LABEL=<label> */
    UINIT_SRC_PARTNUM,               /* PARTNUM=<disk>:<n> */
    UINIT_SRC_NONE,                  /* NONE: virtual file system with no device */
};

struct uinit_source {
    enum uinit_src_kind kind;
    char *value;                     /* UUID or LABEL text */
    char *disk;                      /* PARTNUM: disk name without /dev/, e.g. "sda" */
    unsigned int partnum;            /* PARTNUM: 1-based partition number */
};

struct uinit_mount {
    struct uinit_source src;
    char *target;                    /* as written in the unit; the root is added at run time */
    char *type;                      /* NULL: use the type found by probing the device */
    unsigned long flags;             /* MS_* flags */
    char *data;                      /* file system options, NULL if none */
    unsigned int timeout;            /* seconds to wait for the device to appear */
};

/*
 * How an exec statement runs its command.
 *
 *   WAIT           fork, wait for the command. A non-zero status is a failure.
 *   SPAWN          fork, continue at once. The command is reaped later.
 *   REPLACE        no fork. uinit becomes the command: same PID, and nothing
 *                  after the statement runs.
 *   EXIT_NONZERO fork, wait. A non-zero status ends uinit with that status.
 *   EXIT           fork, wait. uinit ends with the command's status, even 0.
 */
enum uinit_exec_mode {
    UINIT_MODE_WAIT,
    UINIT_MODE_SPAWN,
    UINIT_MODE_REPLACE,
    UINIT_MODE_EXIT_NONZERO,
    UINIT_MODE_EXIT,
};

struct uinit_exec {
    enum uinit_exec_mode mode;
    char *user;                      /* NULL: keep the current account */
    char *group;                     /* NULL: the account's primary group */
    char **groups;                   /* supplementary groups, NULL if not given */
    size_t ngroups;
    char **argv;                     /* argv[argc] == NULL */
    size_t argc;
};

/* How a finished command ended. sig is 0 unless it was killed by a signal. */
struct uinit_status {
    int code;                        /* exit status when it exited normally */
    int sig;                         /* signal number when it was killed */
};

/* chmod and chown. Only the fields for the statement's op are used. */
struct uinit_attr {
    char *path;                      /* target as written in the unit; the root is added at run time */
    int recursive;                   /* -R */
    mode_t mode;                     /* chmod: permission bits */
    int conditional_exec;             /* chmod: +X, add execute/search bits conditionally */
    char *owner;                     /* chown: user name or uid; NULL keeps the owner */
    char *group;                     /* chown: group name or gid; NULL keeps the group */
    int login_group;                 /* chown "owner:": set the group to the owner's login group */
};

struct uinit_stmt {
    enum uinit_op op;
    int line;
    int optional;                    /* failure is logged and the unit continues */
    union {
        char *run_path;              /* resolved to a path on the device */
        struct uinit_mount mount;
        struct uinit_exec exec;      /* exec */
        struct uinit_attr attr;      /* chmod and chown */
        char *log_text;
    } u;
};

struct uinit_unit {
    char *path;                      /* path as seen on the device, e.g. /urados/... */
    struct uinit_stmt *stmts;
    size_t nstmts;
};

/* util.c */
extern int uinit_verbose;
void uinit_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void uinit_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void uinit_seterr(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
char *uinit_path_under(const char *root, const char *path);
int uinit_mkdir_p(const char *path, mode_t mode);

/* config.c */
int uinit_load_ident(const char *path, struct uinit_ident *id, char *err, size_t errlen);

/* parse.c */
int uinit_parse_file(const struct uinit_ctx *ctx, const char *path,
                     struct uinit_unit *unit, char *err, size_t errlen);
int uinit_parse_text(const struct uinit_ctx *ctx, const char *path, const char *text,
                     struct uinit_unit *unit, char *err, size_t errlen);
void uinit_unit_free(struct uinit_unit *unit);

/* run.c */
int uinit_run_unit(struct uinit_ctx *ctx, const char *path);

/* exec.c
 *
 * Returns 0 when the command ran and ended (st says how), -1 when it could not
 * be run and uinit's identity is unchanged, and -2 when a replace failed after
 * uinit changed its identity. -2 means uinit must stop.
 */
int uinit_exec_run(const struct uinit_exec *e, struct uinit_status *st,
                   char *err, size_t errlen);
int uinit_status_exit_code(const struct uinit_status *st);
void uinit_supervise(void) __attribute__((noreturn));

/* attr.c */
int uinit_lookup_uid(const char *s, uid_t *out, char *err, size_t errlen);
int uinit_lookup_gid(const char *s, gid_t *out, char *err, size_t errlen);
int uinit_do_chmod(const struct uinit_ctx *ctx, const struct uinit_attr *a,
                   char *err, size_t errlen);
int uinit_do_chown(const struct uinit_ctx *ctx, const struct uinit_attr *a,
                   char *err, size_t errlen);

/* mount.c */
int uinit_mount_opt(const char *name, unsigned long *flags);
int uinit_do_mount(const struct uinit_ctx *ctx, const struct uinit_mount *m,
                   char *err, size_t errlen);

#endif
