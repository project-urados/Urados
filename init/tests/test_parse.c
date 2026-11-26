/*
 * test_parse.c - unit tests for the .uinit parser and the id loader.
 *
 * Run from the init/ directory (make test does this). The id-file tests write
 * their fixtures to build/, so build/ must exist.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include "uinit.h"

#define ENTRY "/urados/etc/urados/init/hw/init.uinit"

static int failures, passes;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (cond) {                                                         \
            passes++;                                                       \
        } else {                                                            \
            failures++;                                                     \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);            \
            fprintf(stderr, __VA_ARGS__);                                   \
            fputc('\n', stderr);                                            \
        }                                                                   \
    } while (0)

static struct uinit_ctx ctx;

static void setup_ctx(void)
{
    memset(&ctx, 0, sizeof ctx);
    strcpy(ctx.id.name, "Urados");
    strcpy(ctx.id.version, "1.0.0");
    strcpy(ctx.id.channel, "stable");
}

/* Parses text. Returns 0 on success and fills err on failure. */
static int parse(const char *text, struct uinit_unit *u, char *err)
{
    return uinit_parse_text(&ctx, ENTRY, text, u, err, UINIT_ERRLEN);
}

/* Parses text that must be valid. Returns 0 if it was. */
static int parse_ok(const char *name, const char *text, struct uinit_unit *u)
{
    char err[UINIT_ERRLEN];

    if (parse(text, u, err) == 0)
        return 0;
    failures++;
    fprintf(stderr, "FAIL %s: unexpected error: %s\n", name, err);
    return -1;
}

/* Parses text that must fail, and checks that the error mentions want. */
static void expect_err(const char *name, const char *text, const char *want)
{
    struct uinit_unit u;
    char err[UINIT_ERRLEN];

    if (parse(text, &u, err) == 0) {
        failures++;
        fprintf(stderr, "FAIL %s: parsed without error\n", name);
        uinit_unit_free(&u);
        return;
    }
    if (strstr(err, want)) {
        passes++;
    } else {
        failures++;
        fprintf(stderr, "FAIL %s: error '%s' does not mention '%s'\n", name, err, want);
    }
}

static void test_log_and_expand(void)
{
    struct uinit_unit u;

    if (parse_ok("log", "log booting ${NAME} ${VERSION} (${CHANNEL})\n", &u))
        return;
    CHECK(u.nstmts == 1, "log: want 1 statement, got %zu", u.nstmts);
    CHECK(u.stmts[0].op == UINIT_OP_LOG, "log: wrong op");
    CHECK(!strcmp(u.stmts[0].u.log_text, "booting Urados 1.0.0 (stable)"),
          "log: got '%s'", u.stmts[0].u.log_text);
    uinit_unit_free(&u);
}

static void test_quoting_and_comments(void)
{
    struct uinit_unit u;

    if (!parse_ok("quotes", "log \"a  b\" 'c ${NAME}' \"e\\\"f\"\n", &u)) {
        CHECK(!strcmp(u.stmts[0].u.log_text, "a  b c Urados e\"f"),
              "quotes: got '%s'", u.stmts[0].u.log_text);
        uinit_unit_free(&u);
    }
    if (!parse_ok("comment", "log hi # a comment\n", &u)) {
        CHECK(!strcmp(u.stmts[0].u.log_text, "hi"), "comment: got '%s'", u.stmts[0].u.log_text);
        uinit_unit_free(&u);
    }
    if (!parse_ok("hash", "log a#b\n", &u)) {
        CHECK(!strcmp(u.stmts[0].u.log_text, "a#b"), "hash: got '%s'", u.stmts[0].u.log_text);
        uinit_unit_free(&u);
    }
    if (!parse_ok("blank", "\n   \n# only a comment\n\t\n", &u)) {
        CHECK(u.nstmts == 0, "blank: want 0 statements, got %zu", u.nstmts);
        uinit_unit_free(&u);
    }
    if (!parse_ok("crlf", "log hi\r\nlog there\r\n", &u)) {
        CHECK(u.nstmts == 2, "crlf: want 2 statements, got %zu", u.nstmts);
        CHECK(!strcmp(u.stmts[1].u.log_text, "there"), "crlf: got '%s'", u.stmts[1].u.log_text);
        uinit_unit_free(&u);
    }
}

static void test_syntax_errors(void)
{
    expect_err("unknown var", "log ${FOO}\n", "unknown variable 'FOO'");
    expect_err("unterminated var", "log ${NAME\n", "unterminated ${");
    expect_err("unterminated quote", "log \"abc\n", "unterminated quote");
    expect_err("unknown stmt", "frobnicate x\n", "unknown statement 'frobnicate'");
    expect_err("line number", "log ok\nbogus x\n", ":2: ");
    expect_err("empty log", "log\n", "log needs a message");
    expect_err("optional alone", "optional\n", "optional needs a statement");
}

static void test_mount_sources(void)
{
    struct uinit_unit u;

    if (!parse_ok("uuid", "mount UUID=6F1D2A3C-4B5E-4F70-8A9B-0C1D2E3F4A5B /system opts=ro,nosuid timeout=20\n", &u)) {
        const struct uinit_mount *m = &u.stmts[0].u.mount;

        CHECK(m->src.kind == UINIT_SRC_UUID, "uuid: wrong kind");
        CHECK(!strcmp(m->src.value, "6f1d2a3c-4b5e-4f70-8a9b-0c1d2e3f4a5b"),
              "uuid: not lowercased: '%s'", m->src.value);
        CHECK(!strcmp(m->target, "/system"), "uuid: target '%s'", m->target);
        CHECK(m->flags == (MS_RDONLY | MS_NOSUID), "uuid: flags %lx", m->flags);
        CHECK(m->data == NULL, "uuid: data should be NULL");
        CHECK(m->timeout == 20, "uuid: timeout %u", m->timeout);
        uinit_unit_free(&u);
    }
    if (!parse_ok("label", "mount LABEL=urados-data /data type=ext4 opts=errors=remount-ro,nodev\n", &u)) {
        const struct uinit_mount *m = &u.stmts[0].u.mount;

        CHECK(m->src.kind == UINIT_SRC_LABEL && !strcmp(m->src.value, "urados-data"),
              "label: wrong source");
        CHECK(!strcmp(m->type, "ext4"), "label: type '%s'", m->type);
        CHECK(m->flags == MS_NODEV, "label: flags %lx", m->flags);
        CHECK(m->data && !strcmp(m->data, "errors=remount-ro"), "label: data '%s'",
              m->data ? m->data : "(null)");
        CHECK(m->timeout == UINIT_MOUNT_TIMEOUT_DEFAULT, "label: default timeout %u", m->timeout);
        uinit_unit_free(&u);
    }
    if (!parse_ok("partnum", "mount PARTNUM=sda:3 /mnt/backup\nmount PARTNUM=nvme0n1:12 /mnt/x\n", &u)) {
        const struct uinit_mount *a = &u.stmts[0].u.mount;
        const struct uinit_mount *b = &u.stmts[1].u.mount;

        CHECK(a->src.kind == UINIT_SRC_PARTNUM && !strcmp(a->src.disk, "sda") && a->src.partnum == 3,
              "partnum: sda:3 parsed as %s:%u", a->src.disk, a->src.partnum);
        CHECK(!strcmp(b->src.disk, "nvme0n1") && b->src.partnum == 12,
              "partnum: nvme0n1:12 parsed as %s:%u", b->src.disk, b->src.partnum);
        uinit_unit_free(&u);
    }
    if (!parse_ok("none", "mount NONE /proc type=proc opts=nosuid,nodev,noexec\n", &u)) {
        const struct uinit_mount *m = &u.stmts[0].u.mount;

        CHECK(m->src.kind == UINIT_SRC_NONE, "none: wrong kind");
        CHECK(!strcmp(m->type, "proc"), "none: type '%s'", m->type);
        CHECK(m->timeout == 0, "none: timeout %u, want 0", m->timeout);
        CHECK(m->flags == (MS_NOSUID | MS_NODEV | MS_NOEXEC), "none: flags %lx", m->flags);
        uinit_unit_free(&u);
    }
    if (!parse_ok("optional", "optional mount LABEL=x /y\n", &u)) {
        CHECK(u.stmts[0].optional && u.stmts[0].op == UINIT_OP_MOUNT, "optional: flag not set");
        uinit_unit_free(&u);
    }
}

static void test_mount_errors(void)
{
    expect_err("bad uuid", "mount UUID=1234 /x\n", "invalid UUID");
    expect_err("unknown source", "mount DEVICE=sda /x\n", "unknown source");
    expect_err("empty label", "mount LABEL= /x\n", "LABEL must be");
    expect_err("partnum no n", "mount PARTNUM=sda /x\n", "PARTNUM needs");
    expect_err("partnum zero", "mount PARTNUM=sda:0 /x\n", "partition number must be 1 to 4096");
    expect_err("partnum text", "mount PARTNUM=sda:a /x\n", "must be a number");
    expect_err("none no type", "mount NONE /proc\n", "NONE needs type=");
    expect_err("target dotdot", "mount LABEL=a /../x\n", "must be an absolute path");
    expect_err("target relative", "mount LABEL=a x\n", "must be an absolute path");
    expect_err("target root", "mount LABEL=a /\n", "must be an absolute path");
    expect_err("timeout too big", "mount LABEL=a /x timeout=301\n", "timeout must be");
    expect_err("timeout text", "mount LABEL=a /x timeout=x\n", "timeout must be");
    expect_err("unknown option", "mount LABEL=a /x bogus=1\n", "unknown mount option");
    expect_err("empty opts", "mount LABEL=a /x opts=\n", "empty opts=");
    expect_err("empty opt entry", "mount LABEL=a /x opts=ro,,rw\n", "empty entry");
    expect_err("empty type", "mount LABEL=a /x type=\n", "empty type=");
    expect_err("type twice", "mount LABEL=a /x type=ext4 type=ext4\n", "type= given twice");
    expect_err("no target", "mount LABEL=a\n", "needs a source and a target");
}

static void test_exec(void)
{
    struct uinit_unit u;

    if (!parse_ok("exec", "exec user=nobody group=nogroup groups=adm,nogroup -- /bin/sh -c \"echo hi\" extra\n", &u)) {
        const struct uinit_exec *e = &u.stmts[0].u.exec;

        CHECK(u.stmts[0].op == UINIT_OP_EXEC, "exec: wrong op");
        CHECK(!strcmp(e->user, "nobody"), "exec: user");
        CHECK(!strcmp(e->group, "nogroup"), "exec: group");
        CHECK(e->ngroups == 2 && !strcmp(e->groups[0], "adm") && !strcmp(e->groups[1], "nogroup"),
              "exec: groups");
        CHECK(e->argc == 4, "exec: argc %zu", e->argc);
        CHECK(!strcmp(e->argv[0], "/bin/sh") && !strcmp(e->argv[2], "echo hi"), "exec: argv");
        CHECK(e->argv[e->argc] == NULL, "exec: argv not NULL-terminated");
        uinit_unit_free(&u);
    }
    if (!parse_ok("spawn", "spawn -- /bin/true\n", &u)) {
        const struct uinit_exec *e = &u.stmts[0].u.exec;

        CHECK(u.stmts[0].op == UINIT_OP_EXEC, "spawn: wrong op");
        CHECK(e->mode == UINIT_MODE_SPAWN, "spawn: mode %d", e->mode);
        CHECK(e->user == NULL && e->group == NULL && e->groups == NULL, "spawn: identity set");
        CHECK(e->argc == 1 && !strcmp(e->argv[0], "/bin/true"), "spawn: argv");
        uinit_unit_free(&u);
    }
    if (!parse_ok("no separator", "exec /bin/true\n", &u)) {
        CHECK(u.stmts[0].u.exec.argc == 1, "no separator: argc");
        CHECK(u.stmts[0].u.exec.mode == UINIT_MODE_WAIT, "default mode is wait");
        uinit_unit_free(&u);
    }
    if (!parse_ok("modes",
                  "exec mode=wait -- /bin/true\n"
                  "exec mode=spawn -- /bin/true\n"
                  "exec mode=replace -- /bin/true\n"
                  "exec mode=exit-nonzero -- /bin/true\n"
                  "exec mode=exit -- /bin/true\n", &u)) {
        CHECK(u.nstmts == 5, "modes: %zu statements", u.nstmts);
        CHECK(u.stmts[0].u.exec.mode == UINIT_MODE_WAIT, "mode wait");
        CHECK(u.stmts[1].u.exec.mode == UINIT_MODE_SPAWN, "mode spawn");
        CHECK(u.stmts[2].u.exec.mode == UINIT_MODE_REPLACE, "mode replace");
        CHECK(u.stmts[3].u.exec.mode == UINIT_MODE_EXIT_NONZERO, "mode exit-nonzero");
        CHECK(u.stmts[4].u.exec.mode == UINIT_MODE_EXIT, "mode exit");
        uinit_unit_free(&u);
    }
    if (!parse_ok("mode with identity", "exec mode=replace user=nobody group=nogroup -- /bin/true\n", &u)) {
        CHECK(u.stmts[0].u.exec.mode == UINIT_MODE_REPLACE && u.stmts[0].u.exec.user,
              "mode with identity: fields");
        uinit_unit_free(&u);
    }
    expect_err("unknown mode", "exec mode=fork -- /bin/true\n", "unknown mode 'fork'");
    expect_err("empty mode", "exec mode= -- /bin/true\n", "unknown mode ''");
    expect_err("mode twice", "exec mode=wait mode=exit -- /bin/true\n", "mode= given twice");
    expect_err("spawn with mode", "spawn mode=exit -- /bin/true\n", "spawn takes no mode=");
    if (!parse_ok("mode after command is an argument", "exec /bin/true mode=exit\n", &u)) {
        CHECK(u.stmts[0].u.exec.mode == UINIT_MODE_WAIT, "mode after command: mode changed");
        CHECK(u.stmts[0].u.exec.argc == 2 && !strcmp(u.stmts[0].u.exec.argv[1], "mode=exit"),
              "mode after command: argv");
        uinit_unit_free(&u);
    }
    if (!parse_ok("optional exec", "optional exec user=1000 group=1000 -- /bin/true\n", &u)) {
        CHECK(u.stmts[0].optional && u.stmts[0].u.exec.user, "optional exec: fields");
        uinit_unit_free(&u);
    }
    expect_err("exec no cmd", "exec\n", "needs a command");
    expect_err("exec only opts", "exec user=nobody\n", "needs a command");
    expect_err("empty user", "exec user= /bin/true\n", "empty user=");
    expect_err("user twice", "exec user=a user=b /bin/true\n", "user= given twice");
    expect_err("group twice", "exec group=a group=b /bin/true\n", "group= given twice");
    expect_err("groups empty name", "exec groups=a,,b /bin/true\n", "empty name in groups=");
    expect_err("groups twice", "exec groups=a groups=b /bin/true\n", "groups= given twice");
}

static void test_run_paths(void)
{
    struct uinit_unit u;

    if (!parse_ok("run relative", "run units/services.uinit\n", &u)) {
        CHECK(u.stmts[0].op == UINIT_OP_RUN, "run: wrong op");
        CHECK(!strcmp(u.stmts[0].u.run_path, "/urados/etc/urados/init/hw/units/services.uinit"),
              "run relative: got '%s'", u.stmts[0].u.run_path);
        uinit_unit_free(&u);
    }
    if (!parse_ok("run absolute", "run /urados/etc/x.uinit\n", &u)) {
        CHECK(!strcmp(u.stmts[0].u.run_path, "/urados/etc/x.uinit"), "run absolute: got '%s'",
              u.stmts[0].u.run_path);
        uinit_unit_free(&u);
    }
    expect_err("run dotdot", "run ../x.uinit\n", "invalid path");
    expect_err("run no path", "run\n", "exactly one path");
    expect_err("run two paths", "run a b\n", "exactly one path");
}

static void test_import(void)
{
    struct uinit_unit u;

    if (!parse_ok("import one", "import units/services.uinit\n", &u)) {
        CHECK(u.nstmts == 1 && u.stmts[0].op == UINIT_OP_RUN, "import one: op");
        CHECK(!strcmp(u.stmts[0].u.run_path, "/urados/etc/urados/init/hw/units/services.uinit"),
              "import one: got '%s'", u.stmts[0].u.run_path);
        uinit_unit_free(&u);
    }
    if (!parse_ok("import many", "import /urados/a.uinit b.uinit \"c d.uinit\"\n", &u)) {
        CHECK(u.nstmts == 3, "import many: want 3 statements, got %zu", u.nstmts);
        CHECK(!strcmp(u.stmts[0].u.run_path, "/urados/a.uinit"), "import many: first '%s'",
              u.stmts[0].u.run_path);
        CHECK(!strcmp(u.stmts[1].u.run_path, "/urados/etc/urados/init/hw/b.uinit"),
              "import many: second '%s'", u.stmts[1].u.run_path);
        CHECK(!strcmp(u.stmts[2].u.run_path, "/urados/etc/urados/init/hw/c d.uinit"),
              "import many: third '%s'", u.stmts[2].u.run_path);
        uinit_unit_free(&u);
    }
    if (!parse_ok("optional import", "optional import x.uinit\n", &u)) {
        CHECK(u.stmts[0].optional && u.stmts[0].op == UINIT_OP_RUN, "optional import: flag");
        uinit_unit_free(&u);
    }
    expect_err("import no path", "import\n", "import needs at least one path");
    expect_err("import dotdot", "import a.uinit ../b.uinit\n", "invalid path '../b.uinit'");
    expect_err("run still takes one", "run a b\n", "run takes exactly one path");
}

static void test_chmod_chown(void)
{
    struct uinit_unit u;

    if (!parse_ok("chmod", "chmod 0755 /data/bin\nchmod -R 750 /data\nchmod 4750 /x\nchmod +X /opt\n", &u)) {
        CHECK(u.nstmts == 4, "chmod: want 4 statements, got %zu", u.nstmts);
        CHECK(u.stmts[0].op == UINIT_OP_CHMOD, "chmod: op");
        CHECK(u.stmts[0].u.attr.mode == 0755 && !u.stmts[0].u.attr.recursive, "chmod: 0755");
        CHECK(!strcmp(u.stmts[0].u.attr.path, "/data/bin"), "chmod: path '%s'",
              u.stmts[0].u.attr.path);
        CHECK(u.stmts[1].u.attr.mode == 0750 && u.stmts[1].u.attr.recursive, "chmod -R: mode/recursive");
        CHECK(u.stmts[2].u.attr.mode == 04750, "chmod: setuid bit %o", u.stmts[2].u.attr.mode);
        CHECK(u.stmts[3].u.attr.conditional_exec && u.stmts[3].u.attr.mode == 0,
              "chmod: +X conditional execute mode");
        uinit_unit_free(&u);
    }
    if (!parse_ok("chmod root", "chmod 0700 /\n", &u)) {
        CHECK(!strcmp(u.stmts[0].u.attr.path, "/"), "chmod root: path");
        uinit_unit_free(&u);
    }
    if (!parse_ok("chown owner", "chown alice /data\n", &u)) {
        const struct uinit_attr *a = &u.stmts[0].u.attr;

        CHECK(u.stmts[0].op == UINIT_OP_CHOWN, "chown: op");
        CHECK(!strcmp(a->owner, "alice") && !a->group && !a->login_group, "chown owner only");
        uinit_unit_free(&u);
    }
    if (!parse_ok("chown owner:group", "chown -R 1000:100 /data\n", &u)) {
        const struct uinit_attr *a = &u.stmts[0].u.attr;

        CHECK(a->recursive && !strcmp(a->owner, "1000") && !strcmp(a->group, "100"),
              "chown owner:group");
        uinit_unit_free(&u);
    }
    if (!parse_ok("chown owner:", "chown alice: /data\n", &u)) {
        const struct uinit_attr *a = &u.stmts[0].u.attr;

        CHECK(!strcmp(a->owner, "alice") && !a->group && a->login_group, "chown owner:");
        uinit_unit_free(&u);
    }
    if (!parse_ok("chown :group", "chown :staff /data\n", &u)) {
        const struct uinit_attr *a = &u.stmts[0].u.attr;

        CHECK(!a->owner && !strcmp(a->group, "staff") && !a->login_group, "chown :group");
        uinit_unit_free(&u);
    }
    if (!parse_ok("optional chmod", "optional chmod 0644 /x\n", &u)) {
        CHECK(u.stmts[0].optional, "optional chmod: flag");
        uinit_unit_free(&u);
    }
    expect_err("chmod bad digit", "chmod 0758 /x\n", "must be 1 to 4 octal digits");
    expect_err("chmod too long", "chmod 00755 /x\n", "must be 1 to 4 octal digits");
    expect_err("chmod symbolic", "chmod u+x /x\n", "must be 1 to 4 octal digits, e.g. 0755, or +X");
    expect_err("chmod relative", "chmod 0755 x\n", "absolute path");
    expect_err("chmod dotdot", "chmod 0755 /a/../b\n", "absolute path");
    expect_err("chmod missing path", "chmod 0755\n", "chmod takes");
    expect_err("chown no owner", "chown : /x\n", "needs an owner or a group");
    expect_err("chown two colons", "chown a:b:c /x\n", "at most one ':'");
    expect_err("chown relative", "chown alice x\n", "absolute path");
    expect_err("chown missing path", "chown alice\n", "chown takes");
}

static void test_mount_opt_table(void)
{
    unsigned long f = 0;

    CHECK(uinit_mount_opt("ro", &f) && f == MS_RDONLY, "opt ro");
    CHECK(uinit_mount_opt("rw", &f) && !(f & MS_RDONLY), "opt rw clears ro");
    CHECK(uinit_mount_opt("noatime", &f) && (f & MS_NOATIME), "opt noatime");
    CHECK(!uinit_mount_opt("errors=remount-ro", &f), "non-flag option reported as flag");
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");

    if (!f) {
        failures++;
        fprintf(stderr, "FAIL cannot write %s (run from init/ with build/ present)\n", path);
        return;
    }
    fputs(text, f);
    fclose(f);
}

static void test_ident(void)
{
    const char *p = "build/test-id";
    struct uinit_ident id;
    char err[UINIT_ERRLEN];

    write_file(p, "# comment\nNAME=\"Urados OS\"\nVERSION='1.2'\n  CHANNEL = beta  \nEXTRA=ignored\n");
    CHECK(uinit_load_ident(p, &id, err, sizeof err) == 0, "ident ok: %s", err);
    CHECK(!strcmp(id.name, "Urados OS"), "ident name '%s'", id.name);
    CHECK(!strcmp(id.version, "1.2"), "ident version '%s'", id.version);
    CHECK(!strcmp(id.channel, "beta"), "ident channel '%s'", id.channel);

    write_file(p, "NAME=Urados\nVERSION=1\n");
    CHECK(uinit_load_ident(p, &id, err, sizeof err) < 0 && strstr(err, "CHANNEL is missing"),
          "ident missing channel: '%s'", err);

    write_file(p, "NAME=Urados\nVERSION=\nCHANNEL=x\n");
    CHECK(uinit_load_ident(p, &id, err, sizeof err) < 0 && strstr(err, "VERSION is empty"),
          "ident empty version: '%s'", err);

    write_file(p, "NAME Urados\n");
    CHECK(uinit_load_ident(p, &id, err, sizeof err) < 0 && strstr(err, "expected KEY=VALUE"),
          "ident no '=': '%s'", err);

    {
        char big[400];
        size_t n = 0;

        n += (size_t)snprintf(big + n, sizeof big - n, "NAME=");
        while (n < 300)
            big[n++] = 'a';
        big[n++] = '\n';
        big[n] = '\0';
        write_file(p, big);
        CHECK(uinit_load_ident(p, &id, err, sizeof err) < 0 && strstr(err, "longer than"),
              "ident long name: '%s'", err);
    }

    CHECK(uinit_load_ident("build/no-such-id", &id, err, sizeof err) < 0,
          "ident missing file should fail");
    remove(p);
}

int main(void)
{
    setup_ctx();
    test_log_and_expand();
    test_quoting_and_comments();
    test_syntax_errors();
    test_mount_sources();
    test_mount_errors();
    test_exec();
    test_run_paths();
    test_import();
    test_chmod_chown();
    test_mount_opt_table();
    test_ident();

    printf("test_parse: %d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
