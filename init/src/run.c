/*
 * run.c - executes a parsed unit, statement by statement.
 *
 * A unit is parsed in full before any of its statements run, so a syntax error
 * stops the unit before anything has happened. A failed statement stops the
 * unit unless the statement is marked optional, in which case the failure is
 * logged and the unit continues. In --check mode, nothing is mounted or run,
 * but run and log are still followed so the whole tree is validated.
 */
#include <stdio.h>
#include <string.h>

#include "uinit.h"

/* Runs one statement. On failure, err describes what went wrong. */
static int run_stmt(struct uinit_ctx *ctx, const struct uinit_stmt *st,
                    char *err, size_t errlen)
{
    switch (st->op) {
    case UINIT_OP_RUN:
        if (uinit_run_unit(ctx, st->u.run_path) < 0) {
            uinit_seterr(err, errlen, "unit %s failed", st->u.run_path);
            return -1;
        }
        return 0;
    case UINIT_OP_LOG:
        uinit_log("%s", st->u.log_text);
        return 0;
    case UINIT_OP_MOUNT:
        if (ctx->check_only)
            return 0;
        return uinit_do_mount(ctx, &st->u.mount, err, errlen);
    case UINIT_OP_EXEC:
        if (ctx->check_only)
            return 0;
        return uinit_exec_run(&st->u.exec, 1, err, errlen);
    case UINIT_OP_SPAWN:
        if (ctx->check_only)
            return 0;
        return uinit_exec_run(&st->u.exec, 0, err, errlen);
    }
    uinit_seterr(err, errlen, "internal error: unknown statement");
    return -1;
}

int uinit_run_unit(struct uinit_ctx *ctx, const char *path)
{
    struct uinit_unit unit;
    char err[UINIT_ERRLEN];
    size_t i;
    int rc = 0;

    if (ctx->depth >= UINIT_MAX_DEPTH) {
        uinit_log("%s: run nesting too deep (limit %d), is a unit running itself?",
                  path, UINIT_MAX_DEPTH);
        return -1;
    }
    if (uinit_parse_file(ctx, path, &unit, err, sizeof err) < 0) {
        uinit_log("%s", err);
        return -1;
    }

    uinit_debug("unit %s (%zu statements)", path, unit.nstmts);
    ctx->depth++;
    for (i = 0; i < unit.nstmts; i++) {
        const struct uinit_stmt *st = &unit.stmts[i];

        if (run_stmt(ctx, st, err, sizeof err) == 0)
            continue;
        if (st->optional) {
            uinit_log("%s:%d: optional statement failed: %s", path, st->line, err);
            continue;
        }
        uinit_log("%s:%d: %s", path, st->line, err);
        rc = -1;
        break;
    }
    ctx->depth--;
    uinit_unit_free(&unit);
    return rc;
}
