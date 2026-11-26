/*
 * run.c - executes a parsed unit, statement by statement.
 *
 * A unit is parsed in full before any of its statements run, so a syntax error
 * stops the unit before anything has happened. A failed statement stops the
 * unit unless the statement is marked optional, in which case the failure is
 * logged and the unit continues.
 *
 * Two things stop the whole boot, not just the unit, and optional does not
 * stop them:
 *   - exec mode=exit or mode=exit-nonzero ended with a status to exit with.
 *   - exec mode=replace changed uinit's identity and then could not run the
 *     command. uinit cannot return to root, so it must stop.
 * Both set ctx->exit_requested. Every unit up the import chain then stops, and
 * main() exits with ctx->exit_code (or, as PID 1, reaps forever instead).
 *
 * In --check mode, nothing is mounted, changed or run. Imports, runs, and logs
 * are still followed, and exec statements do not end the boot, so the whole
 * tree is validated.
 */
#include <stdio.h>
#include <string.h>

#include "uinit.h"

/* Runs one exec statement. Sets ctx->exit_requested for the exit modes. */
static int run_exec(struct uinit_ctx *ctx, const char *path, const struct uinit_stmt *st,
                    char *err, size_t errlen)
{
    const struct uinit_exec *e = &st->u.exec;
    struct uinit_status status;
    int rc;

    if (ctx->check_only)
        return 0;

    rc = uinit_exec_run(e, &status, err, errlen);
    if (rc == -2) {
        /* Identity changed and the command never ran. Nothing can continue. */
        ctx->exit_requested = 1;
        ctx->exit_code = 1;
        return -1;
    }
    if (rc < 0)
        return -1;

    /* The command ran and has ended. Decide what that means for the boot. */
    if (e->mode == UINIT_MODE_EXIT_NONZERO || e->mode == UINIT_MODE_EXIT) {
        int code = uinit_status_exit_code(&status);

        if (e->mode == UINIT_MODE_EXIT_NONZERO && code == 0)
            return 0;
        ctx->exit_requested = 1;
        ctx->exit_code = code;
        uinit_log("%s:%d: %s ended with status %d, so uinit exits with it",
                  path, st->line, e->argv[0], code);
        return 0;
    }
    if (e->mode == UINIT_MODE_WAIT) {
        if (status.sig) {
            snprintf(err, errlen, "%s killed by signal %d", e->argv[0], status.sig);
            return -1;
        }
        if (status.code != 0) {
            snprintf(err, errlen, "%s exited with status %d", e->argv[0], status.code);
            return -1;
        }
    }
    return 0;
}

/* Runs one statement. On failure, err describes what went wrong. */
static int run_stmt(struct uinit_ctx *ctx, const char *path, const struct uinit_stmt *st,
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
    case UINIT_OP_CHMOD:
        if (ctx->check_only)
            return 0;
        return uinit_do_chmod(ctx, &st->u.attr, err, errlen);
    case UINIT_OP_CHOWN:
        if (ctx->check_only)
            return 0;
        return uinit_do_chown(ctx, &st->u.attr, err, errlen);
    case UINIT_OP_EXEC:
        return run_exec(ctx, path, st, err, errlen);
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

        if (run_stmt(ctx, path, st, err, sizeof err) == 0) {
            if (ctx->exit_requested)
                break;
            continue;
        }
        if (ctx->exit_requested) {
            /* An import has already logged its own failure. Anything else is logged here. */
            if (st->op != UINIT_OP_RUN)
                uinit_log("%s:%d: %s", path, st->line, err);
            break;
        }
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
