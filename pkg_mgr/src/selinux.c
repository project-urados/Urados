/*
 * selinux.c - SELinux registration for app accounts (libsemanage).
 *
 * Each app <name> gets:
 *   - an SELinux user "<name>_u" (prefix user, role urados_app_r, range s0), and
 *   - a Linux login mapping "<name>" -> "<name>_u".
 *
 * Both are local customisations of the policy store, so they survive policy
 * rebuilds. libsemanage cannot validate a login mapping whose SELinux user is
 * added in the same transaction, so every record gets its own transaction and
 * the SELinux user is committed first.
 *
 * With a root prefix the store is the one under that root (semanage_set_root)
 * and nothing is loaded into the kernel. On the device the policy is reloaded
 * after each commit, so the mapping takes effect at once.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <semanage/handle.h>
#include <semanage/seuser_record.h>
#include <semanage/seusers_local.h>
#include <semanage/user_record.h>
#include <semanage/users_local.h>

#include "urados_pkg.h"

#define SEL_CONFIG         "/etc/selinux/config"
#define SEL_DEFAULT_POLICY "default"
#define SEL_POLICY_MAX     64

/* Reads SELINUXTYPE from <root>/etc/selinux/config into out. */
int pkg_sel_policy(const char *root, char *out, size_t outlen)
{
    char *path = pkg_join(root, SEL_CONFIG);
    FILE *fp;
    char line[256];
    int found = 0;

    if (!path)
        return -1;
    fp = fopen(path, "r");
    free(path);
    if (!fp)
        return -1;
    snprintf(out, outlen, "%s", SEL_DEFAULT_POLICY);
    while (!found && fgets(line, sizeof(line), fp)) {
        char *v;
        size_t i, n;

        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "SELINUXTYPE=", 12) != 0)
            continue;
        v = line + 12;
        n = strlen(v);
        if (n == 0 || n >= outlen) {
            fclose(fp);
            return -1;
        }
        for (i = 0; i < n; i++) {
            char c = v[i];

            if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.')) {
                fclose(fp);
                return -1;
            }
        }
        memcpy(out, v, n + 1);
        found = 1;
    }
    fclose(fp);
    return 0;
}

int pkg_sel_name(const char *app, char *out, size_t outlen)
{
    static const char *const reserved[] = PKG_SEL_RESERVED_USERS;
    size_t i;

    if (!pkg_name_valid(app))
        return -1;
    if (snprintf(out, outlen, "%s%s", app, PKG_SEL_SUFFIX) >= (int)outlen)
        return -1;
    /* Refuse names that would reuse a policy-defined Urados user. */
    for (i = 0; i < PKG_SEL_RESERVED_COUNT; i++) {
        if (strcmp(out, reserved[i]) == 0)
            return -1;
    }
    return 0;
}

/* Opens a handle on the policy store (under o->root when it is set). */
static int sel_open(const pkg_opts *o, semanage_handle_t **out, char *err, size_t errlen)
{
    char policy[SEL_POLICY_MAX];
    semanage_handle_t *sh;

    if (pkg_sel_policy(o->root, policy, sizeof(policy)) != 0) {
        pkg_seterr(err, errlen, "cannot read the SELinux policy type from %s", SEL_CONFIG);
        return -1;
    }
    if (o->root[0] != '\0' && semanage_set_root(o->root) != 0) {
        pkg_seterr(err, errlen, "cannot use '%s' as the SELinux root", o->root);
        return -1;
    }
    sh = semanage_handle_create();
    if (!sh) {
        pkg_seterr(err, errlen, "cannot create a policy store handle");
        return -1;
    }
    semanage_set_reload(sh, o->root[0] == '\0');
    semanage_select_store(sh, policy, SEMANAGE_CON_DIRECT);
    if (semanage_connect(sh) < 0) {
        semanage_handle_destroy(sh);
        pkg_seterr(err, errlen, "cannot connect to the SELinux policy store");
        return -1;
    }
    *out = sh;
    return 0;
}

static void sel_close(semanage_handle_t *sh)
{
    if (!sh)
        return;
    semanage_disconnect(sh);
    semanage_handle_destroy(sh);
}

static int sel_commit(semanage_handle_t *sh, const char *what, char *err, size_t errlen)
{
    if (semanage_commit(sh) < 0) {
        pkg_seterr(err, errlen, "cannot %s: the policy store rejected the change", what);
        return -1;
    }
    return 0;
}

static int sel_add_user(const pkg_opts *o, const char *sename, char *err, size_t errlen)
{
    semanage_handle_t *sh = NULL;
    semanage_user_key_t *k = NULL;
    semanage_user_t *u = NULL;
    int rc = -1;

    if (sel_open(o, &sh, err, errlen) != 0)
        return -1;
    if (semanage_begin_transaction(sh) < 0) {
        pkg_seterr(err, errlen, "cannot start a policy transaction");
        goto out;
    }
    if (semanage_user_key_create(sh, sename, &k) < 0 || semanage_user_create(sh, &u) < 0 ||
        semanage_user_set_name(sh, u, sename) < 0 ||
        semanage_user_set_prefix(sh, u, PKG_SEL_PREFIX) < 0 ||
        semanage_user_set_mlslevel(sh, u, PKG_SEL_RANGE) < 0 ||
        semanage_user_set_mlsrange(sh, u, PKG_SEL_RANGE) < 0 ||
        semanage_user_add_role(sh, u, PKG_SEL_ROLE) < 0) {
        pkg_seterr(err, errlen, "cannot prepare SELinux user '%s'", sename);
        goto out;
    }
    if (semanage_user_modify_local(sh, k, u) < 0) {
        pkg_seterr(err, errlen, "cannot add SELinux user '%s'", sename);
        goto out;
    }
    rc = sel_commit(sh, "add the SELinux user", err, errlen);
out:
    if (u)
        semanage_user_free(u);
    if (k)
        semanage_user_key_free(k);
    sel_close(sh);
    return rc;
}

static int sel_del_user(const pkg_opts *o, const char *sename, char *err, size_t errlen)
{
    semanage_handle_t *sh = NULL;
    semanage_user_key_t *k = NULL;
    int rc = -1;

    if (sel_open(o, &sh, err, errlen) != 0)
        return -1;
    if (semanage_begin_transaction(sh) < 0 || semanage_user_key_create(sh, sename, &k) < 0) {
        pkg_seterr(err, errlen, "cannot remove SELinux user '%s'", sename);
        goto out;
    }
    if (semanage_user_del_local(sh, k) < 0) {
        pkg_seterr(err, errlen, "cannot remove SELinux user '%s'", sename);
        goto out;
    }
    rc = sel_commit(sh, "remove the SELinux user", err, errlen);
out:
    if (k)
        semanage_user_key_free(k);
    sel_close(sh);
    return rc;
}

static int sel_add_login(const pkg_opts *o, const char *app, const char *sename,
                         char *err, size_t errlen)
{
    semanage_handle_t *sh = NULL;
    semanage_seuser_key_t *k = NULL;
    semanage_seuser_t *s = NULL;
    int rc = -1;

    if (sel_open(o, &sh, err, errlen) != 0)
        return -1;
    if (semanage_begin_transaction(sh) < 0) {
        pkg_seterr(err, errlen, "cannot start a policy transaction");
        goto out;
    }
    if (semanage_seuser_key_create(sh, app, &k) < 0 || semanage_seuser_create(sh, &s) < 0 ||
        semanage_seuser_set_name(sh, s, app) < 0 ||
        semanage_seuser_set_sename(sh, s, sename) < 0 ||
        semanage_seuser_set_mlsrange(sh, s, PKG_SEL_RANGE) < 0) {
        pkg_seterr(err, errlen, "cannot prepare the login mapping for '%s'", app);
        goto out;
    }
    if (semanage_seuser_modify_local(sh, k, s) < 0) {
        pkg_seterr(err, errlen, "cannot map login '%s' to '%s'", app, sename);
        goto out;
    }
    rc = sel_commit(sh, "map the login", err, errlen);
out:
    if (s)
        semanage_seuser_free(s);
    if (k)
        semanage_seuser_key_free(k);
    sel_close(sh);
    return rc;
}

static int sel_del_login(const pkg_opts *o, const char *app, char *err, size_t errlen)
{
    semanage_handle_t *sh = NULL;
    semanage_seuser_key_t *k = NULL;
    int rc = -1;

    if (sel_open(o, &sh, err, errlen) != 0)
        return -1;
    if (semanage_begin_transaction(sh) < 0 || semanage_seuser_key_create(sh, app, &k) < 0) {
        pkg_seterr(err, errlen, "cannot remove the login mapping for '%s'", app);
        goto out;
    }
    if (semanage_seuser_del_local(sh, k) < 0) {
        pkg_seterr(err, errlen, "cannot remove the login mapping for '%s'", app);
        goto out;
    }
    rc = sel_commit(sh, "remove the login mapping", err, errlen);
out:
    if (k)
        semanage_seuser_key_free(k);
    sel_close(sh);
    return rc;
}

/* Reads the local SELinux state of an app. Read-only. */
int pkg_sel_query(const pkg_opts *o, const char *app, pkg_sel_status *st,
                  char *err, size_t errlen)
{
    semanage_handle_t *sh = NULL;
    semanage_user_key_t *uk = NULL;
    semanage_seuser_key_t *sk = NULL;
    semanage_seuser_t *s = NULL;
    char sename[PKG_SEL_USER_MAX];
    const char *cur;
    int exists = 0, rc = -1;

    memset(st, 0, sizeof(*st));
    if (pkg_sel_name(app, sename, sizeof(sename)) != 0) {
        pkg_seterr(err, errlen, "invalid app name '%s'", app);
        return -1;
    }
    if (sel_open(o, &sh, err, errlen) != 0)
        return -1;
    if (semanage_user_key_create(sh, sename, &uk) < 0 ||
        semanage_user_exists_local(sh, uk, &exists) < 0) {
        pkg_seterr(err, errlen, "cannot query SELinux user '%s'", sename);
        goto out;
    }
    st->user_exists = exists != 0;

    if (semanage_seuser_key_create(sh, app, &sk) < 0 ||
        semanage_seuser_exists_local(sh, sk, &exists) < 0) {
        pkg_seterr(err, errlen, "cannot query the login mapping for '%s'", app);
        goto out;
    }
    st->login_exists = exists != 0;
    if (st->login_exists) {
        if (semanage_seuser_query_local(sh, sk, &s) < 0 || !s) {
            pkg_seterr(err, errlen, "cannot read the login mapping for '%s'", app);
            goto out;
        }
        cur = semanage_seuser_get_sename(s);
        snprintf(st->login_sename, sizeof(st->login_sename), "%s", cur ? cur : "");
    }
    rc = 0;
out:
    if (s)
        semanage_seuser_free(s);
    if (sk)
        semanage_seuser_key_free(sk);
    if (uk)
        semanage_user_key_free(uk);
    sel_close(sh);
    return rc;
}

/*
 * Registers the SELinux user and login mapping for an app. Missing records are
 * added and recorded in st, so pkg_sel_unregister removes only what this call
 * added. Records that already exist are kept. A login that maps to a different
 * SELinux user is an error. On failure, everything this call added is removed.
 */
int pkg_sel_register(const pkg_opts *o, const char *app, pkg_sel_state *st,
                     char *err, size_t errlen)
{
    pkg_sel_status cur;
    char sename[PKG_SEL_USER_MAX], undo_err[512] = "";

    memset(st, 0, sizeof(*st));
    if (pkg_sel_name(app, sename, sizeof(sename)) != 0) {
        pkg_seterr(err, errlen, "invalid app name '%s'", app);
        return -1;
    }
    if (pkg_sel_query(o, app, &cur, err, errlen) != 0)
        return -1;
    if (cur.login_exists && strcmp(cur.login_sename, sename) != 0) {
        pkg_seterr(err, errlen, "login '%s' already maps to SELinux user '%s'",
                   app, cur.login_sename);
        return -1;
    }
    if (!cur.user_exists) {
        if (sel_add_user(o, sename, err, errlen) != 0)
            return -1;
        st->user_added = 1;
    }
    if (!cur.login_exists) {
        if (sel_add_login(o, app, sename, err, errlen) != 0) {
            char first[512];

            snprintf(first, sizeof(first), "%s", err);
            if (pkg_sel_unregister(o, app, st, undo_err, sizeof(undo_err)) != 0)
                pkg_seterr(err, errlen, "%s (undo also failed: %s)", first, undo_err);
            memset(st, 0, sizeof(*st));
            return -1;
        }
        st->login_added = 1;
    }
    return 0;
}

/*
 * Removes what pkg_sel_register added: the login mapping first, then the
 * SELinux user, because the mapping refers to the user.
 */
int pkg_sel_unregister(const pkg_opts *o, const char *app, const pkg_sel_state *st,
                       char *err, size_t errlen)
{
    char sename[PKG_SEL_USER_MAX];

    if (pkg_sel_name(app, sename, sizeof(sename)) != 0) {
        pkg_seterr(err, errlen, "invalid app name '%s'", app);
        return -1;
    }
    if (st->login_added && sel_del_login(o, app, err, errlen) != 0)
        return -1;
    if (st->user_added && sel_del_user(o, sename, err, errlen) != 0)
        return -1;
    return 0;
}
