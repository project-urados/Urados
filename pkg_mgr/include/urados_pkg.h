/*
 * urados_pkg.h - shared definitions for the Urados package tools.
 *
 *   urpkg  - package manager: install / start / verify. Runs as root.
 *   urdev  - developer tool: init / check / keygen / pack.
 *
 * Package format: a zip archive containing
 *   manifest.xml   XML manifest (schema in src/manifest.c)
 *   SIGNATURE      signature over the digest text
 *   SIGNER_CERTS   required PEM leaf/intermediate X.509 chain
 *   app/<rel>      payload files, installed as system_cache/app/<rel>
 *
 * Digest text: one line per archive file except SIGNATURE (manifest.xml is
 * included), sorted by name with strcmp:
 *   "<sha256 hex>  <name>\n"
 * The signature covers exactly these bytes, so no file can be added, removed
 * or swapped without invalidating the package.
 *
 * Installed layout (every device path is prefixed by --root when one is given):
 *   /data/app_progs/                        root:root 0700   root only
 *   /data/app_progs/.locks/                 root:root 0700   install/start serialization
 *   /data/app_progs/.staging/               root:root 0700   install staging
 *   /data/app_progs/<name>.zip              root:root 0600   trusted package
 *   /data/app/                              root:root 0711   traverse only
 *   /data/app/<name>/                       root:users 0710, parent protected
 *   /data/app/<name>/data/                  root:users 0770 + per-UID ACL, non-executable data
 *   /data/app/<name>/system_cache/          root:users 2730 + per-UID ACL, app WX
 *   /data/app/<name>/system_cache/app/      root:users 2770 + per-UID ACL
 *   /data/app/<name>/system_cache/user/     root:users 2770 + per-UID ACL
 *
 * Every app user has the single shared primary group 'users'. POSIX ACLs grant
 * access to each app's data home and cache only to its UID; shared group entries
 * have no permissions. Root owns the data-home directory so an app cannot
 * chmod it to expose files to other members of 'users'.
 */
#ifndef URADOS_PKG_H
#define URADOS_PKG_H

#include <openssl/evp.h>
#include <stddef.h>
#include <sys/types.h>

#define PKG_NAME_MAX    32    /* Linux user name limit */
#define PKG_VERSION_MAX 63
#define PKG_LABEL_MAX   127
#define PKG_DESC_MAX    511
#define PKG_AUTHOR_MAX  127
#define PKG_ENTRY_MAX   255
#define PKG_PATH_MAX    1024
#define PKG_META_MAX    (1024u * 1024u)        /* manifest, signature, signer chain */
#define PKG_FILE_MAX    (256u * 1024u * 1024u) /* any single payload file */
#define PKG_ARCHIVE_MAX (1024u * 1024u * 1024u)
#ifndef PKG_UNPACKED_MAX
#define PKG_UNPACKED_MAX (1024ull * 1024ull * 1024ull)
#endif
#define PKG_FILES_MAX   4096
#define PKG_GROUPS_MAX  64
#define PKG_ARGS_MAX    64

#define PKG_MANIFEST_FILE  "manifest.xml"
#define PKG_SIGNATURE_FILE "SIGNATURE"
#define PKG_SIGNER_CERTS_FILE "SIGNER_CERTS.pem"
#define PKG_ARCHIVE_SUFFIX ".zip"             /* trusted archive: <app-name>.zip */
#define PKG_KEYS_SUBDIR    "/etc/urados/keys" /* administrator-installed X.509 CA roots */
#define PKG_DATA_DIR       "/data"
#define PKG_PROGS_DIR      "/data/app_progs"
#define PKG_STAGING_DIR    ".staging"
#define PKG_APPDATA_DIR    "/data/app"
#define PKG_APP_DATA_SUBDIR "data"
#define PKG_APP_GROUP      "users"            /* primary group of app users */
#define PKG_CACHE_DIR      "system_cache"
#define PKG_CACHE_USER_DIR "user"
#define PKG_RUNNER_PATH    "/urados/bin/urapp-runner"
#define PKG_USER_UTILS     "/urados/bin/user"
#define PKG_ZIP_APP_PREFIX "app/"             /* payload prefix inside the zip */
#define PKG_ENTRY_PREFIX   "system_cache/app/"/* manifest <entry> prefix */

/* SELinux: each app account <name> gets SELinux user "<name>_u", and the Linux
 * login <name> is mapped to it. */
#define PKG_SEL_SUFFIX   "_u"
#define PKG_SEL_USER_MAX (PKG_NAME_MAX + 3)   /* "<name>_u" plus NUL */
#define PKG_SEL_PREFIX   "user"
#define PKG_SEL_ROLE     "urados_app_r"
#define PKG_SEL_RANGE    "s0"

typedef struct {
    char name[PKG_NAME_MAX + 1];
    char version[PKG_VERSION_MAX + 1];
    char label[PKG_LABEL_MAX + 1];
    char description[PKG_DESC_MAX + 1];
    char author[PKG_AUTHOR_MAX + 1];
    char entry[PKG_ENTRY_MAX + 1];   /* e.g. system_cache/app/bin/notes */
} pkg_manifest;

typedef struct {
    const char *country;
    const char *state;
    const char *locality;
    const char *organization;
    const char *organizational_unit;
    const char *common_name;
    const char *email;
} pkg_cert_subject;

typedef struct {
    char *name;          /* zip entry name, owned by pkg_verified */
    char hex[65];        /* sha256 of the file contents */
} pkg_digest;

/* Result of a successful verification. Release with pkg_verified_free(). */
typedef struct {
    pkg_manifest manifest;
    pkg_digest *digests; /* sorted; includes manifest/signer chain, excludes SIGNATURE */
    size_t ndigests;
} pkg_verified;

/* Options shared by the urpkg commands. */
typedef struct {
    const char *root;      /* "" for the device, or an absolute staging prefix */
    const char *keys_dir;  /* PEM-encoded trusted X.509 CA certificates */
} pkg_opts;

/* Current SELinux state of an app (pkg_sel_query). */
typedef struct {
    int  user_exists;                    /* "<name>_u" is defined in the policy */
    int  login_exists;                   /* a login mapping for <name> is defined */
    char login_sename[PKG_SEL_USER_MAX]; /* the SELinux user the mapping points at */
} pkg_sel_status;

/* What pkg_sel_register added, so that pkg_sel_unregister can undo it. */
typedef struct {
    int user_added;
    int login_added;
} pkg_sel_state;

/* common.c */
void pkg_seterr(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
int  pkg_name_valid(const char *name);
int  pkg_version_valid(const char *v);
int  pkg_path_safe(const char *p);
int  pkg_entry_zipname(const char *entry, char *out, size_t outlen);
int  pkg_digest_cmp(const void *a, const void *b);
int  pkg_digest_text(const pkg_digest *d, size_t n, unsigned char **out, size_t *outlen);
void pkg_hex_encode(const unsigned char *md, size_t len, char hex[65]);
void pkg_sha256(const void *data, size_t len, char hex[65]);
int  pkg_read_file(const char *path, size_t max, unsigned char **out, size_t *outlen);
int  pkg_write_all(int fd, const void *buf, size_t len);
char *pkg_join(const char *root, const char *path);

/* crypto.c */
int  pkg_check_signature(EVP_PKEY **keys, size_t n, const unsigned char *data,
                         size_t dlen, const unsigned char *sig, size_t slen);
int  pkg_sign_data(EVP_PKEY *key, const unsigned char *data, size_t dlen,
                   unsigned char **sig, size_t *slen);
int  pkg_load_private_key(const char *path, EVP_PKEY **key, char *err, size_t errlen);
int  pkg_generate_key(const char *priv_path, const char *pub_path, int encrypt,
                      char *err, size_t errlen);
int  pkg_validate_signer_certificate(const unsigned char *chain, size_t chainlen,
                                     EVP_PKEY *key, char *err, size_t errlen);
int  pkg_verify_certificate_signature(const unsigned char *chain, size_t chainlen,
                                      const char *roots_dir,
                                      const unsigned char *data, size_t datalen,
                                      const unsigned char *sig, size_t siglen,
                                      char *err, size_t errlen);
int  pkg_create_csr(const char *keypath, const char *csrpath,
                    const pkg_cert_subject *subject, char *err, size_t errlen);

/* archive.c */
int  pkg_verify(const char *zip_path, const char *keys_dir, pkg_verified *v,
                char *err, size_t errlen);
int  pkg_extract(const char *zip_path, int appfd, gid_t gid, const pkg_verified *v,
                 char *err, size_t errlen);
void pkg_verified_free(pkg_verified *v);

/* manifest.c */
int  pkg_manifest_parse(const unsigned char *buf, size_t len, pkg_manifest *m,
                        char *err, size_t errlen);

/* sys.c */
int  pkg_run(char *const argv[]);
int  pkg_rm_entry_at(int dirfd, const char *name, int depth);
int  pkg_open_subdir(int dirfd, const char *name, mode_t mode, uid_t uid, gid_t gid);
int  pkg_lookup_passwd(const char *root, const char *name, uid_t *uid, gid_t *gid);
int  pkg_lookup_group(const char *root, const char *name, gid_t *gid);
int  pkg_set_app_uid_acl(int fd, uid_t app_uid, int app_read);

/* selinux.c (libsemanage: SELinux user and login mapping for each app) */
int  pkg_sel_policy(const char *root, char *out, size_t outlen);
int  pkg_sel_name(const char *app, char *out, size_t outlen);
int  pkg_sel_query(const pkg_opts *o, const char *app, pkg_sel_status *st,
                   char *err, size_t errlen);
int  pkg_sel_register(const pkg_opts *o, const char *app, pkg_sel_state *st,
                      char *err, size_t errlen);
int  pkg_sel_unregister(const pkg_opts *o, const char *app, const pkg_sel_state *st,
                        char *err, size_t errlen);

/* fetch.c */
int  pkg_fetch(const char *src, int fd, size_t max, char *err, size_t errlen);

/* pack.c (urdev) */
int  pkg_init_project(const char *dir, const char *name, const char *version,
                      char *err, size_t errlen);
int  pkg_check_project(const char *dir, pkg_manifest *m, char *err, size_t errlen);
int  pkg_pack(const char *dir, const char *out_zip, EVP_PKEY *key,
              const char *cert_chain_path,
              char *err, size_t errlen);

/* install.c (urpkg) */
int  pkg_cmd_install(const char *source, const pkg_opts *o);
int  pkg_cmd_start(const char *name, int argc, char **argv, const pkg_opts *o);
int  pkg_cmd_verify(const char *zip, const pkg_opts *o);

#endif
