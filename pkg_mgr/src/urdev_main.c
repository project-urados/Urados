/*
 * urdev_main.c - developer tool: create, check, sign and pack apps.
 *
 *   urdev init   <dir> <name> [version]          create a project skeleton
 *   urdev check  <dir>                           validate manifest and entry
 *   urdev keygen <private.pem> <public.pem> [--no-passphrase]
 *                                                create an Ed25519 signing key
 *   urdev csr    <private.pem> <request.csr> <CN> create a certificate request
 *   urdev pack   <dir> <out.zip> [--key FILE] [--cert CHAIN.pem]
 *
 * pack asks for the signing key path when --key is not given. OpenSSL asks for
 * the key's passphrase on the terminal when the key is encrypted.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "urados_pkg.h"

static void usage(FILE *f)
{
    fputs("usage:\n"
          "  urdev init   <dir> <name> [version]\n"
          "  urdev check  <dir>\n"
          "  urdev keygen <private.pem> <public.pem> [--no-passphrase]\n"
          "  urdev csr    <private.pem> <request.csr> <common-name>\n"
          "  urdev pack   <dir> <out.zip> [--key FILE] [--cert CHAIN.pem]\n",
          f);
}

static void fail(const char *msg)
{
    fprintf(stderr, "urdev: error: %s\n", msg);
}

/* Asks for the signing key path on the terminal. */
static int prompt_key(char *buf, size_t len)
{
    size_t n;

    if (!isatty(STDIN_FILENO))
        return -1;
    fputs("Signing key (private PEM) path: ", stderr);
    if (!fgets(buf, (int)len, stdin))
        return -1;
    n = strcspn(buf, "\r\n");
    buf[n] = '\0';
    return n > 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    char err[512] = "";
    char keypath[PKG_PATH_MAX];
    pkg_manifest m;
    EVP_PKEY *key = NULL;
    const char *cmd;
    int rc = 1;

    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    cmd = argv[1];

    if (strcmp(cmd, "init") == 0) {
        if (argc < 4 || argc > 5) {
            usage(stderr);
            return 2;
        }
        if (pkg_init_project(argv[2], argv[3], argc == 5 ? argv[4] : "0.1.0", err, sizeof(err)) != 0) {
            fail(err);
            return 1;
        }
        printf("created %s: edit manifest.xml and replace app/%s with your program\n",
               argv[2], argv[3]);
        return 0;
    }

    if (strcmp(cmd, "check") == 0) {
        if (argc != 3) {
            usage(stderr);
            return 2;
        }
        if (pkg_check_project(argv[2], &m, err, sizeof(err)) != 0) {
            fail(err);
            return 1;
        }
        printf("OK %s %s, entry %s\n", m.name, m.version, m.entry);
        return 0;
    }

    if (strcmp(cmd, "keygen") == 0) {
        int encrypt = 1;

        if (argc < 4 || argc > 5) {
            usage(stderr);
            return 2;
        }
        if (argc == 5) {
            if (strcmp(argv[4], "--no-passphrase") != 0) {
                usage(stderr);
                return 2;
            }
            encrypt = 0;
        }
        if (pkg_generate_key(argv[2], argv[3], encrypt, err, sizeof(err)) != 0) {
            fail(err);
            return 1;
        }
        printf("wrote private key %s (keep it secret) and public key %s\n", argv[2], argv[3]);
        printf("for certificate signing, create a CSR with: urdev csr %s request.csr <common-name>\n", argv[2]);
        return 0;
    }

    if (strcmp(cmd, "csr") == 0) {
        if (argc != 5) {
            usage(stderr);
            return 2;
        }
        if (pkg_create_csr(argv[2], argv[3], argv[4], err, sizeof(err)) != 0) {
            fail(err);
            return 1;
        }
        printf("created CSR %s; send only the CSR to your certificate authority\n", argv[3]);
        return 0;
    }

    if (strcmp(cmd, "pack") == 0) {
        const char *keyarg = NULL;
        const char *certarg = NULL;
        int i;

        if (argc < 4) {
            usage(stderr);
            return 2;
        }
        for (i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
                keyarg = argv[++i];
            else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
                certarg = argv[++i];
            else {
                usage(stderr);
                return 2;
            }
        }
        if (!keyarg) {
            if (prompt_key(keypath, sizeof(keypath)) != 0) {
                fail("no signing key given (use --key FILE)");
                return 1;
            }
            keyarg = keypath;
        }
        if (pkg_load_private_key(keyarg, &key, err, sizeof(err)) != 0) {
            fail(err);
            goto done;
        }
        if (pkg_pack(argv[2], argv[3], key, certarg, err, sizeof(err)) != 0) {
            fail(err);
            goto done;
        }
        printf("packed %s%s\n", argv[3], certarg ? " with certificate chain" : "");
        rc = 0;
        goto done;
    }

    usage(stderr);
    return 2;

done:
    EVP_PKEY_free(key);
    return rc;
}
