/*
 * manifest.c - parse manifest.xml with libxml2.
 *
 * Schema (root element <package>, child elements only):
 *
 *   <package>
 *     <name>notes</name>                         required, pkg_name_valid
 *     <version>1.2.0</version>                   required, pkg_version_valid
 *     <entry>system_cache/app/bin/notes</entry>  required, under system_cache/app/
 *     <label>Notes</label>                       optional
 *     <description>...</description>             optional
 *     <author>...</author>                       optional
 *   </package>
 *
 * Each child may appear at most once. Unknown elements, attributes, DOCTYPE
 * declarations and external entities are rejected. The parser does no
 * network access and loads no external entities.
 */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "urados_pkg.h"

enum field {
    F_NAME, F_VERSION, F_ENTRY, F_LABEL, F_DESCRIPTION, F_AUTHOR, F_COUNT
};

static const char *const field_names[F_COUNT] = {
    "name", "version", "entry", "label", "description", "author"
};

static void trim(char *s)
{
    size_t n = strlen(s), a = 0;

    while (a < n && isspace((unsigned char)s[a]))
        a++;
    while (n > a && isspace((unsigned char)s[n - 1]))
        n--;
    memmove(s, s + a, n - a);
    s[n - a] = '\0';
}

/* Copies src into dst (capacity cap), failing if it does not fit. */
static int store(char *dst, size_t cap, const char *src, const char *field,
                 char *err, size_t errlen)
{
    size_t n = strlen(src);

    if (n >= cap) {
        pkg_seterr(err, errlen, "<%s> is longer than %zu characters", field, cap - 1);
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

static int store_field(pkg_manifest *m, int idx, const char *value, const char *fname,
                       char *err, size_t errlen)
{
    char zipname[PKG_PATH_MAX];

    switch (idx) {
    case F_NAME:
        if (!pkg_name_valid(value)) {
            pkg_seterr(err, errlen, "invalid package name '%s'", value);
            return -1;
        }
        return store(m->name, sizeof(m->name), value, fname, err, errlen);
    case F_VERSION:
        if (!pkg_version_valid(value)) {
            pkg_seterr(err, errlen, "invalid version '%s'", value);
            return -1;
        }
        return store(m->version, sizeof(m->version), value, fname, err, errlen);
    case F_ENTRY:
        if (pkg_entry_zipname(value, zipname, sizeof(zipname)) != 0) {
            pkg_seterr(err, errlen, "entry '%s' must be a safe path under %s",
                       value, PKG_ENTRY_PREFIX);
            return -1;
        }
        return store(m->entry, sizeof(m->entry), value, fname, err, errlen);
    case F_LABEL:
        return store(m->label, sizeof(m->label), value, fname, err, errlen);
    case F_DESCRIPTION:
        return store(m->description, sizeof(m->description), value, fname, err, errlen);
    case F_AUTHOR:
        return store(m->author, sizeof(m->author), value, fname, err, errlen);
    }
    return -1;
}

int pkg_manifest_parse(const unsigned char *buf, size_t len, pkg_manifest *m,
                       char *err, size_t errlen)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root, node;
    int seen[F_COUNT] = {0};
    int rc = -1;

    memset(m, 0, sizeof(*m));
    if (!buf || len == 0 || len > PKG_META_MAX) {
        pkg_seterr(err, errlen, "manifest is empty or too large");
        return -1;
    }

    doc = xmlReadMemory((const char *)buf, (int)len, PKG_MANIFEST_FILE, NULL,
                        XML_PARSE_NONET | XML_PARSE_NOBLANKS);
    if (!doc) {
        pkg_seterr(err, errlen, "manifest is not well-formed XML");
        return -1;
    }
    if (doc->intSubset || doc->extSubset) {
        pkg_seterr(err, errlen, "manifest must not contain a DOCTYPE");
        goto out;
    }
    root = xmlDocGetRootElement(doc);
    if (!root || xmlStrcmp(root->name, (const xmlChar *)"package") != 0) {
        pkg_seterr(err, errlen, "root element must be <package>");
        goto out;
    }
    if (root->properties) {
        pkg_seterr(err, errlen, "<package> takes no attributes");
        goto out;
    }

    for (node = root->children; node; node = node->next) {
        const char *fname = NULL;
        xmlChar *text;
        char *value;
        int i, found = 0;

        if (node->type == XML_COMMENT_NODE || node->type == XML_TEXT_NODE)
            continue;
        if (node->type != XML_ELEMENT_NODE) {
            pkg_seterr(err, errlen, "unexpected node in <package>");
            goto out;
        }
        for (i = 0; i < F_COUNT; i++) {
            if (xmlStrcmp(node->name, (const xmlChar *)field_names[i]) == 0) {
                fname = field_names[i];
                found = 1;
                break;
            }
        }
        if (!found) {
            pkg_seterr(err, errlen, "unknown element <%s>", (const char *)node->name);
            goto out;
        }
        if (node->properties) {
            pkg_seterr(err, errlen, "<%s> takes no attributes", fname);
            goto out;
        }
        if (seen[i]) {
            pkg_seterr(err, errlen, "duplicate <%s>", fname);
            goto out;
        }
        seen[i] = 1;

        text = xmlNodeGetContent(node);
        if (!text) {
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
        value = strdup((const char *)text);
        xmlFree(text);
        if (!value) {
            pkg_seterr(err, errlen, "out of memory");
            goto out;
        }
        trim(value);
        if (store_field(m, i, value, fname, err, errlen) != 0) {
            free(value);
            goto out;
        }
        free(value);
    }

    if (!seen[F_NAME] || !seen[F_VERSION] || !seen[F_ENTRY]) {
        pkg_seterr(err, errlen, "manifest needs <name>, <version> and <entry>");
        goto out;
    }
    rc = 0;
out:
    xmlFreeDoc(doc);
    return rc;
}
