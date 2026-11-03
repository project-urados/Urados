/*
 * fetch.c - copy a package from a local path or an http(s) URL into fd.
 *
 * The size limit is enforced while the data arrives, so an oversized
 * download is aborted instead of filling the staging area.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#include "urados_pkg.h"

struct sink {
    int fd;
    size_t max;
    size_t total;
    int failed;
};

static size_t on_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct sink *s = userdata;
    size_t n = size * nmemb;

    if (s->total + n > s->max) {
        s->failed = 1;
        return 0; /* aborts the transfer */
    }
    if (pkg_write_all(s->fd, ptr, n) != 0) {
        s->failed = 1;
        return 0;
    }
    s->total += n;
    return n;
}

static int fetch_local(const char *path, int fd, size_t max, char *err, size_t errlen)
{
    int in = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    char buf[65536];

    if (in < 0) {
        pkg_seterr(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(in);
        pkg_seterr(err, errlen, "%s is not a regular file", path);
        return -1;
    }
    if ((size_t)st.st_size > max) {
        close(in);
        pkg_seterr(err, errlen, "%s is larger than %zu bytes", path, max);
        return -1;
    }
    for (;;) {
        ssize_t r = read(in, buf, sizeof(buf));
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            pkg_seterr(err, errlen, "read error on %s: %s", path, strerror(errno));
            close(in);
            return -1;
        }
        if (r == 0)
            break;
        if (pkg_write_all(fd, buf, (size_t)r) != 0) {
            pkg_seterr(err, errlen, "write error: %s", strerror(errno));
            close(in);
            return -1;
        }
    }
    close(in);
    return 0;
}

static int fetch_url(const char *url, int fd, size_t max, char *err, size_t errlen)
{
    CURL *c;
    CURLcode rc;
    struct sink s = { fd, max, 0, 0 };
    long code = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    c = curl_easy_init();
    if (!c) {
        pkg_seterr(err, errlen, "cannot initialise libcurl");
        return -1;
    }
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
    /* A signed package cannot be forged by a downgrade, but allowing an
     * HTTPS URL to redirect to HTTP leaks the download and invites tampering
     * or denial of service. Keep redirects on HTTPS. */
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &s);
    rc = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    curl_global_cleanup();

    if (s.failed) {
        pkg_seterr(err, errlen, "download exceeded %zu bytes or could not be stored", max);
        return -1;
    }
    if (rc != CURLE_OK) {
        pkg_seterr(err, errlen, "download failed: %s (HTTP %ld)", curl_easy_strerror(rc), code);
        return -1;
    }
    return 0;
}

int pkg_fetch(const char *src, int fd, size_t max, char *err, size_t errlen)
{
    if (strncmp(src, "https://", 8) == 0 || strncmp(src, "http://", 7) == 0)
        return fetch_url(src, fd, max, err, errlen);
    return fetch_local(src, fd, max, err, errlen);
}
