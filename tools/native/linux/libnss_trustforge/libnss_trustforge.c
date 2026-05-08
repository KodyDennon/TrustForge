/*
 * libnss_trustforge — glibc NSS module that resolves TrustForge actors as
 * POSIX users and groups.
 *
 * Status: Draft (Phase 0). The daemon and decide.sock contract exist as a
 * working reference, but this module remains mock-tested and experimental.
 *
 * Design notes:
 *   - NSS modules are loaded into EVERY process that resolves a username
 *     (sshd, su, login, sudo, ls -l, every glibc getpwnam caller). They must
 *     therefore be tiny, allocation-disciplined, and fail closed-but-quiet:
 *     return NSS_STATUS_NOTFOUND on miss so other modules in the chain can
 *     answer.
 *   - We talk to the system local daemon at /run/trustforge/decide.sock
 *     using a hand-rolled minimal HTTP/1.0 request — pulling in libcurl from
 *     an NSS module would be a footgun.
 *   - All output strings (pw_name, pw_dir, etc.) MUST live inside the
 *     caller-provided `buffer`; we never hand back pointers to static or
 *     heap memory. If buffer is too small return NSS_STATUS_TRYAGAIN with
 *     errno=ERANGE, per the NSS contract.
 *   - UID/GID mapping: we hash the actor_id (FNV-1a 64) and fold into the
 *     range [TF_UID_MIN, TF_UID_MAX]. The daemon is the source of truth;
 *     reverse lookups (getpwuid_r) ask the daemon for whichever actor owns
 *     the given uid hash so collisions are resolved server-side.
 *
 * No custom crypto here — FNV is used purely for namespace-local UID
 * derivation, never for authentication.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/* NSS entry points are visible; everything else stays hidden. */
#define NSS_EXPORT __attribute__((visibility("default")))

/* ---- TrustForge-reserved POSIX id range ------------------------------- *
 * Above 100000 by spec to stay clear of system + LDAP/AD reservations.
 * 30 bits of hash gives plenty of headroom while staying inside the
 * conventional 32-bit uid_t space. */
#define TF_UID_MIN   100000u
#define TF_UID_MAX   0x3FFFFFFFu  /* ~1.07e9, safely below 2^31 */

#define TF_DEFAULT_SHELL  "/usr/sbin/nologin"
#define TF_HOME_PREFIX    "/var/lib/trustforge/actors/"

#define TF_SOCK_PATH      "/run/trustforge/decide.sock"
#define TF_HTTP_HOST      "localhost"
#define TF_MAX_RESP       8192
#define TF_CONNECT_TO_MS  500   /* daemon must be snappy or we punt */

/* ---- enumeration cursor ----------------------------------------------- */
struct tf_enum_state {
    int          active;
    size_t       cursor;
    /* The list of known actor names returned by /v1/list-actors lives in
     * `buf`, NUL-separated, terminated by a double-NUL. */
    char        *buf;
    size_t       buf_len;
};
static struct tf_enum_state g_pwent = { 0, 0, NULL, 0 };
static pthread_mutex_t       g_pwent_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---- tiny utils ------------------------------------------------------- */

static uint64_t fnv1a64(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uid_t tf_uid_for_actor(const char *actor_id)
{
    uint64_t h = fnv1a64(actor_id);
    uint64_t span = (uint64_t)(TF_UID_MAX - TF_UID_MIN);
    return (uid_t)(TF_UID_MIN + (h % span));
}

/* Production path is the system local decision socket. */
static int tf_socket_path(char *out, size_t outlen)
{
    const char *override = getenv("TRUSTFORGE_SOCKET");
    const char *path = (override && *override) ? override : TF_SOCK_PATH;
    int n = snprintf(out, outlen, "%s", path);
    if (n > 0 && (size_t)n < outlen) return 0;
    return -1;
}

/* Connect to AF_UNIX path; return fd or -1 on failure (errno set). */
static int tf_connect(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/* Write everything or fail. */
static int tf_write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += n; len -= (size_t)n;
    }
    return 0;
}

/* Read until EOF or buffer full; NUL-terminate. Returns bytes read or -1. */
static ssize_t tf_read_all(int fd, char *buf, size_t cap)
{
    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t n = read(fd, buf + off, cap - 1 - off);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) break;
        off += (size_t)n;
    }
    buf[off] = '\0';
    return (ssize_t)off;
}

/*
 * tf_call(): send a one-shot HTTP/1.0 request to decide.sock and return
 * the response body in *out_body (caller frees). Returns:
 *    0  success, body populated
 *   -1  transient error (EAGAIN, ECONNREFUSED, etc.) — caller returns TRYAGAIN
 *   -2  daemon answered "not found" (HTTP 404) — caller returns NOTFOUND
 *   -3  malformed daemon response                — caller returns NOTFOUND
 */
static int tf_call(const char *path, const char *body_json, char **out_body)
{
    *out_body = NULL;

    char sock[256];
    if (tf_socket_path(sock, sizeof(sock)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = tf_connect(sock);
    if (fd < 0) return -1;

    /* Build request. Content-Length is mandatory for the daemon's parser. */
    char req[1024];
    int rn = snprintf(req, sizeof(req),
        "POST %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, TF_HTTP_HOST, strlen(body_json));
    if (rn <= 0 || (size_t)rn >= sizeof(req)) {
        close(fd); errno = EOVERFLOW; return -1;
    }

    if (tf_write_all(fd, req, (size_t)rn) != 0 ||
        tf_write_all(fd, body_json, strlen(body_json)) != 0) {
        int e = errno; close(fd); errno = e; return -1;
    }

    char *resp = malloc(TF_MAX_RESP);
    if (!resp) { close(fd); errno = ENOMEM; return -1; }

    ssize_t got = tf_read_all(fd, resp, TF_MAX_RESP);
    close(fd);
    if (got < 0) { free(resp); return -1; }

    /* Parse status line: "HTTP/1.x NNN ..." */
    if (strncmp(resp, "HTTP/1.", 7) != 0) { free(resp); return -3; }
    char *sp = strchr(resp, ' ');
    if (!sp) { free(resp); return -3; }
    int status = atoi(sp + 1);

    /* Body starts after CRLFCRLF. */
    char *body = strstr(resp, "\r\n\r\n");
    if (!body) { free(resp); return -3; }
    body += 4;

    if (status == 404) { free(resp); return -2; }
    if (status < 200 || status >= 300) { free(resp); return -3; }

    /* Hand back a freshly-allocated body. */
    char *dup = strdup(body);
    free(resp);
    if (!dup) { errno = ENOMEM; return -1; }
    *out_body = dup;
    return 0;
}

/*
 * Crude JSON string field extractor — sufficient for the two/three keys we
 * care about ("actor_id", "name", "shell", "home"). NOT a real JSON parser.
 * Output is written into `out`, up to outlen-1 chars, NUL-terminated.
 * Returns 0 on success, -1 if the key is missing.
 */
static int json_get_string(const char *json, const char *key,
                           char *out, size_t outlen)
{
    char needle[64];
    int nn = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (nn <= 0 || (size_t)nn >= sizeof(needle)) return -1;

    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += nn;
    while (*p && *p != ':') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;

    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outlen) {
        if (*p == '\\' && p[1]) { /* tolerate basic escapes */
            char c = p[1];
            switch (c) {
                case 'n': out[i++] = '\n'; break;
                case 't': out[i++] = '\t'; break;
                case '"': out[i++] = '"';  break;
                case '\\': out[i++] = '\\'; break;
                case '/': out[i++] = '/';  break;
                default: out[i++] = c; break;
            }
            p += 2;
            continue;
        }
        out[i++] = *p++;
    }
    if (i >= outlen) return -1;
    out[i] = '\0';
    return (*p == '"') ? 0 : -1;
}

/*
 * Pack a passwd record into the caller's buffer.
 *
 * NSS contract: every char* in `pwd` must point inside `buffer`. If we don't
 * fit, return ERANGE and the caller (glibc) will retry with a bigger buf.
 */
static int fill_passwd(struct passwd *pwd,
                       const char *name, const char *actor_id,
                       const char *home, const char *shell,
                       char *buffer, size_t buflen)
{
    size_t name_len  = strlen(name)  + 1;
    size_t pass_len  = 2;                  /* "x\0" */
    size_t gecos_len = strlen(actor_id) + 1;
    size_t home_len  = strlen(home)  + 1;
    size_t shell_len = strlen(shell) + 1;
    size_t total = name_len + pass_len + gecos_len + home_len + shell_len;
    if (total > buflen) return ERANGE;

    char *p = buffer;
    pwd->pw_name = p;   memcpy(p, name, name_len);     p += name_len;
    pwd->pw_passwd = p; memcpy(p, "x", pass_len);      p += pass_len;
    pwd->pw_gecos = p;  memcpy(p, actor_id, gecos_len); p += gecos_len;
    pwd->pw_dir = p;    memcpy(p, home, home_len);     p += home_len;
    pwd->pw_shell = p;  memcpy(p, shell, shell_len);

    uid_t uid = tf_uid_for_actor(actor_id);
    pwd->pw_uid = uid;
    pwd->pw_gid = uid;  /* user-private-group convention */
    return 0;
}

static int fill_group(struct group *grp,
                      const char *name, const char *actor_id,
                      char *buffer, size_t buflen)
{
    size_t name_len = strlen(name) + 1;
    size_t pass_len = 2;
    /* one-element gr_mem array (NULL terminator) — needs sizeof(char*)
     * worth of buffer aligned past the strings. */
    size_t total = name_len + pass_len + sizeof(char *);
    if (total > buflen) return ERANGE;

    char *p = buffer;
    grp->gr_name = p;   memcpy(p, name, name_len);  p += name_len;
    grp->gr_passwd = p; memcpy(p, "x", pass_len);   p += pass_len;

    /* Align p to pointer boundary for gr_mem. */
    uintptr_t pad = ((uintptr_t)p) % sizeof(char *);
    if (pad) {
        size_t add = sizeof(char *) - pad;
        if ((size_t)(p - buffer) + add + sizeof(char *) > buflen) return ERANGE;
        p += add;
    }
    char **mem = (char **)p;
    mem[0] = NULL;
    grp->gr_mem = mem;
    grp->gr_gid = tf_uid_for_actor(actor_id);
    return 0;
}

/* Build a JSON request body. Returns 0/-1, output in `out`. */
static int build_import_credential(char *out, size_t outlen,
                                   const char *credential, const char *hint)
{
    int n = snprintf(out, outlen,
        "{\"credential\":\"%s\",\"hint\":\"%s\"}",
        credential, hint);
    return (n > 0 && (size_t)n < outlen) ? 0 : -1;
}

static int build_lookup_uid(char *out, size_t outlen, uid_t uid)
{
    int n = snprintf(out, outlen, "{\"uid\":%u}", (unsigned)uid);
    return (n > 0 && (size_t)n < outlen) ? 0 : -1;
}

/* ====================================================================== *
 *  passwd entry points
 * ====================================================================== */

NSS_EXPORT enum nss_status
_nss_trustforge_getpwnam_r(const char *name, struct passwd *pwd,
                           char *buffer, size_t buflen, int *errnop)
{
    if (!name || !*name) { *errnop = EINVAL; return NSS_STATUS_NOTFOUND; }

    char body[512];
    if (build_import_credential(body, sizeof(body), name, "system-username") != 0) {
        *errnop = EINVAL; return NSS_STATUS_NOTFOUND;
    }

    char *resp = NULL;
    int rc = tf_call("/v1/import-credential", body, &resp);
    if (rc == -1) { *errnop = EAGAIN; return NSS_STATUS_TRYAGAIN; }
    if (rc == -2 || rc == -3) { *errnop = ENOENT; return NSS_STATUS_NOTFOUND; }

    char actor_id[256];
    if (json_get_string(resp, "actor_id", actor_id, sizeof(actor_id)) != 0) {
        free(resp); *errnop = ENOENT; return NSS_STATUS_NOTFOUND;
    }

    char home[512];
    if (json_get_string(resp, "home", home, sizeof(home)) != 0) {
        snprintf(home, sizeof(home), "%s%s", TF_HOME_PREFIX, name);
    }
    char shell[256];
    if (json_get_string(resp, "shell", shell, sizeof(shell)) != 0) {
        snprintf(shell, sizeof(shell), "%s", TF_DEFAULT_SHELL);
    }

    int frc = fill_passwd(pwd, name, actor_id, home, shell, buffer, buflen);
    free(resp);
    if (frc == ERANGE) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
    return NSS_STATUS_SUCCESS;
}

NSS_EXPORT enum nss_status
_nss_trustforge_getpwuid_r(uid_t uid, struct passwd *pwd,
                           char *buffer, size_t buflen, int *errnop)
{
    /* Fast reject anything outside our reserved range so we don't waste
     * a socket round-trip on every `ls -l` lookup. */
    if (uid < TF_UID_MIN || uid > TF_UID_MAX) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    char body[128];
    if (build_lookup_uid(body, sizeof(body), uid) != 0) {
        *errnop = EINVAL; return NSS_STATUS_NOTFOUND;
    }

    char *resp = NULL;
    int rc = tf_call("/v1/lookup-uid", body, &resp);
    if (rc == -1) { *errnop = EAGAIN; return NSS_STATUS_TRYAGAIN; }
    if (rc == -2 || rc == -3) { *errnop = ENOENT; return NSS_STATUS_NOTFOUND; }

    char name[256], actor_id[256];
    if (json_get_string(resp, "name", name, sizeof(name)) != 0 ||
        json_get_string(resp, "actor_id", actor_id, sizeof(actor_id)) != 0) {
        free(resp); *errnop = ENOENT; return NSS_STATUS_NOTFOUND;
    }
    char home[512];
    if (json_get_string(resp, "home", home, sizeof(home)) != 0) {
        snprintf(home, sizeof(home), "%s%s", TF_HOME_PREFIX, name);
    }
    char shell[256];
    if (json_get_string(resp, "shell", shell, sizeof(shell)) != 0) {
        snprintf(shell, sizeof(shell), "%s", TF_DEFAULT_SHELL);
    }

    int frc = fill_passwd(pwd, name, actor_id, home, shell, buffer, buflen);
    free(resp);
    if (frc == ERANGE) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

    /* The daemon is authoritative on uid; if its hash disagrees with ours,
     * we still trust the daemon — don't override pw_uid. */
    pwd->pw_uid = uid;
    pwd->pw_gid = uid;
    return NSS_STATUS_SUCCESS;
}

/* ====================================================================== *
 *  group entry points
 * ====================================================================== */

NSS_EXPORT enum nss_status
_nss_trustforge_getgrnam_r(const char *name, struct group *grp,
                           char *buffer, size_t buflen, int *errnop)
{
    if (!name || !*name) { *errnop = EINVAL; return NSS_STATUS_NOTFOUND; }

    char body[512];
    if (build_import_credential(body, sizeof(body), name, "system-groupname") != 0) {
        *errnop = EINVAL; return NSS_STATUS_NOTFOUND;
    }
    char *resp = NULL;
    int rc = tf_call("/v1/import-credential", body, &resp);
    if (rc == -1) { *errnop = EAGAIN; return NSS_STATUS_TRYAGAIN; }
    if (rc == -2 || rc == -3) { *errnop = ENOENT; return NSS_STATUS_NOTFOUND; }

    char actor_id[256];
    if (json_get_string(resp, "actor_id", actor_id, sizeof(actor_id)) != 0) {
        free(resp); *errnop = ENOENT; return NSS_STATUS_NOTFOUND;
    }

    int frc = fill_group(grp, name, actor_id, buffer, buflen);
    free(resp);
    if (frc == ERANGE) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
    return NSS_STATUS_SUCCESS;
}

NSS_EXPORT enum nss_status
_nss_trustforge_getgrgid_r(gid_t gid, struct group *grp,
                           char *buffer, size_t buflen, int *errnop)
{
    if (gid < TF_UID_MIN || gid > TF_UID_MAX) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    char body[128];
    if (build_lookup_uid(body, sizeof(body), (uid_t)gid) != 0) {
        *errnop = EINVAL; return NSS_STATUS_NOTFOUND;
    }
    char *resp = NULL;
    int rc = tf_call("/v1/lookup-uid", body, &resp);
    if (rc == -1) { *errnop = EAGAIN; return NSS_STATUS_TRYAGAIN; }
    if (rc == -2 || rc == -3) { *errnop = ENOENT; return NSS_STATUS_NOTFOUND; }

    char name[256], actor_id[256];
    if (json_get_string(resp, "name", name, sizeof(name)) != 0 ||
        json_get_string(resp, "actor_id", actor_id, sizeof(actor_id)) != 0) {
        free(resp); *errnop = ENOENT; return NSS_STATUS_NOTFOUND;
    }

    int frc = fill_group(grp, name, actor_id, buffer, buflen);
    free(resp);
    if (frc == ERANGE) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
    grp->gr_gid = gid;
    return NSS_STATUS_SUCCESS;
}

/* ====================================================================== *
 *  passwd enumeration  (setpwent/getpwent_r/endpwent)
 *
 *  Enumeration is only useful for `getent passwd` style tooling; we list
 *  whatever the daemon hands back from /v1/list-actors. Many production
 *  deployments will want to disable this entirely (returns NOTFOUND).
 * ====================================================================== */

NSS_EXPORT enum nss_status
_nss_trustforge_setpwent(void)
{
    pthread_mutex_lock(&g_pwent_mu);

    if (g_pwent.buf) { free(g_pwent.buf); g_pwent.buf = NULL; }
    g_pwent.buf_len = 0;
    g_pwent.cursor  = 0;
    g_pwent.active  = 0;

    char *resp = NULL;
    int rc = tf_call("/v1/list-actors", "{\"hint\":\"system-username\"}", &resp);
    if (rc != 0) {
        pthread_mutex_unlock(&g_pwent_mu);
        return (rc == -1) ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
    }

    /* Convert the JSON array `["a","b","c"]` to NUL-separated names. We
     * deliberately do not depend on a JSON lib; this is a strict fast-path
     * that tolerates the expected daemon format only. */
    size_t cap = strlen(resp) + 2;
    char *out = malloc(cap);
    if (!out) { free(resp); pthread_mutex_unlock(&g_pwent_mu); return NSS_STATUS_UNAVAIL; }
    size_t off = 0;

    const char *p = strchr(resp, '[');
    if (p) {
        p++;
        while (*p) {
            while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\t') p++;
            if (*p == ']' || *p == '\0') break;
            if (*p != '"') { p++; continue; }
            p++;
            while (*p && *p != '"' && off + 1 < cap) {
                out[off++] = *p++;
            }
            if (*p == '"') p++;
            if (off + 1 < cap) out[off++] = '\0';
        }
    }
    if (off + 1 < cap) out[off++] = '\0';  /* terminator */

    g_pwent.buf     = out;
    g_pwent.buf_len = off;
    g_pwent.cursor  = 0;
    g_pwent.active  = 1;

    free(resp);
    pthread_mutex_unlock(&g_pwent_mu);
    return NSS_STATUS_SUCCESS;
}

NSS_EXPORT enum nss_status
_nss_trustforge_endpwent(void)
{
    pthread_mutex_lock(&g_pwent_mu);
    if (g_pwent.buf) { free(g_pwent.buf); g_pwent.buf = NULL; }
    g_pwent.buf_len = 0;
    g_pwent.cursor  = 0;
    g_pwent.active  = 0;
    pthread_mutex_unlock(&g_pwent_mu);
    return NSS_STATUS_SUCCESS;
}

NSS_EXPORT enum nss_status
_nss_trustforge_getpwent_r(struct passwd *pwd, char *buffer, size_t buflen,
                           int *errnop)
{
    pthread_mutex_lock(&g_pwent_mu);
    if (!g_pwent.active || !g_pwent.buf || g_pwent.cursor >= g_pwent.buf_len) {
        pthread_mutex_unlock(&g_pwent_mu);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    const char *name = g_pwent.buf + g_pwent.cursor;
    if (*name == '\0') {
        pthread_mutex_unlock(&g_pwent_mu);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    /* Snapshot name; advance cursor past this NUL-terminated entry. */
    char namebuf[256];
    snprintf(namebuf, sizeof(namebuf), "%s", name);
    g_pwent.cursor += strlen(name) + 1;
    pthread_mutex_unlock(&g_pwent_mu);

    /* Reuse the by-name path so home/shell come from the daemon. */
    return _nss_trustforge_getpwnam_r(namebuf, pwd, buffer, buflen, errnop);
}
