/*
 * TrustForgePlugin.m - macOS Authorization plugin bridge for TrustForge
 *
 * Status: Draft (Phase 0). Experimental — not production-ready.
 *
 * Loaded by SecurityAgent when an authorization right is registered with
 * the rule "allow,com.trustforge.AuthPlugin:gate" via `security
 * authorizationdb write`. SecurityAgent invokes us through the
 * AuthorizationPluginInterface vtable defined in
 * <Security/AuthorizationPlugin.h>.
 *
 * On MechanismInvoke we:
 *   1. Read the requesting user from kAuthorizationEnvironmentUsername.
 *   2. Read the requested right name from kAuthorizationEnvironmentMechanism
 *      (falls back to "unknown").
 *   3. POST a small JSON body to /var/run/trustforge/decide.sock at
 *      /v1/decide and parse a "decision":"allow"|"deny" reply.
 *   4. SetResult(kAuthorizationResultAllow) iff "allow"; otherwise Deny.
 *
 * All other failure modes (missing socket, timeout, malformed reply,
 * non-2xx HTTP status) fail closed with Deny. We never default to allow.
 *
 * No custom crypto. No password handling. We only forward the decision
 * envelope to the daemon — the trust decisions live there per
 * docs/specs/TF-0001-core-architecture.md.
 */

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>
#import <Security/AuthorizationTags.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define TF_SOCK_PATH         "/var/run/trustforge/decide.sock"
#define TF_HTTP_PATH         "/v1/decide"
#define TF_DECIDE_TIMEOUT_MS 2000
#define TF_BUF_SIZE          8192

/* ---------- plugin / mechanism state types ---------- */

typedef struct {
    const AuthorizationCallbacks *callbacks;
} TFPlugin;

typedef struct {
    TFPlugin                *plugin;
    AuthorizationEngineRef   engine;
    const char              *mechanismId;  /* not owned, copy of AuthorizationMechanismId */
} TFMechanism;

/* ---------- logging ---------- */

static void
tf_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void
tf_log(int prio, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    /* SecurityAgent runs as a launchd job; syslog/asl ends up in unified log
     * under the "SecurityAgent" subsystem. */
    vsyslog(prio, fmt, ap);
    va_end(ap);
}

/* ---------- minimal JSON helpers (mirror linux/pam_trustforge) ---------- */

static int
tf_json_escape(char *out, size_t outsz, const char *in)
{
    size_t o = 0;
    if (outsz == 0) return -1;
    for (const char *p = in; *p; p++) {
        unsigned char c = (unsigned char)*p;
        const char *esc = NULL;
        char ubuf[8];
        size_t n = 0;
        switch (c) {
        case '"':  esc = "\\\""; n = 2; break;
        case '\\': esc = "\\\\"; n = 2; break;
        case '\b': esc = "\\b";  n = 2; break;
        case '\f': esc = "\\f";  n = 2; break;
        case '\n': esc = "\\n";  n = 2; break;
        case '\r': esc = "\\r";  n = 2; break;
        case '\t': esc = "\\t";  n = 2; break;
        default:
            if (c < 0x20) {
                snprintf(ubuf, sizeof(ubuf), "\\u%04x", c);
                esc = ubuf;
                n = 6;
            }
            break;
        }
        if (esc) {
            if (o + n >= outsz) return -1;
            memcpy(out + o, esc, n);
            o += n;
        } else {
            if (o + 1 >= outsz) return -1;
            out[o++] = (char)c;
        }
    }
    if (o >= outsz) return -1;
    out[o] = '\0';
    return (int)o;
}

static int
tf_json_find_string(const char *body, const char *key, char *out, size_t outsz)
{
    if (!body || !key || !out || outsz == 0) return 0;
    size_t klen = strlen(key);
    for (const char *p = body; *p; p++) {
        if (*p != '"') continue;
        const char *q = p + 1;
        while (*q) {
            if (*q == '\\' && q[1]) { q += 2; continue; }
            if (*q == '"') break;
            q++;
        }
        size_t span = (size_t)(q - (p + 1));
        if (span == klen && strncmp(p + 1, key, klen) == 0) {
            const char *r = q + 1;
            while (*r && (*r == ' ' || *r == '\t')) r++;
            if (*r != ':') { p = q; continue; }
            r++;
            while (*r && (*r == ' ' || *r == '\t')) r++;
            if (*r != '"') return 0;
            r++;
            size_t o = 0;
            while (*r && *r != '"') {
                char d = *r;
                if (*r == '\\' && r[1]) {
                    switch (r[1]) {
                    case '"':  d = '"';  break;
                    case '\\': d = '\\'; break;
                    case '/':  d = '/';  break;
                    case 'b':  d = '\b'; break;
                    case 'f':  d = '\f'; break;
                    case 'n':  d = '\n'; break;
                    case 'r':  d = '\r'; break;
                    case 't':  d = '\t'; break;
                    default:   d = r[1]; break;
                    }
                    r += 2;
                } else {
                    r++;
                }
                if (o + 1 < outsz) out[o++] = d;
            }
            out[o < outsz ? o : outsz - 1] = '\0';
            return 1;
        }
        p = q;
        if (*p == '\0') break;
    }
    return 0;
}

/* ---------- I/O with deadline ---------- */

static long
tf_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + (long)(ts.tv_nsec / 1000000L);
}

static int
tf_wait(int fd, short events, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = events };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1;
    if (pfd.revents & (POLLERR | POLLNVAL)) return -1;
    return 0;
}

/* ---------- HTTP request / response ---------- */

static int
tf_build_request(char *out, size_t outsz, const char *user,
                 const char *right, const char *service)
{
    char body[1024];
    char eu[256], er[256], es[256];

    if (tf_json_escape(eu, sizeof(eu), user ? user : "") < 0) return -1;
    if (tf_json_escape(er, sizeof(er), right ? right : "") < 0) return -1;
    if (tf_json_escape(es, sizeof(es), service ? service : "") < 0) return -1;

    int blen = snprintf(body, sizeof(body),
        "{"
        "\"actor\":null,"
        "\"host_token\":null,"
        "\"host_token_kind\":\"macos-authorization\","
        "\"action\":\"%s\","
        "\"target\":\"%s\","
        "\"username\":\"%s\""
        "}",
        er, es, eu);
    if (blen < 0 || (size_t)blen >= sizeof(body)) return -1;

    int n = snprintf(out, outsz,
        "POST %s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: TrustForgeAuthPlugin/0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        TF_HTTP_PATH, blen, body);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return n;
}

static int
tf_parse_http(const char *resp, size_t resp_len, int *status_out, const char **body_out)
{
    if (resp_len < 12 || strncmp(resp, "HTTP/", 5) != 0) return -1;
    const char *sp = memchr(resp, ' ', resp_len);
    if (!sp) return -1;
    int status = atoi(sp + 1);
    if (status <= 0) return -1;
    const char *end = NULL;
    for (size_t i = 0; i + 3 < resp_len; i++) {
        if (resp[i] == '\r' && resp[i+1] == '\n' &&
            resp[i+2] == '\r' && resp[i+3] == '\n') {
            end = resp + i + 4;
            break;
        }
    }
    if (!end) return -1;
    *status_out = status;
    *body_out   = end;
    return 0;
}

/*
 * Returns 1=allow, 0=explicit deny, -1=transport/parse error (callers treat
 * as deny, fail-closed).
 */
static int
tf_decide(const char *user, const char *right, const char *service)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        tf_log(LOG_ERR, "trustforge: socket(): %s", strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        tf_log(LOG_ERR, "trustforge: fcntl(): %s", strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(TF_SOCK_PATH) >= sizeof(addr.sun_path)) {
        tf_log(LOG_ERR, "trustforge: socket path too long");
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, TF_SOCK_PATH, sizeof(addr.sun_path) - 1);

    long deadline = tf_now_ms() + TF_DECIDE_TIMEOUT_MS;

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        tf_log(LOG_ERR, "trustforge: connect(%s): %s", TF_SOCK_PATH, strerror(errno));
        close(fd);
        return -1;
    }
    if (rc < 0) {
        long now = tf_now_ms();
        int wait_ms = (int)(deadline - now);
        if (wait_ms <= 0 || tf_wait(fd, POLLOUT, wait_ms) != 0) {
            tf_log(LOG_ERR, "trustforge: connect timeout");
            close(fd);
            return -1;
        }
        int err = 0; socklen_t errlen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
            tf_log(LOG_ERR, "trustforge: connect failed: %s",
                   err ? strerror(err) : "unknown");
            close(fd);
            return -1;
        }
    }

    char req[TF_BUF_SIZE];
    int reqlen = tf_build_request(req, sizeof(req), user, right, service);
    if (reqlen < 0) { close(fd); return -1; }

    size_t sent = 0;
    while (sent < (size_t)reqlen) {
        long now = tf_now_ms();
        int wait_ms = (int)(deadline - now);
        if (wait_ms <= 0) { close(fd); return -1; }
        if (tf_wait(fd, POLLOUT, wait_ms) != 0) { close(fd); return -1; }
        ssize_t n = send(fd, req + sent, reqlen - sent, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            tf_log(LOG_ERR, "trustforge: send: %s", strerror(errno));
            close(fd);
            return -1;
        }
        sent += (size_t)n;
    }

    char resp[TF_BUF_SIZE];
    size_t got = 0;
    for (;;) {
        long now = tf_now_ms();
        int wait_ms = (int)(deadline - now);
        if (wait_ms <= 0) { close(fd); return -1; }
        if (tf_wait(fd, POLLIN, wait_ms) != 0) { close(fd); return -1; }
        ssize_t n = recv(fd, resp + got, sizeof(resp) - 1 - got, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            tf_log(LOG_ERR, "trustforge: recv: %s", strerror(errno));
            close(fd);
            return -1;
        }
        if (n == 0) break;
        got += (size_t)n;
        if (got >= sizeof(resp) - 1) break;
    }
    close(fd);
    resp[got] = '\0';

    int status = 0;
    const char *body = NULL;
    if (tf_parse_http(resp, got, &status, &body) != 0) {
        tf_log(LOG_ERR, "trustforge: malformed HTTP response");
        return -1;
    }
    if (status < 200 || status >= 300) {
        tf_log(LOG_NOTICE, "trustforge: decide HTTP status %d", status);
        return 0;
    }

    char decision[32] = {0};
    if (!tf_json_find_string(body, "decision", decision, sizeof(decision))) {
        tf_log(LOG_ERR, "trustforge: response missing 'decision' field");
        return -1;
    }
    if (strcmp(decision, "allow") == 0) {
        tf_log(LOG_INFO, "trustforge: allow user=%s right=%s",
               user ? user : "?", right ? right : "?");
        return 1;
    }
    tf_log(LOG_NOTICE, "trustforge: deny user=%s right=%s decision=%s",
           user ? user : "?", right ? right : "?", decision);
    return 0;
}

/* ---------- environment / hint helpers ---------- */

static const char *
tf_get_hint_string(TFMechanism *m, AuthorizationString key, char *buf, size_t bufsz)
{
    if (!m || !m->plugin || !m->plugin->callbacks) return NULL;
    const AuthorizationValue *val = NULL;
    OSStatus s = m->plugin->callbacks->GetHintValue(m->engine, key, &val);
    if (s != errAuthorizationSuccess || !val || !val->data || val->length == 0)
        return NULL;
    size_t n = val->length;
    if (n >= bufsz) n = bufsz - 1;
    memcpy(buf, val->data, n);
    /* The auth engine may or may not NUL-terminate; trim a trailing NUL if
     * present so we don't include it in JSON. */
    while (n > 0 && buf[n - 1] == '\0') n--;
    buf[n] = '\0';
    return buf;
}

static const char *
tf_get_context_string(TFMechanism *m, AuthorizationString key, char *buf, size_t bufsz)
{
    if (!m || !m->plugin || !m->plugin->callbacks) return NULL;
    AuthorizationContextFlags flags = 0;
    const AuthorizationValue *val = NULL;
    OSStatus s = m->plugin->callbacks->GetContextValue(m->engine, key, &flags, &val);
    if (s != errAuthorizationSuccess || !val || !val->data || val->length == 0)
        return NULL;
    size_t n = val->length;
    if (n >= bufsz) n = bufsz - 1;
    memcpy(buf, val->data, n);
    while (n > 0 && buf[n - 1] == '\0') n--;
    buf[n] = '\0';
    return buf;
}

/* ---------- AuthorizationPluginInterface vtable ---------- */

static OSStatus
TFMechanismInvoke(AuthorizationMechanismRef inMechanism)
{
    TFMechanism *m = (TFMechanism *)inMechanism;
    if (!m || !m->plugin || !m->plugin->callbacks) {
        return errAuthorizationInternal;
    }

    char user[256] = {0};
    char right[256] = {0};
    char service[256] = {0};

    /* Username may live in either context (after a credential mechanism ran)
     * or hints (when we are the first mechanism). Try context first. */
    const char *u = tf_get_context_string(m, kAuthorizationEnvironmentUsername,
                                          user, sizeof(user));
    if (!u || !*u) {
        u = tf_get_hint_string(m, kAuthorizationEnvironmentUsername,
                               user, sizeof(user));
    }
    if (!u || !*u) {
        /* Last resort: real uid -> name. */
        struct passwd pwd, *pwres = NULL;
        char pwbuf[1024];
        if (getpwuid_r(getuid(), &pwd, pwbuf, sizeof(pwbuf), &pwres) == 0 && pwres) {
            strncpy(user, pwres->pw_name, sizeof(user) - 1);
            u = user;
        } else {
            u = "";
        }
    }

    /* The right name is exposed to mechanisms via the "right" hint and the
     * mechanism id itself. */
    const char *r = tf_get_hint_string(m, "right", right, sizeof(right));
    if (!r || !*r) {
        if (m->mechanismId) {
            strncpy(right, m->mechanismId, sizeof(right) - 1);
            r = right;
        } else {
            r = "unknown";
        }
    }

    const char *svc = tf_get_hint_string(m, "client-path", service, sizeof(service));
    if (!svc || !*svc) svc = "macos-authorization";

    int verdict = tf_decide(u, r, svc);

    AuthorizationResult result =
        (verdict == 1) ? kAuthorizationResultAllow : kAuthorizationResultDeny;

    OSStatus s = m->plugin->callbacks->SetResult(m->engine, result);
    if (s != errAuthorizationSuccess) {
        tf_log(LOG_ERR, "trustforge: SetResult failed: %d", (int)s);
        return s;
    }
    return errAuthorizationSuccess;
}

static OSStatus
TFMechanismCreate(AuthorizationPluginRef inPlugin,
                  AuthorizationEngineRef inEngine,
                  AuthorizationMechanismId mechanismId,
                  AuthorizationMechanismRef *outMechanism)
{
    if (!inPlugin || !outMechanism) return errAuthorizationInternal;
    TFMechanism *m = (TFMechanism *)calloc(1, sizeof(*m));
    if (!m) return errAuthorizationInternal;
    m->plugin       = (TFPlugin *)inPlugin;
    m->engine       = inEngine;
    m->mechanismId  = mechanismId;
    *outMechanism   = (AuthorizationMechanismRef)m;
    tf_log(LOG_DEBUG, "trustforge: MechanismCreate id=%s",
           mechanismId ? mechanismId : "?");
    return errAuthorizationSuccess;
}

static OSStatus
TFMechanismDeactivate(AuthorizationMechanismRef inMechanism)
{
    TFMechanism *m = (TFMechanism *)inMechanism;
    if (!m || !m->plugin || !m->plugin->callbacks) return errAuthorizationInternal;
    /* Acknowledge deactivation; we have no async state to drain. */
    OSStatus s = m->plugin->callbacks->DidDeactivate(m->engine);
    return s;
}

static OSStatus
TFMechanismDestroy(AuthorizationMechanismRef inMechanism)
{
    if (inMechanism) free(inMechanism);
    return errAuthorizationSuccess;
}

static OSStatus
TFPluginDestroy(AuthorizationPluginRef inPlugin)
{
    if (inPlugin) free(inPlugin);
    return errAuthorizationSuccess;
}

static const AuthorizationPluginInterface gTFInterface = {
    .version              = kAuthorizationPluginInterfaceVersion,
    .PluginDestroy        = TFPluginDestroy,
    .MechanismCreate      = TFMechanismCreate,
    .MechanismInvoke      = TFMechanismInvoke,
    .MechanismDeactivate  = TFMechanismDeactivate,
    .MechanismDestroy     = TFMechanismDestroy,
};

/* The single exported symbol the SecurityAgent looks up. */
OSStatus
AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                          AuthorizationPluginRef *outPlugin,
                          const AuthorizationPluginInterface **outPluginInterface)
{
    if (!callbacks || !outPlugin || !outPluginInterface) {
        return errAuthorizationInternal;
    }
    if (callbacks->version < kAuthorizationCallbacksVersion) {
        tf_log(LOG_ERR, "trustforge: callbacks version too old: %u",
               (unsigned)callbacks->version);
        return errAuthorizationInternal;
    }
    TFPlugin *p = (TFPlugin *)calloc(1, sizeof(*p));
    if (!p) return errAuthorizationInternal;
    p->callbacks = callbacks;
    *outPlugin = (AuthorizationPluginRef)p;
    *outPluginInterface = &gTFInterface;
    openlog("TrustForgeAuthPlugin", LOG_PID | LOG_NDELAY, LOG_AUTH);
    tf_log(LOG_INFO, "trustforge: plugin loaded");
    return errAuthorizationSuccess;
}
