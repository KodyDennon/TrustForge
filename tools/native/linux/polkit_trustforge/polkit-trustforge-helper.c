/*
 * polkit-trustforge-helper.c -- companion helper for polkit-1 JS rules.
 *
 * polkit's authorization rules are JavaScript executed inside polkitd by
 * mozjs. Embedding TrustForge logic into JS is awkward and would force
 * us to link libpolkit; instead we ship a tiny standalone helper that
 * the JS rule invokes via polkit.spawn(). The helper:
 *
 *   1. Receives the polkit action.id as argv[1] and the subject user as
 *      argv[2] (passed by the rule file, see 49-trustforge.rules).
 *   2. Connects to the TrustForge daemon socket
 *      (/run/trustforge/decide.sock by default; overridable via
 *      $TRUSTFORGE_SOCKET).
 *   3. POSTs to /v1/decide with body
 *        { "actor": "<subject user>", "host_token": "<subject user>",
 *          "host_token_kind": "session-cookie",
 *          "action": "<mapped action name>",
 *          "target": "<polkit action.id>",
 *          "context": {} }
 *   4. Prints "yes" on stdout iff the daemon's response contains
 *      "decision":"allow"; otherwise prints "no". The polkit JS rule
 *      maps "yes" -> polkit.Result.YES, anything else -> polkit.Result.NO.
 *
 * Fails closed: any error path (bad args, daemon unreachable, malformed
 * response) results in "no" on stdout and a non-zero exit.
 *
 * No cryptography happens here. All policy is the daemon's call. See
 * SECURITY.md and TF-0001.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Map polkit action namespaces to TrustForge action names. The JS rule
 * could pass these directly, but doing it here keeps the rule one-line
 * and the mapping table reviewable. */
static const char *
tf_action_for_polkit(const char *action_id)
{
    if (action_id == NULL) return "polkit.unknown";
    /* Common prefix-based mapping. Refine as the TF action vocabulary
     * stabilises (see TF-0001 canonical object vocabulary). */
    if (strncmp(action_id, "org.freedesktop.policykit.exec", 30) == 0)
        return "shell.exec";
    if (strncmp(action_id, "org.freedesktop.systemd1.", 25) == 0)
        return "service.manage";
    if (strncmp(action_id, "org.freedesktop.NetworkManager.", 31) == 0)
        return "network.configure";
    if (strncmp(action_id, "org.freedesktop.UDisks2.", 24) == 0)
        return "storage.manage";
    if (strncmp(action_id, "org.freedesktop.packagekit.", 27) == 0)
        return "package.manage";
    /* Default: prefix with polkit. so the daemon side can match by family. */
    static char buf[256];
    snprintf(buf, sizeof(buf), "polkit.%s", action_id);
    return buf;
}

static int
resolve_socket(char *out, size_t cap)
{
    const char *override = getenv("TRUSTFORGE_SOCKET");
    if (override != NULL && override[0] != '\0') {
        snprintf(out, cap, "%s", override);
        return 0;
    }
    snprintf(out, cap, "/run/trustforge/decide.sock");
    return 0;
}

static ssize_t
json_escape(char *out, size_t cap, const char *in)
{
    size_t n = 0;
    if (cap == 0) return -1;
    out[n++] = '"';
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (n + 8 >= cap) return -1;
        switch (*p) {
        case '"':  out[n++] = '\\'; out[n++] = '"';  break;
        case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
        case '\b': out[n++] = '\\'; out[n++] = 'b';  break;
        case '\f': out[n++] = '\\'; out[n++] = 'f';  break;
        case '\n': out[n++] = '\\'; out[n++] = 'n';  break;
        case '\r': out[n++] = '\\'; out[n++] = 'r';  break;
        case '\t': out[n++] = '\\'; out[n++] = 't';  break;
        default:
            if (*p < 0x20) {
                n += snprintf(out + n, cap - n, "\\u%04x", *p);
            } else {
                out[n++] = (char)*p;
            }
        }
    }
    if (n + 2 >= cap) return -1;
    out[n++] = '"';
    out[n] = '\0';
    return (ssize_t)n;
}

static int
write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t w = write(fd, buf, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += w; len -= (size_t)w;
    }
    return 0;
}

static ssize_t
read_all(int fd, char *out, size_t cap)
{
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t r = read(fd, out + total, cap - 1 - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    out[total] = '\0';
    return (ssize_t)total;
}

static int
response_is_allow(const char *body)
{
    const char *sep = strstr(body, "\r\n\r\n");
    const char *json = sep ? sep + 4 : body;
    return strstr(json, "\"decision\":\"allow\"")  != NULL ||
           strstr(json, "\"decision\": \"allow\"") != NULL;
}

int
main(int argc, char **argv)
{
    /* polkit.spawn() invokes us with argv[1]=action.id, argv[2]=user. */
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <polkit-action-id> <subject-user>\n",
                argv[0]);
        printf("no\n");
        return 2;
    }
    const char *action_id = argv[1];
    const char *subject   = argv[2];
    const char *tf_action = tf_action_for_polkit(action_id);

    char sock_path[512];
    if (resolve_socket(sock_path, sizeof(sock_path)) != 0) {
        fprintf(stderr, "cannot resolve TrustForge socket path "
                        "(check /run/trustforge/decide.sock or TRUSTFORGE_SOCKET)\n");
        printf("no\n");
        return 3;
    }

    char esc_subject[256], esc_action[256], esc_target[512];
    if (json_escape(esc_subject, sizeof(esc_subject), subject)   < 0 ||
        json_escape(esc_action,  sizeof(esc_action),  tf_action) < 0 ||
        json_escape(esc_target,  sizeof(esc_target),  action_id) < 0) {
        fprintf(stderr, "failed to encode request body\n");
        printf("no\n");
        return 4;
    }

    char body[2048];
    int body_len = snprintf(body, sizeof(body),
        "{\"actor\":%s,"
        "\"host_token\":%s,"
        "\"host_token_kind\":\"session-cookie\","
        "\"action\":%s,"
        "\"target\":%s,"
        "\"context\":{}}",
        esc_subject, esc_subject, esc_action, esc_target);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        fprintf(stderr, "request body too large\n");
        printf("no\n");
        return 4;
    }

    char request[4096];
    int req_len = snprintf(request, sizeof(request),
        "POST /v1/decide HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body);
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        fprintf(stderr, "request too large\n");
        printf("no\n");
        return 4;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket(): %s\n", strerror(errno));
        printf("no\n");
        return 5;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket path too long\n");
        close(fd);
        printf("no\n");
        return 5;
    }
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "connect(%s): %s\n", sock_path, strerror(errno));
        close(fd);
        printf("no\n");
        return 5;
    }

    if (write_all(fd, request, (size_t)req_len) != 0) {
        fprintf(stderr, "write: %s\n", strerror(errno));
        close(fd);
        printf("no\n");
        return 6;
    }

    char resp[4096];
    ssize_t n = read_all(fd, resp, sizeof(resp));
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "no response from daemon\n");
        printf("no\n");
        return 7;
    }

    if (response_is_allow(resp)) {
        printf("yes\n");
        return 0;
    }
    printf("no\n");
    return 1;
}
