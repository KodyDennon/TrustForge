/*
 * sudo_trustforge.c -- TrustForge sudo policy plugin
 *
 * This is a sudo policy plugin (see sudo_plugin(5)). It intercepts every
 * `sudo <command>` invocation, asks the local TrustForge daemon whether
 * the action is permitted, and accepts or rejects accordingly.
 *
 * Wire contract: a single POST to ~/.trustforge/decide.sock at /v1/decide
 * with body:
 *
 *   {
 *     "actor": null,
 *     "host_token": "<SUDO_USER>",
 *     "host_token_kind": "session-cookie",
 *     "action": "shell.exec",
 *     "target": "<argv[0]>",
 *     "context": { "argv": "<serialized argv>" }
 *   }
 *
 * The daemon's response is JSON; the plugin allows iff the top-level
 * "decision" field equals "allow". Any other response (deny, indeterminate,
 * malformed, daemon unreachable) is treated as deny -- fail-closed.
 *
 * NOTE: this plugin performs *no* cryptography. It is a transport-only
 * shim that defers all policy to the TrustForge daemon, which is the
 * canonical decision point. See SECURITY.md and TF-0001.
 *
 * Build: see Makefile. Requires sudo_plugin.h from libsudo-dev.
 */

#include <sudo_plugin.h>

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SUDO_API_VERSION
#error "sudo_plugin.h missing SUDO_API_VERSION; install libsudo-dev / sudo-devel"
#endif

/* ----- plugin state ---------------------------------------------------- */

static sudo_printf_t  tf_log    = NULL;
static sudo_conv_t    tf_conv   = NULL;
static char *const   *tf_settings  = NULL;
static char *const   *tf_user_info = NULL;
static char *const   *tf_user_env  = NULL;

static char tf_socket_path[512] = {0};

/* ----- helpers --------------------------------------------------------- */

static void
tf_logf(int level, const char *fmt, ...)
{
    if (tf_log == NULL)
        return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    tf_log(level, "sudo_trustforge: %s\n", buf);
}

/* Resolve the daemon socket path. We default to ~/.trustforge/decide.sock
 * but allow override via the TRUSTFORGE_SOCKET environment variable for
 * tests. Users running sudo retain HOME of the *invoking* user for the
 * purposes of locating the daemon socket: TrustForge runs in the user's
 * session, not as root. */
static int
tf_resolve_socket(void)
{
    const char *override = getenv("TRUSTFORGE_SOCKET");
    if (override != NULL && override[0] != '\0') {
        snprintf(tf_socket_path, sizeof(tf_socket_path), "%s", override);
        return 0;
    }
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        /* sudo scrubs HOME by default; fall back to SUDO_USER's homedir
         * via a conservative path. The README documents that operators
         * who run with `Defaults env_reset` must add HOME to env_keep or
         * set TRUSTFORGE_SOCKET in sudo.conf-side configuration. */
        return -1;
    }
    snprintf(tf_socket_path, sizeof(tf_socket_path),
             "%s/.trustforge/decide.sock", home);
    return 0;
}

/* Append an escaped JSON string to `out` of capacity `cap`. Returns the
 * number of bytes written or -1 on overflow. */
static ssize_t
tf_json_escape(char *out, size_t cap, const char *in)
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

/* Serialize argv into a single space-delimited (JSON-escaped) string. */
static int
tf_serialize_argv(char *const argv[], char *out, size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; argv != NULL && argv[i] != NULL; i++) {
        const char *a = argv[i];
        if (i > 0) {
            if (n + 1 >= cap) return -1;
            out[n++] = ' ';
        }
        for (const char *p = a; *p; p++) {
            if (n + 1 >= cap) return -1;
            out[n++] = *p;
        }
    }
    if (n >= cap) return -1;
    out[n] = '\0';
    return 0;
}

/* Connect to the daemon UNIX socket. Returns fd or -1. */
static int
tf_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        tf_logf(SUDO_CONV_ERROR_MSG, "socket(): %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(tf_socket_path) >= sizeof(addr.sun_path)) {
        tf_logf(SUDO_CONV_ERROR_MSG, "socket path too long");
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, tf_socket_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        tf_logf(SUDO_CONV_ERROR_MSG, "connect(%s): %s",
                tf_socket_path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* Write all of buf, looping over short writes. */
static int
tf_write_all(int fd, const char *buf, size_t len)
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

/* Read up to cap-1 bytes from fd into out. NUL-terminates. */
static ssize_t
tf_read_all(int fd, char *out, size_t cap)
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

/* Crude scan for `"decision":"allow"` inside the response body. We do not
 * link a JSON parser into a sudo plugin; the daemon's contract guarantees
 * a stable shape. Anything else is denial. */
static int
tf_response_is_allow(const char *body)
{
    /* Find start of body past HTTP headers. */
    const char *sep = strstr(body, "\r\n\r\n");
    const char *json = sep ? sep + 4 : body;
    /* Tolerate whitespace variations. */
    const char *needle1 = "\"decision\":\"allow\"";
    const char *needle2 = "\"decision\": \"allow\"";
    return strstr(json, needle1) != NULL || strstr(json, needle2) != NULL;
}

/* Send the decide request and return 1=allow, 0=deny. Fails closed. */
static int
tf_query_daemon(const char *target, const char *argv_serialized)
{
    if (tf_resolve_socket() != 0) {
        tf_logf(SUDO_CONV_ERROR_MSG,
                "cannot resolve TrustForge socket path (HOME unset?)");
        return 0;
    }

    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user == NULL) sudo_user = "";

    /* Build the JSON body. */
    char esc_user[256], esc_target[1024], esc_argv[4096];
    if (tf_json_escape(esc_user,   sizeof(esc_user),   sudo_user)        < 0 ||
        tf_json_escape(esc_target, sizeof(esc_target), target)           < 0 ||
        tf_json_escape(esc_argv,   sizeof(esc_argv),   argv_serialized)  < 0) {
        tf_logf(SUDO_CONV_ERROR_MSG, "failed to encode request body");
        return 0;
    }

    char body[8192];
    int body_len = snprintf(body, sizeof(body),
        "{\"actor\":null,"
        "\"host_token\":%s,"
        "\"host_token_kind\":\"session-cookie\","
        "\"action\":\"shell.exec\","
        "\"target\":%s,"
        "\"context\":{\"argv\":%s}}",
        esc_user, esc_target, esc_argv);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        tf_logf(SUDO_CONV_ERROR_MSG, "request body too large");
        return 0;
    }

    char request[12288];
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
        tf_logf(SUDO_CONV_ERROR_MSG, "request too large");
        return 0;
    }

    int fd = tf_connect();
    if (fd < 0) return 0;

    if (tf_write_all(fd, request, (size_t)req_len) != 0) {
        tf_logf(SUDO_CONV_ERROR_MSG, "write to daemon failed: %s",
                strerror(errno));
        close(fd);
        return 0;
    }

    char resp[8192];
    ssize_t n = tf_read_all(fd, resp, sizeof(resp));
    close(fd);
    if (n <= 0) {
        tf_logf(SUDO_CONV_ERROR_MSG, "no response from daemon");
        return 0;
    }

    return tf_response_is_allow(resp) ? 1 : 0;
}

/* ----- policy plugin entry points ------------------------------------- */

static int
policy_open(unsigned int version, sudo_conv_t conversation,
            sudo_printf_t plugin_printf, char *const settings[],
            char *const user_info[], char *const user_env[],
            char *const plugin_options[])
{
    (void)plugin_options;

    tf_log      = plugin_printf;
    tf_conv     = conversation;
    tf_settings = settings;
    tf_user_info = user_info;
    tf_user_env  = user_env;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        tf_logf(SUDO_CONV_ERROR_MSG,
                "incompatible plugin major %u (expected %u)",
                SUDO_API_VERSION_GET_MAJOR(version),
                SUDO_API_VERSION_MAJOR);
        return -1;
    }
    return 1;
}

static void
policy_close(int exit_status, int error)
{
    (void)exit_status;
    (void)error;
}

static int
policy_show_version(int verbose)
{
    if (tf_log == NULL) return 1;
    tf_log(SUDO_CONV_INFO_MSG, "TrustForge sudo policy plugin 0.1.0\n");
    if (verbose) {
        tf_log(SUDO_CONV_INFO_MSG,
               "  fail-closed; daemon socket: $HOME/.trustforge/decide.sock\n");
    }
    return 1;
}

static int
policy_check(int argc, char *const argv[],
             char *env_add[], char **command_info_out[],
             char **argv_out[], char **user_env_out[])
{
    (void)env_add;

    if (argc < 1 || argv == NULL || argv[0] == NULL) {
        tf_logf(SUDO_CONV_ERROR_MSG, "policy_check: empty argv");
        return 0;
    }

    /* argv[0] is the command sudo is being asked to run. */
    const char *target = argv[0];

    char serialized[4096];
    if (tf_serialize_argv(argv, serialized, sizeof(serialized)) != 0) {
        tf_logf(SUDO_CONV_ERROR_MSG, "argv too long to serialize");
        return 0;
    }

    int allow = tf_query_daemon(target, serialized);
    if (!allow) {
        tf_logf(SUDO_CONV_ERROR_MSG,
                "TrustForge denied: action=shell.exec target=%s", target);
        return 0;
    }

    /* On allow, hand argv straight back unchanged. sudo requires a
     * command_info array describing how to execute the command; we
     * supply the minimum: the resolved command. */
    static char *info[3];
    static char  info0[1024];
    snprintf(info0, sizeof(info0), "command=%s", target);
    info[0] = info0;
    info[1] = "runas_uid=0";
    info[2] = NULL;

    *command_info_out = info;
    *argv_out         = (char **)argv;
    *user_env_out     = (char **)tf_user_env;
    return 1;
}

static int
policy_list(int argc, char *const argv[], int verbose, const char *list_user)
{
    (void)argc;
    (void)argv;
    (void)verbose;
    (void)list_user;
    if (tf_log != NULL) {
        tf_log(SUDO_CONV_INFO_MSG,
               "TrustForge policy is delegated to the TrustForge daemon.\n"
               "Use `tf policy list` for the user-facing view.\n");
    }
    return 1;
}

static int
policy_validate(void)
{
    /* Nothing to pre-validate; every check is dynamic. */
    return 1;
}

static void
policy_invalidate(int remove)
{
    (void)remove;
    /* Stateless plugin: no cached credentials to drop. */
}

static int
policy_init_session(struct passwd *pwd, char **user_env_out[])
{
    (void)pwd;
    if (user_env_out != NULL)
        *user_env_out = (char **)tf_user_env;
    return 1;
}

/* ----- plugin registration -------------------------------------------- */

__attribute__((visibility("default")))
struct policy_plugin sudoers_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    policy_open,
    policy_close,
    policy_show_version,
    policy_check,
    policy_list,
    policy_validate,
    policy_invalidate,
    policy_init_session,
    NULL, /* register_hooks    */
    NULL, /* deregister_hooks  */
};
