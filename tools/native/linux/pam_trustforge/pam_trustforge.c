/*
 * pam_trustforge.c - TrustForge PAM bridge
 *
 * Status: Draft (Phase 0). Experimental — not production-ready.
 *
 * On authenticate / acct_mgmt / open_session, this module asks the local
 * TrustForge daemon (Unix socket at /run/trustforge/decide.sock by default) whether
 * the requested action should be allowed. The decision is made by sending
 * a small JSON body to POST /v1/decide and inspecting the "decision" field
 * of the JSON response.
 *
 * Fail-closed semantics:
 *   - Any error (no socket, timeout, malformed JSON, non-allow decision,
 *     non-2xx status) returns PAM_AUTH_ERR for auth/acct/session. We never
 *     fall back to "allow" on error.
 *
 * Heavy deps are deliberately avoided. We hand-parse a tiny JSON subset
 * (sufficient for {"decision":"allow|deny", ...}) so the .so has only a
 * libpam runtime dependency.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>

#define TF_DECIDE_TIMEOUT_MS  2000
#define TF_BUF_SIZE           8192
#define TF_DEFAULT_SOCK_PATH  "/run/trustforge/decide.sock"
#define TF_HTTP_PATH          "/v1/decide"

/* ---------- logging helpers ---------- */

static void
tf_log(pam_handle_t *pamh, int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	pam_vsyslog(pamh, prio, fmt, ap);
	va_end(ap);
}

/* ---------- JSON helpers (minimal) ---------- */

/*
 * Append a JSON string literal, escaping the bare minimum: ", \, control
 * chars. Other non-ASCII bytes are emitted unchanged (assumed UTF-8).
 *
 * Returns number of bytes written or -1 on overflow.
 */
static int
tf_json_escape(char *out, size_t outsz, const char *in)
{
	size_t o = 0;
	if (outsz == 0)
		return -1;
	for (const char *p = in; *p; p++) {
		const unsigned char c = (unsigned char)*p;
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
			if (o + n >= outsz)
				return -1;
			memcpy(out + o, esc, n);
			o += n;
		} else {
			if (o + 1 >= outsz)
				return -1;
			out[o++] = (char)c;
		}
	}
	if (o >= outsz)
		return -1;
	out[o] = '\0';
	return (int)o;
}

/*
 * Find a top-level JSON string field by name in a flat object body.
 * Caveat: this is intentionally a tiny lexer — it skips strings/escapes
 * but does not validate full JSON. Sufficient for "decision":"allow".
 *
 * On match, copies the unescaped (we treat as raw) value into out (NUL-
 * terminated, truncated to outsz) and returns 1. Returns 0 if missing.
 */
static int
tf_json_find_string(const char *body, const char *key, char *out, size_t outsz)
{
	if (!body || !key || !out || outsz == 0)
		return 0;
	size_t klen = strlen(key);

	for (const char *p = body; *p; p++) {
		/* skip strings entirely so we don't match inside values */
		if (*p == '"') {
			const char *q = p + 1;
			while (*q) {
				if (*q == '\\' && q[1])
					q += 2;
				else if (*q == '"')
					break;
				else
					q++;
			}
			/* Check whether this string is exactly our key */
			size_t span = (size_t)(q - (p + 1));
			if (span == klen && strncmp(p + 1, key, klen) == 0) {
				/* Move past closing quote of the key */
				const char *r = q + 1;
				while (*r && isspace((unsigned char)*r))
					r++;
				if (*r != ':')
					goto skip;
				r++;
				while (*r && isspace((unsigned char)*r))
					r++;
				if (*r != '"')
					return 0;
				r++;
				size_t o = 0;
				while (*r && *r != '"') {
					if (*r == '\\' && r[1]) {
						/* Decode common escapes */
						char d = 0;
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
						if (o + 1 < outsz)
							out[o++] = d;
						r += 2;
					} else {
						if (o + 1 < outsz)
							out[o++] = *r;
						r++;
					}
				}
				out[o < outsz ? o : outsz - 1] = '\0';
				return 1;
			}
skip:
			p = q; /* continue after the string */
			if (*p == '\0')
				break;
		}
	}
	return 0;
}

/* ---------- socket path resolution ---------- */

static int
tf_resolve_sock_path(pam_handle_t *pamh, const char *user, char *out, size_t outsz)
{
	const char *override = getenv("TRUSTFORGE_SOCKET");
	const char *path = (override && override[0]) ? override : TF_DEFAULT_SOCK_PATH;
	int n = snprintf(out, outsz, "%s", path);
	if (n < 0 || (size_t)n >= outsz) {
		tf_log(pamh, LOG_ERR, "trustforge: socket path overflow");
		return -1;
	}
	(void)user;
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
tf_wait_writable(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0)
		return -1;
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
		return -1;
	return 0;
}

static int
tf_wait_readable(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0)
		return -1;
	if (pfd.revents & (POLLERR | POLLNVAL))
		return -1;
	return 0;
}

/* ---------- request builder ---------- */

/*
 * Build an HTTP/1.1 POST /v1/decide request with a small JSON body.
 * Returns total request length, or -1 on overflow.
 */
static int
tf_build_request(char *out, size_t outsz, const char *action, const char *target,
		 const char *host_token)
{
	char body[2048];
	char esc_action[256];
	char esc_target[256];
	char esc_token[1024];

	/* host_token may be NULL (no PAM_AUTHTOK available) */
	const char *tok = host_token ? host_token : "";

	if (tf_json_escape(esc_action, sizeof(esc_action), action) < 0)
		return -1;
	if (tf_json_escape(esc_target, sizeof(esc_target), target) < 0)
		return -1;
	if (tf_json_escape(esc_token, sizeof(esc_token), tok) < 0)
		return -1;

	int blen = snprintf(body, sizeof(body),
		"{"
		"\"actor\":null,"
		"\"host_token\":\"%s\","
		"\"host_token_kind\":\"session-cookie\","
		"\"action\":\"%s\","
		"\"target\":\"%s\""
		"}",
		esc_token, esc_action, esc_target);
	if (blen < 0 || (size_t)blen >= sizeof(body))
		return -1;

	int n = snprintf(out, outsz,
		"POST %s HTTP/1.1\r\n"
		"Host: localhost\r\n"
		"User-Agent: pam_trustforge/0.1\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		TF_HTTP_PATH, blen, body);
	if (n < 0 || (size_t)n >= outsz)
		return -1;
	return n;
}

/* ---------- HTTP response parsing ---------- */

/*
 * Locate the start of the response body and the HTTP status code.
 * Returns 0 on success and fills *body_out / *status_out.
 */
static int
tf_parse_http(const char *resp, size_t resp_len, int *status_out, const char **body_out)
{
	if (resp_len < 12 || strncmp(resp, "HTTP/", 5) != 0)
		return -1;
	const char *sp = memchr(resp, ' ', resp_len);
	if (!sp)
		return -1;
	int status = atoi(sp + 1);
	if (status <= 0)
		return -1;

	/* Find end of headers (\r\n\r\n) */
	const char *end = NULL;
	for (size_t i = 0; i + 3 < resp_len; i++) {
		if (resp[i] == '\r' && resp[i + 1] == '\n' &&
		    resp[i + 2] == '\r' && resp[i + 3] == '\n') {
			end = resp + i + 4;
			break;
		}
	}
	if (!end)
		return -1;

	*status_out = status;
	*body_out = end;
	return 0;
}

/* ---------- decision RPC ---------- */

/*
 * Send a decide request and parse the decision. Returns:
 *   1  -> allow
 *   0  -> deny / not-allow
 *  -1  -> transport / parse error (treated as deny by callers)
 */
static int
tf_decide(pam_handle_t *pamh, const char *user, const char *action,
	  const char *target, const char *host_token)
{
	char sockpath[256];
	if (tf_resolve_sock_path(pamh, user, sockpath, sizeof(sockpath)) != 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(sockpath) >= sizeof(addr.sun_path)) {
		tf_log(pamh, LOG_ERR, "trustforge: socket path too long: %s", sockpath);
		return -1;
	}
	strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		tf_log(pamh, LOG_ERR, "trustforge: socket(): %s", strerror(errno));
		return -1;
	}

	/* Make the fd non-blocking so we can enforce a 2s deadline. */
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		tf_log(pamh, LOG_ERR, "trustforge: fcntl(): %s", strerror(errno));
		close(fd);
		return -1;
	}

	long deadline = tf_now_ms() + TF_DECIDE_TIMEOUT_MS;

	int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0 && errno != EINPROGRESS) {
		tf_log(pamh, LOG_ERR, "trustforge: connect(%s): %s", sockpath, strerror(errno));
		close(fd);
		return -1;
	}
	if (rc < 0) {
		long now = tf_now_ms();
		int wait_ms = (int)(deadline - now);
		if (wait_ms <= 0 || tf_wait_writable(fd, wait_ms) != 0) {
			tf_log(pamh, LOG_ERR, "trustforge: connect timeout to %s", sockpath);
			close(fd);
			return -1;
		}
		int err = 0;
		socklen_t errlen = sizeof(err);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
			tf_log(pamh, LOG_ERR, "trustforge: connect failed: %s",
			       err ? strerror(err) : "unknown");
			close(fd);
			return -1;
		}
	}

	char req[TF_BUF_SIZE];
	int reqlen = tf_build_request(req, sizeof(req), action, target, host_token);
	if (reqlen < 0) {
		tf_log(pamh, LOG_ERR, "trustforge: failed to build request");
		close(fd);
		return -1;
	}

	size_t sent = 0;
	while (sent < (size_t)reqlen) {
		long now = tf_now_ms();
		int wait_ms = (int)(deadline - now);
		if (wait_ms <= 0) {
			tf_log(pamh, LOG_ERR, "trustforge: send timeout");
			close(fd);
			return -1;
		}
		if (tf_wait_writable(fd, wait_ms) != 0) {
			tf_log(pamh, LOG_ERR, "trustforge: send wait failed");
			close(fd);
			return -1;
		}
		ssize_t n = send(fd, req + sent, reqlen - sent, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			tf_log(pamh, LOG_ERR, "trustforge: send: %s", strerror(errno));
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
		if (wait_ms <= 0) {
			tf_log(pamh, LOG_ERR, "trustforge: recv timeout");
			close(fd);
			return -1;
		}
		if (tf_wait_readable(fd, wait_ms) != 0) {
			tf_log(pamh, LOG_ERR, "trustforge: recv wait failed");
			close(fd);
			return -1;
		}
		ssize_t n = recv(fd, resp + got, sizeof(resp) - 1 - got, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			tf_log(pamh, LOG_ERR, "trustforge: recv: %s", strerror(errno));
			close(fd);
			return -1;
		}
		if (n == 0)
			break; /* EOF — server closed connection */
		got += (size_t)n;
		if (got >= sizeof(resp) - 1)
			break;
	}
	close(fd);
	resp[got] = '\0';

	int status = 0;
	const char *body = NULL;
	if (tf_parse_http(resp, got, &status, &body) != 0) {
		tf_log(pamh, LOG_ERR, "trustforge: malformed HTTP response");
		return -1;
	}
	if (status < 200 || status >= 300) {
		tf_log(pamh, LOG_NOTICE, "trustforge: decide HTTP status %d", status);
		return 0;
	}

	char decision[32] = {0};
	if (!tf_json_find_string(body, "decision", decision, sizeof(decision))) {
		tf_log(pamh, LOG_ERR, "trustforge: response missing 'decision' field");
		return -1;
	}

	if (strcmp(decision, "allow") == 0) {
		tf_log(pamh, LOG_INFO, "trustforge: allow user=%s action=%s target=%s",
		       user, action, target);
		return 1;
	}

	tf_log(pamh, LOG_NOTICE, "trustforge: deny user=%s action=%s target=%s decision=%s",
	       user, action, target, decision);
	return 0;
}

/* ---------- common dispatch ---------- */

static int
tf_dispatch(pam_handle_t *pamh, const char *action)
{
	const char *user = NULL;
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user) {
		tf_log(pamh, LOG_ERR, "trustforge: pam_get_user failed");
		return PAM_AUTH_ERR;
	}

	const char *service = NULL;
	(void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (!service)
		service = "unknown";

	/* Best-effort: pull an existing host token from PAM if one was set. */
	const char *host_token = NULL;
	(void)pam_get_item(pamh, PAM_AUTHTOK, (const void **)&host_token);

	int verdict = tf_decide(pamh, user, action, service, host_token);
	if (verdict == 1)
		return PAM_SUCCESS;
	return PAM_AUTH_ERR;
}

/* ---------- PAM entry points ---------- */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)flags; (void)argc; (void)argv;
	return tf_dispatch(pamh, "login");
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)flags; (void)argc; (void)argv;
	return tf_dispatch(pamh, "account.access");
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)flags; (void)argc; (void)argv;
	return tf_dispatch(pamh, "session.open");
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_IGNORE;
}
