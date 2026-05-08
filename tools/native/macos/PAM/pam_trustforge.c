/*
 * pam_trustforge.c - TrustForge PAM bridge (macOS / OpenPAM)
 *
 * Status: Draft (Phase 0). Experimental — not production-ready.
 *
 * macOS-specific port of tools/native/linux/pam_trustforge/pam_trustforge.c.
 * Differences from the Linux build:
 *
 *   - Builds against OpenPAM (the BSD-derived PAM that Apple ships in
 *     /usr/include/security/), not Linux-PAM.
 *   - No `pam_modutil_*` helpers; user lookups go through getpwnam_r(3)
 *     directly. OpenPAM has `openpam_log(level, ...)` instead of
 *     `pam_vsyslog(pamh, ...)` — we use openpam_log when available and
 *     fall back to syslog otherwise.
 *   - The decision socket is system-scoped: /var/run/trustforge/decide.sock,
 *     created by the launchd job in
 *     ../com.trustforge.daemon.plist. (The Linux module now also defaults to a system socket.)
 *
 * Same fail-closed semantics as the Linux module: any error -> PAM_AUTH_ERR.
 */

#define _DARWIN_C_SOURCE 1

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_appl.h>
/* OpenPAM extensions (openpam_log, openpam_get_option, ...) live here on
 * macOS. The header is unconditionally present in /usr/include/security/. */
#include <security/openpam.h>

#define TF_DECIDE_TIMEOUT_MS  2000
#define TF_BUF_SIZE           8192
#define TF_SOCK_PATH          "/var/run/trustforge/decide.sock"
#define TF_HTTP_PATH          "/v1/decide"

/* ---------- logging helpers ---------- */

static void
tf_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void
tf_log(int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	/* OpenPAM's openpam_log() is a macro that captures __func__; we want
	 * a printf-style helper instead. Fall back to vsyslog for portability;
	 * the openpam build uses LOG_AUTHPRIV by default. */
	vsyslog(prio, fmt, ap);
	va_end(ap);
}

/* ---------- JSON helpers (minimal — same as Linux module) ---------- */

static int
tf_json_escape(char *out, size_t outsz, const char *in)
{
	size_t o = 0;
	if (outsz == 0) return -1;
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
			while (*r && isspace((unsigned char)*r)) r++;
			if (*r != ':') { p = q; continue; }
			r++;
			while (*r && isspace((unsigned char)*r)) r++;
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

/* ---------- request builder ---------- */

static int
tf_build_request(char *out, size_t outsz, const char *action, const char *target,
		 const char *host_token, const char *user)
{
	char body[2048];
	char esc_action[256];
	char esc_target[256];
	char esc_user[256];
	char esc_token[1024];

	if (tf_json_escape(esc_action, sizeof(esc_action), action ? action : "") < 0) return -1;
	if (tf_json_escape(esc_target, sizeof(esc_target), target ? target : "") < 0) return -1;
	if (tf_json_escape(esc_user,   sizeof(esc_user),   user   ? user   : "") < 0) return -1;
	if (tf_json_escape(esc_token,  sizeof(esc_token),  host_token ? host_token : "") < 0) return -1;

	int blen = snprintf(body, sizeof(body),
		"{"
		"\"actor\":null,"
		"\"host_token\":\"%s\","
		"\"host_token_kind\":\"session-cookie\","
		"\"action\":\"%s\","
		"\"target\":\"%s\","
		"\"username\":\"%s\""
		"}",
		esc_token, esc_action, esc_target, esc_user);
	if (blen < 0 || (size_t)blen >= sizeof(body)) return -1;

	int n = snprintf(out, outsz,
		"POST %s HTTP/1.1\r\n"
		"Host: localhost\r\n"
		"User-Agent: pam_trustforge-macos/0.1\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		TF_HTTP_PATH, blen, body);
	if (n < 0 || (size_t)n >= outsz) return -1;
	return n;
}

/* ---------- HTTP response parsing ---------- */

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

/* ---------- user resolution (no pam_modutil on openpam) ---------- */

/*
 * Resolve a passwd entry the way pam_modutil_getpwnam would, but using
 * getpwnam_r(3) directly. Returns 0 on success, -1 on error. *out_name is
 * filled with the canonical login name (which may differ from `user` due to
 * directory services normalisation).
 */
static int
tf_resolve_user(const char *user, char *out_name, size_t out_namesz)
{
	if (!user || !*user) return -1;
	struct passwd pwd, *pwres = NULL;
	char buf[4096];
	if (getpwnam_r(user, &pwd, buf, sizeof(buf), &pwres) != 0 || !pwres) {
		return -1;
	}
	if (snprintf(out_name, out_namesz, "%s", pwres->pw_name) < 0)
		return -1;
	return 0;
}

/* ---------- decision RPC ---------- */

/* Returns 1=allow, 0=explicit deny, -1=error (treated as deny). */
static int
tf_decide(const char *user, const char *action,
	  const char *target, const char *host_token)
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
		tf_log(LOG_ERR, "trustforge: socket path too long: %s", TF_SOCK_PATH);
		close(fd);
		return -1;
	}
	strncpy(addr.sun_path, TF_SOCK_PATH, sizeof(addr.sun_path) - 1);

	long deadline = tf_now_ms() + TF_DECIDE_TIMEOUT_MS;

	int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0 && errno != EINPROGRESS) {
		tf_log(LOG_ERR, "trustforge: connect(%s): %s",
		       TF_SOCK_PATH, strerror(errno));
		close(fd);
		return -1;
	}
	if (rc < 0) {
		long now = tf_now_ms();
		int wait_ms = (int)(deadline - now);
		if (wait_ms <= 0 || tf_wait(fd, POLLOUT, wait_ms) != 0) {
			tf_log(LOG_ERR, "trustforge: connect timeout to %s", TF_SOCK_PATH);
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
	int reqlen = tf_build_request(req, sizeof(req), action, target, host_token, user);
	if (reqlen < 0) {
		tf_log(LOG_ERR, "trustforge: failed to build request");
		close(fd);
		return -1;
	}

	size_t sent = 0;
	while (sent < (size_t)reqlen) {
		long now = tf_now_ms();
		int wait_ms = (int)(deadline - now);
		if (wait_ms <= 0) { tf_log(LOG_ERR, "trustforge: send timeout"); close(fd); return -1; }
		if (tf_wait(fd, POLLOUT, wait_ms) != 0) { tf_log(LOG_ERR, "trustforge: send wait failed"); close(fd); return -1; }
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
		if (wait_ms <= 0) { tf_log(LOG_ERR, "trustforge: recv timeout"); close(fd); return -1; }
		if (tf_wait(fd, POLLIN, wait_ms) != 0) { tf_log(LOG_ERR, "trustforge: recv wait failed"); close(fd); return -1; }
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
		tf_log(LOG_INFO, "trustforge: allow user=%s action=%s target=%s",
		       user ? user : "?", action, target);
		return 1;
	}
	tf_log(LOG_NOTICE, "trustforge: deny user=%s action=%s target=%s decision=%s",
	       user ? user : "?", action, target, decision);
	return 0;
}

/* ---------- common dispatch ---------- */

static int
tf_dispatch(pam_handle_t *pamh, const char *action)
{
	const char *user = NULL;
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user) {
		tf_log(LOG_ERR, "trustforge: pam_get_user failed");
		return PAM_AUTH_ERR;
	}

	/* On macOS pam_get_item(PAM_SERVICE) returns the calling service name
	 * (sshd, login, sudo, screensaver, ...). */
	const char *service = NULL;
	(void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (!service) service = "unknown";

	/* Best-effort: forward an existing host token (e.g. PAM_AUTHTOK from a
	 * preceding stack entry like pam_unix). May be NULL — daemon decides
	 * what to do with that. */
	const char *host_token = NULL;
	(void)pam_get_item(pamh, PAM_AUTHTOK, (const void **)&host_token);

	/* Validate the username via getpwnam_r so we don't forward something
	 * Directory Services would reject. Failure is non-fatal (we still ask
	 * the daemon, just with the unresolved string), but we log. */
	char canon[256];
	if (tf_resolve_user(user, canon, sizeof(canon)) == 0) {
		user = canon;
	} else {
		tf_log(LOG_NOTICE, "trustforge: getpwnam_r('%s') failed: %s",
		       user, strerror(errno));
	}

	int verdict = tf_decide(user, action, service, host_token);
	if (verdict == 1) return PAM_SUCCESS;
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
