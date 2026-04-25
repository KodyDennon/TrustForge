/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tf-lsm-bridge.c
 *
 * Userspace companion for the TrustForge LSM kernel module.
 *
 * Listens on NETLINK_USERSOCK (multicast group 29), forwards events
 * to the local TrustForge daemon over a Unix domain socket
 * (/run/trustforge/decide.sock by default), reads back an allow/deny
 * verdict, and unicasts the verdict back to the kernel.
 *
 * Wire format mirrors trustforge_lsm.c:
 *   struct tf_event   { magic='TFEV', version=1, cookie, kind, pid,
 *                       uid, gid, mask, path_len, path[512] };
 *   struct tf_verdict { magic='TFVD', version=1, cookie, result, _ };
 *
 * The userspace -> daemon protocol over the Unix socket is a single
 * line of JSON per request, terminated by '\n'. The daemon answers
 * with one line of JSON containing {"result": 0} or {"result": -13}.
 *
 * Build:   cc -O2 -Wall -o tf-lsm-bridge tf-lsm-bridge.c
 * Run:     sudo ./tf-lsm-bridge --daemon /run/trustforge/decide.sock
 *
 * This program does NOT perform any cryptography. It is a transport
 * shim only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>

#define TF_NL_GROUP            29
#define TF_MAX_PATH            512
#define TF_DEFAULT_DAEMON_SOCK "/run/trustforge/decide.sock"

#define TF_EV_INODE_PERMISSION 1
#define TF_EV_FILE_PERMISSION  2
#define TF_EV_SOCKET_CREATE    3
#define TF_EV_SOCKET_CONNECT   4
#define TF_EV_BPRM_SET_CREDS   5

#define TF_EVENT_MAGIC   0x54464556u   /* 'TFEV' */
#define TF_VERDICT_MAGIC 0x54465644u   /* 'TFVD' */

#pragma pack(push, 1)
struct tf_event {
	uint32_t magic;
	uint32_t version;
	uint64_t cookie;
	uint32_t kind;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	uint32_t mask;
	uint32_t path_len;
	char     path[TF_MAX_PATH];
};

struct tf_verdict {
	uint32_t magic;
	uint32_t version;
	uint64_t cookie;
	int32_t  result;
	uint32_t reserved;
};
#pragma pack(pop)

static volatile sig_atomic_t g_stop = 0;
static int g_verbose = 0;

static void on_signal(int s) { (void)s; g_stop = 1; }

static void logmsg(int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (g_verbose) {
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	} else {
		vsyslog(prio, fmt, ap);
	}
	va_end(ap);
}

static const char *kind_name(uint32_t k)
{
	switch (k) {
	case TF_EV_INODE_PERMISSION: return "inode_permission";
	case TF_EV_FILE_PERMISSION:  return "file_permission";
	case TF_EV_SOCKET_CREATE:    return "socket_create";
	case TF_EV_SOCKET_CONNECT:   return "socket_connect";
	case TF_EV_BPRM_SET_CREDS:   return "bprm_set_creds";
	default:                     return "unknown";
	}
}

static int connect_daemon(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/*
 * Forward an event to the daemon and parse a one-line JSON response.
 * On any error, fall through to allow (fail-open). The kernel module
 * also fails open on timeout, so this matches the documented policy.
 */
static int decide(const char *daemon_path, const struct tf_event *ev)
{
	int fd = connect_daemon(daemon_path);
	if (fd < 0) {
		logmsg(LOG_WARNING, "tf-lsm-bridge: daemon connect failed: %s",
		       strerror(errno));
		return 0;
	}

	char buf[1024];
	int n = snprintf(buf, sizeof(buf),
		"{\"v\":1,\"cookie\":%llu,\"kind\":\"%s\",\"pid\":%u,"
		"\"uid\":%u,\"gid\":%u,\"mask\":%u,\"path\":\"%.*s\"}\n",
		(unsigned long long)ev->cookie,
		kind_name(ev->kind), ev->pid, ev->uid, ev->gid, ev->mask,
		(int)(ev->path_len < TF_MAX_PATH ? ev->path_len : TF_MAX_PATH - 1),
		ev->path);
	if (n <= 0 || (size_t)n >= sizeof(buf)) {
		close(fd);
		return 0;
	}

	if (write(fd, buf, (size_t)n) != n) {
		close(fd);
		return 0;
	}

	char rbuf[256];
	ssize_t got = read(fd, rbuf, sizeof(rbuf) - 1);
	close(fd);
	if (got <= 0) return 0;
	rbuf[got] = '\0';

	const char *p = strstr(rbuf, "\"result\"");
	if (!p) return 0;
	p = strchr(p, ':');
	if (!p) return 0;
	return (int)strtol(p + 1, NULL, 10);
}

static int send_verdict(int nl_fd, uint64_t cookie, int result)
{
	struct {
		struct nlmsghdr h;
		struct tf_verdict v;
	} msg = {0};

	msg.h.nlmsg_len = NLMSG_LENGTH(sizeof(msg.v));
	msg.h.nlmsg_type = NLMSG_DONE;
	msg.h.nlmsg_flags = 0;
	msg.h.nlmsg_seq = 0;
	msg.h.nlmsg_pid = (uint32_t)getpid();
	msg.v.magic = TF_VERDICT_MAGIC;
	msg.v.version = 1;
	msg.v.cookie = cookie;
	msg.v.result = result;

	struct sockaddr_nl dest = {0};
	dest.nl_family = AF_NETLINK;
	dest.nl_pid = 0;       /* kernel */
	dest.nl_groups = 1u << (TF_NL_GROUP - 1);

	struct iovec iov = { .iov_base = &msg, .iov_len = msg.h.nlmsg_len };
	struct msghdr mh = {
		.msg_name = &dest, .msg_namelen = sizeof(dest),
		.msg_iov = &iov, .msg_iovlen = 1,
	};
	if (sendmsg(nl_fd, &mh, 0) < 0) {
		logmsg(LOG_WARNING, "tf-lsm-bridge: sendmsg verdict failed: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: %s [-d|--daemon SOCK] [-v]\n"
		"  -d, --daemon SOCK   Unix socket of the TF policy daemon\n"
		"                      (default %s)\n"
		"  -v                  verbose (log to stderr instead of syslog)\n",
		p, TF_DEFAULT_DAEMON_SOCK);
}

int main(int argc, char **argv)
{
	const char *daemon_sock = TF_DEFAULT_DAEMON_SOCK;
	static const struct option opts[] = {
		{ "daemon",  required_argument, NULL, 'd' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 },
	};
	int o;
	while ((o = getopt_long(argc, argv, "d:vh", opts, NULL)) != -1) {
		switch (o) {
		case 'd': daemon_sock = optarg; break;
		case 'v': g_verbose = 1; break;
		case 'h': default: usage(argv[0]); return o == 'h' ? 0 : 1;
		}
	}

	if (!g_verbose)
		openlog("tf-lsm-bridge", LOG_PID, LOG_DAEMON);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	if (nl < 0) {
		logmsg(LOG_ERR, "tf-lsm-bridge: netlink socket: %s",
		       strerror(errno));
		return 1;
	}
	struct sockaddr_nl src = {0};
	src.nl_family = AF_NETLINK;
	src.nl_pid = (uint32_t)getpid();
	src.nl_groups = 1u << (TF_NL_GROUP - 1);
	if (bind(nl, (struct sockaddr *)&src, sizeof(src)) < 0) {
		logmsg(LOG_ERR, "tf-lsm-bridge: netlink bind: %s",
		       strerror(errno));
		close(nl);
		return 1;
	}

	logmsg(LOG_INFO, "tf-lsm-bridge: started, daemon=%s", daemon_sock);

	while (!g_stop) {
		char rbuf[NLMSG_LENGTH(sizeof(struct tf_event)) + 16];
		ssize_t got = recv(nl, rbuf, sizeof(rbuf), 0);
		if (got < 0) {
			if (errno == EINTR) continue;
			logmsg(LOG_WARNING, "tf-lsm-bridge: recv: %s",
			       strerror(errno));
			continue;
		}
		struct nlmsghdr *nh = (struct nlmsghdr *)rbuf;
		if (!NLMSG_OK(nh, (size_t)got)) continue;
		if ((size_t)nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct tf_event)))
			continue;

		struct tf_event *ev = (struct tf_event *)NLMSG_DATA(nh);
		if (ev->magic != TF_EVENT_MAGIC) continue;

		int verdict = decide(daemon_sock, ev);
		send_verdict(nl, ev->cookie, verdict);
	}

	close(nl);
	logmsg(LOG_INFO, "tf-lsm-bridge: stopped");
	if (!g_verbose) closelog();
	return 0;
}
