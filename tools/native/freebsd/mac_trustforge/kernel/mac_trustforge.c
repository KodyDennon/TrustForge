/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * mac_trustforge.c - TrustForge FreeBSD MAC policy module.
 *
 * Phase M reference module. Hooks a small set of FreeBSD MAC events
 * (vnode_check_open, vnode_check_exec, socket_check_connect,
 * proc_check_signal), forwards a compact event description to a
 * userspace daemon over a character device (/dev/mac_trustforge),
 * and waits a bounded time for an allow / deny verdict.
 *
 * Event/verdict transport uses the cdev pattern:
 *   - Userspace opens /dev/mac_trustforge and reads `struct tf_event`
 *     records (one per request); the read blocks until an event is
 *     available or the device is closed.
 *   - Userspace writes back a `struct tf_verdict` carrying the matching
 *     cookie and a result code (0 = allow, EACCES etc. = deny).
 *
 * If the daemon does not respond within the configured timeout
 * (default 100ms) the hook FAILS OPEN — the kernel does not block the
 * operation and an error is logged. This matches the TrustForge
 * "availability over correctness for unanchored events" rule. Set the
 * sysctl `security.mac.trustforge.fail_open=0` for strict deployments.
 *
 * NOTE: Status: experimental. Not production-ready. No custom
 * cryptography is performed in-kernel; verdicts are the responsibility
 * of userspace.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/file.h>
#include <sys/imgact.h>
#include <sys/sx.h>
#include <sys/atomic.h>
#include <sys/refcount.h>

#include <netinet/in.h>

#include <security/mac/mac_policy.h>

#define	TF_MAC_NAME		"mac_trustforge"
#define	TF_MAC_FULLNAME		"TrustForge MAC policy bridge"
#define	TF_MAX_PATH		512
#define	TF_DEFAULT_TIMEOUT_MS	100

/* ---- Wire format ---------------------------------------------------- */

#define	TF_EV_VNODE_OPEN	1
#define	TF_EV_VNODE_EXEC	2
#define	TF_EV_SOCKET_CONNECT	3
#define	TF_EV_PROC_SIGNAL	4

#define	TF_EVENT_MAGIC		0x54464556u	/* 'TFEV' */
#define	TF_VERDICT_MAGIC	0x54465644u	/* 'TFVD' */

struct tf_event {
	uint32_t	magic;
	uint32_t	version;
	uint64_t	cookie;
	uint32_t	kind;
	uint32_t	pid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	mask;
	uint32_t	target_pid;	/* used by signal */
	uint32_t	target_sig;	/* signal number */
	uint32_t	path_len;
	char		path[TF_MAX_PATH];
} __packed;

struct tf_verdict {
	uint32_t	magic;
	uint32_t	version;
	uint64_t	cookie;
	int32_t		result;
	uint32_t	reserved;
} __packed;

/* ---- Per-pending request state ------------------------------------- */

struct tf_pending {
	TAILQ_ENTRY(tf_pending)	link;	/* on tf_pending_q (waiting to be read) */
	LIST_ENTRY(tf_pending)	hlink;	/* on tf_inflight (awaiting verdict) */
	uint64_t		cookie;
	int			result;
	bool			answered;
	bool			delivered;
	struct tf_event		ev;
	struct mtx		mtx;
	struct cv		cv;
};

static MALLOC_DEFINE(M_TF_MAC, "tf_mac", "TrustForge MAC policy");

static TAILQ_HEAD(, tf_pending) tf_pending_q =
    TAILQ_HEAD_INITIALIZER(tf_pending_q);
static LIST_HEAD(, tf_pending) tf_inflight =
    LIST_HEAD_INITIALIZER(tf_inflight);
static struct mtx tf_q_mtx;
static struct cv tf_readers_cv;
static volatile uint64_t tf_cookie_ctr = 1;

/* ---- Sysctl knobs --------------------------------------------------- */

static int tf_enabled = 1;
static int tf_fail_open = 1;
static int tf_timeout_ms = TF_DEFAULT_TIMEOUT_MS;
static int tf_have_reader = 0;	/* 1 if /dev/mac_trustforge is open */

SYSCTL_NODE(_security_mac, OID_AUTO, trustforge,
    CTLFLAG_RW, 0, "TrustForge MAC policy");
SYSCTL_INT(_security_mac_trustforge, OID_AUTO, enabled,
    CTLFLAG_RW, &tf_enabled, 0, "Enable TrustForge MAC enforcement");
SYSCTL_INT(_security_mac_trustforge, OID_AUTO, fail_open,
    CTLFLAG_RW, &tf_fail_open, 0,
    "If 1, allow when daemon is absent / times out");
SYSCTL_INT(_security_mac_trustforge, OID_AUTO, timeout_ms,
    CTLFLAG_RW, &tf_timeout_ms, 0, "Userspace decision timeout (ms)");
SYSCTL_INT(_security_mac_trustforge, OID_AUTO, have_reader,
    CTLFLAG_RD, &tf_have_reader, 0,
    "Non-zero when bridge daemon is connected to /dev/mac_trustforge");

/* ---- /dev/mac_trustforge cdev -------------------------------------- */

static struct cdev *tf_dev;
static struct sx tf_dev_sx;

static d_open_t  tf_dev_open;
static d_close_t tf_dev_close;
static d_read_t  tf_dev_read;
static d_write_t tf_dev_write;

static struct cdevsw tf_cdevsw = {
	.d_version = D_VERSION,
	.d_open    = tf_dev_open,
	.d_close   = tf_dev_close,
	.d_read    = tf_dev_read,
	.d_write   = tf_dev_write,
	.d_name    = TF_MAC_NAME,
};

static int
tf_dev_open(struct cdev *dev __unused, int oflags __unused, int devtype __unused,
    struct thread *td __unused)
{

	sx_xlock(&tf_dev_sx);
	if (tf_have_reader) {
		sx_xunlock(&tf_dev_sx);
		return (EBUSY);
	}
	tf_have_reader = 1;
	sx_xunlock(&tf_dev_sx);
	return (0);
}

static int
tf_dev_close(struct cdev *dev __unused, int fflag __unused, int devtype __unused,
    struct thread *td __unused)
{
	struct tf_pending *p, *t;

	sx_xlock(&tf_dev_sx);
	tf_have_reader = 0;
	sx_xunlock(&tf_dev_sx);

	/* Wake everyone — they will fail open per policy. */
	mtx_lock(&tf_q_mtx);
	LIST_FOREACH_SAFE(p, &tf_inflight, hlink, t) {
		mtx_lock(&p->mtx);
		if (!p->answered) {
			p->answered = true;
			p->result = tf_fail_open ? 0 : EACCES;
			cv_signal(&p->cv);
		}
		mtx_unlock(&p->mtx);
	}
	mtx_unlock(&tf_q_mtx);
	return (0);
}

static int
tf_dev_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct tf_pending *p;
	int error;

	if (uio->uio_resid < (off_t)sizeof(struct tf_event))
		return (EINVAL);

	mtx_lock(&tf_q_mtx);
	while (TAILQ_EMPTY(&tf_pending_q)) {
		if (ioflag & IO_NDELAY) {
			mtx_unlock(&tf_q_mtx);
			return (EAGAIN);
		}
		error = cv_wait_sig(&tf_readers_cv, &tf_q_mtx);
		if (error) {
			mtx_unlock(&tf_q_mtx);
			return (error);
		}
	}
	p = TAILQ_FIRST(&tf_pending_q);
	TAILQ_REMOVE(&tf_pending_q, p, link);
	p->delivered = true;
	mtx_unlock(&tf_q_mtx);

	error = uiomove(&p->ev, sizeof(p->ev), uio);
	return (error);
}

static int
tf_dev_write(struct cdev *dev __unused, struct uio *uio, int ioflag __unused)
{
	struct tf_verdict vd;
	struct tf_pending *p;
	int error;

	if (uio->uio_resid != (off_t)sizeof(vd))
		return (EINVAL);
	error = uiomove(&vd, sizeof(vd), uio);
	if (error)
		return (error);
	if (vd.magic != TF_VERDICT_MAGIC)
		return (EINVAL);

	mtx_lock(&tf_q_mtx);
	LIST_FOREACH(p, &tf_inflight, hlink) {
		if (p->cookie == vd.cookie) {
			mtx_lock(&p->mtx);
			p->result = vd.result;
			p->answered = true;
			cv_signal(&p->cv);
			mtx_unlock(&p->mtx);
			break;
		}
	}
	mtx_unlock(&tf_q_mtx);
	return (0);
}

/* ---- Decision dispatch --------------------------------------------- */

static uint64_t
tf_next_cookie(void)
{

	return (atomic_fetchadd_64(&tf_cookie_ctr, 1));
}

static int
tf_decide(struct tf_event *ev)
{
	struct tf_pending *p;
	int rc, ticks_to_wait;

	if (!tf_enabled)
		return (0);
	if (!tf_have_reader)
		return (tf_fail_open ? 0 : EACCES);

	p = malloc(sizeof(*p), M_TF_MAC, M_WAITOK | M_ZERO);
	mtx_init(&p->mtx, "tf_pending", NULL, MTX_DEF);
	cv_init(&p->cv, "tf_pending");
	p->cookie = tf_next_cookie();
	ev->magic = TF_EVENT_MAGIC;
	ev->version = 1;
	ev->cookie = p->cookie;
	memcpy(&p->ev, ev, sizeof(*ev));

	mtx_lock(&tf_q_mtx);
	TAILQ_INSERT_TAIL(&tf_pending_q, p, link);
	LIST_INSERT_HEAD(&tf_inflight, p, hlink);
	cv_signal(&tf_readers_cv);
	mtx_unlock(&tf_q_mtx);

	ticks_to_wait = (tf_timeout_ms * hz + 999) / 1000;
	if (ticks_to_wait < 1)
		ticks_to_wait = 1;

	mtx_lock(&p->mtx);
	if (!p->answered) {
		(void)cv_timedwait_sig(&p->cv, &p->mtx, ticks_to_wait);
	}
	rc = p->answered ? p->result : (tf_fail_open ? 0 : EACCES);
	mtx_unlock(&p->mtx);

	mtx_lock(&tf_q_mtx);
	if (!p->delivered)
		TAILQ_REMOVE(&tf_pending_q, p, link);
	LIST_REMOVE(p, hlink);
	mtx_unlock(&tf_q_mtx);

	cv_destroy(&p->cv);
	mtx_destroy(&p->mtx);
	free(p, M_TF_MAC);
	return (rc);
}

/* ---- Path / cred fill helpers -------------------------------------- */

static void
tf_fill_creds(struct tf_event *ev, struct ucred *cred)
{

	ev->pid = curproc != NULL ? curproc->p_pid : 0;
	if (cred != NULL) {
		ev->uid = cred->cr_uid;
		ev->gid = cred->cr_gid;
	}
}

static void
tf_fill_vnode_path(struct tf_event *ev, struct vnode *vp)
{
	char *fullpath = NULL, *freebuf = NULL;

	if (vp == NULL)
		return;
	/* vn_fullpath is best-effort; failure is non-fatal. */
	if (vn_fullpath(vp, &fullpath, &freebuf) == 0 && fullpath != NULL) {
		size_t n = strlen(fullpath);
		if (n >= TF_MAX_PATH)
			n = TF_MAX_PATH - 1;
		memcpy(ev->path, fullpath, n);
		ev->path[n] = '\0';
		ev->path_len = n;
	}
	if (freebuf != NULL)
		free(freebuf, M_TEMP);
}

/* ---- MAC policy hooks ---------------------------------------------- */

static void
tf_init(struct mac_policy_conf *conf __unused)
{

	mtx_init(&tf_q_mtx, "tf_q", NULL, MTX_DEF);
	cv_init(&tf_readers_cv, "tf_readers");
	sx_init(&tf_dev_sx, "tf_dev_sx");

	tf_dev = make_dev(&tf_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600,
	    "mac_trustforge");
	if (tf_dev == NULL) {
		printf("%s: failed to create cdev\n", TF_MAC_NAME);
		return;
	}
	printf("%s: initialized (timeout=%dms fail_open=%d)\n",
	    TF_MAC_NAME, tf_timeout_ms, tf_fail_open);
}

static void
tf_destroy(struct mac_policy_conf *conf __unused)
{
	struct tf_pending *p, *t;

	if (tf_dev != NULL) {
		destroy_dev(tf_dev);
		tf_dev = NULL;
	}
	/* Drain any in-flight requests, fail-open them. */
	mtx_lock(&tf_q_mtx);
	LIST_FOREACH_SAFE(p, &tf_inflight, hlink, t) {
		mtx_lock(&p->mtx);
		if (!p->answered) {
			p->answered = true;
			p->result = 0;
			cv_signal(&p->cv);
		}
		mtx_unlock(&p->mtx);
	}
	mtx_unlock(&tf_q_mtx);

	sx_destroy(&tf_dev_sx);
	cv_destroy(&tf_readers_cv);
	mtx_destroy(&tf_q_mtx);
	printf("%s: destroyed\n", TF_MAC_NAME);
}

static int
tf_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, accmode_t accmode)
{
	struct tf_event ev;

	if (!tf_enabled)
		return (0);
	memset(&ev, 0, sizeof(ev));
	ev.kind = TF_EV_VNODE_OPEN;
	ev.mask = (uint32_t)accmode;
	tf_fill_creds(&ev, cred);
	tf_fill_vnode_path(&ev, vp);
	return (tf_decide(&ev));
}

static int
tf_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, struct image_params *imgp __unused,
    struct label *execlabel __unused)
{
	struct tf_event ev;

	if (!tf_enabled)
		return (0);
	memset(&ev, 0, sizeof(ev));
	ev.kind = TF_EV_VNODE_EXEC;
	tf_fill_creds(&ev, cred);
	tf_fill_vnode_path(&ev, vp);
	return (tf_decide(&ev));
}

static int
tf_socket_check_connect(struct ucred *cred, struct socket *so __unused,
    struct label *solabel __unused, struct sockaddr *sa)
{
	struct tf_event ev;

	if (!tf_enabled || sa == NULL)
		return (0);
	memset(&ev, 0, sizeof(ev));
	ev.kind = TF_EV_SOCKET_CONNECT;
	tf_fill_creds(&ev, cred);
	ev.mask = (uint32_t)sa->sa_family;

	if (sa->sa_family == AF_INET && sa->sa_len >=
	    (uint8_t)sizeof(struct sockaddr_in)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		uint8_t *o = (uint8_t *)&sin->sin_addr.s_addr;
		snprintf(ev.path, TF_MAX_PATH, "ip4:%u.%u.%u.%u:%u",
		    o[0], o[1], o[2], o[3], ntohs(sin->sin_port));
		ev.path_len = strlen(ev.path);
	} else if (sa->sa_family == AF_INET6 && sa->sa_len >=
	    (uint8_t)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		snprintf(ev.path, TF_MAX_PATH, "ip6:port=%u",
		    ntohs(sin6->sin6_port));
		ev.path_len = strlen(ev.path);
	}
	return (tf_decide(&ev));
}

static int
tf_proc_check_signal(struct ucred *cred, struct proc *target, int signum)
{
	struct tf_event ev;

	if (!tf_enabled)
		return (0);
	memset(&ev, 0, sizeof(ev));
	ev.kind = TF_EV_PROC_SIGNAL;
	tf_fill_creds(&ev, cred);
	ev.target_pid = target != NULL ? target->p_pid : 0;
	ev.target_sig = (uint32_t)signum;
	return (tf_decide(&ev));
}

/* ---- Policy registration ------------------------------------------- */

static struct mac_policy_ops tf_ops = {
	.mpo_init			= tf_init,
	.mpo_destroy			= tf_destroy,
	.mpo_vnode_check_open		= tf_vnode_check_open,
	.mpo_vnode_check_exec		= tf_vnode_check_exec,
	.mpo_socket_check_connect	= tf_socket_check_connect,
	.mpo_proc_check_signal		= tf_proc_check_signal,
};

MAC_POLICY_SET(&tf_ops, mac_trustforge, TF_MAC_FULLNAME,
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
