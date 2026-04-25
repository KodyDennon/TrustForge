// SPDX-License-Identifier: GPL-2.0
/*
 * trustforge_lsm.c - TrustForge Linux Security Module
 *
 * Phase M1 reference module. Hooks a small set of LSM events
 * (inode_permission, file_permission, socket_create, socket_connect,
 * bprm_set_creds), forwards a compact event description to a userspace
 * daemon over NETLINK_USERSOCK, and waits a bounded time for an
 * allow/deny verdict. If the daemon does not respond within the
 * configured timeout (default 100ms) the hook FAILS OPEN — the kernel
 * does not block the operation and an error is logged.
 *
 * Compatible with Linux >= 5.15. Uses the LSM stacking interface
 * (security_add_hooks) introduced in 5.7.
 *
 * NOTE: This is a reference / experimental module. It must be reviewed
 * and hardened before any production use. No custom cryptography is
 * performed here; verdicts are the responsibility of userspace.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/printk.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/netlink.h>

#define TF_LSM_NAME      "trustforge"
#define TF_NL_GROUP      29     /* NETLINK_USERSOCK multicast group */
#define TF_DEFAULT_TIMEOUT_MS  100
#define TF_MAX_PATH      512
#define TF_HASH_BITS     8

/* ---- Module parameters --------------------------------------------------- */

static unsigned int tf_timeout_ms = TF_DEFAULT_TIMEOUT_MS;
module_param_named(timeout_ms, tf_timeout_ms, uint, 0644);
MODULE_PARM_DESC(timeout_ms,
		 "Userspace decision timeout in milliseconds (default 100)");

static bool tf_enabled = true;
module_param_named(enabled, tf_enabled, bool, 0644);
MODULE_PARM_DESC(enabled,
		 "Globally enable/disable enforcement (fail-open when false)");

static bool tf_fail_open = true;
module_param_named(fail_open, tf_fail_open, bool, 0644);
MODULE_PARM_DESC(fail_open,
		 "On userspace timeout, allow (true) or deny (false). Default true.");

/* ---- Event / verdict wire format ----------------------------------------- */

enum tf_event_kind {
	TF_EV_INODE_PERMISSION = 1,
	TF_EV_FILE_PERMISSION  = 2,
	TF_EV_SOCKET_CREATE    = 3,
	TF_EV_SOCKET_CONNECT   = 4,
	TF_EV_BPRM_SET_CREDS   = 5,
};

struct tf_event {
	__u32 magic;        /* 'TFEV' */
	__u32 version;      /* 1 */
	__u64 cookie;       /* matched in verdict */
	__u32 kind;         /* enum tf_event_kind */
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u32 mask;         /* MAY_READ etc., or family/type/protocol */
	__u32 path_len;
	char  path[TF_MAX_PATH];
} __packed;

#define TF_EVENT_MAGIC  0x54464556u   /* 'TFEV' */

struct tf_verdict {
	__u32 magic;        /* 'TFVD' */
	__u32 version;
	__u64 cookie;
	__s32 result;       /* 0 = allow, -EACCES etc. = deny */
	__u32 reserved;
} __packed;

#define TF_VERDICT_MAGIC 0x54465644u  /* 'TFVD' */

/* ---- Pending decision table --------------------------------------------- */

struct tf_pending {
	struct hlist_node node;
	u64 cookie;
	int result;
	bool answered;
	wait_queue_head_t wq;
};

static DEFINE_HASHTABLE(tf_pending_tbl, TF_HASH_BITS);
static DEFINE_SPINLOCK(tf_pending_lock);
static atomic64_t tf_cookie_ctr = ATOMIC64_INIT(1);

static struct sock *tf_nl_sock;

static u64 tf_next_cookie(void)
{
	return (u64)atomic64_inc_return(&tf_cookie_ctr);
}

static void tf_pending_insert(struct tf_pending *p)
{
	unsigned long flags;
	spin_lock_irqsave(&tf_pending_lock, flags);
	hash_add(tf_pending_tbl, &p->node, p->cookie);
	spin_unlock_irqrestore(&tf_pending_lock, flags);
}

static void tf_pending_remove(struct tf_pending *p)
{
	unsigned long flags;
	spin_lock_irqsave(&tf_pending_lock, flags);
	hash_del(&p->node);
	spin_unlock_irqrestore(&tf_pending_lock, flags);
}

static struct tf_pending *tf_pending_find(u64 cookie)
{
	struct tf_pending *p;
	unsigned long flags;

	spin_lock_irqsave(&tf_pending_lock, flags);
	hash_for_each_possible(tf_pending_tbl, p, node, cookie) {
		if (p->cookie == cookie) {
			spin_unlock_irqrestore(&tf_pending_lock, flags);
			return p;
		}
	}
	spin_unlock_irqrestore(&tf_pending_lock, flags);
	return NULL;
}

/* ---- Netlink send / receive --------------------------------------------- */

static int tf_send_event(const struct tf_event *ev)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	size_t payload_len = sizeof(*ev);

	if (!tf_nl_sock)
		return -ENODEV;

	skb = nlmsg_new(payload_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, payload_len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}
	memcpy(nlmsg_data(nlh), ev, payload_len);
	NETLINK_CB(skb).dst_group = TF_NL_GROUP;

	return netlink_broadcast(tf_nl_sock, skb, 0, TF_NL_GROUP, GFP_ATOMIC);
}

static void tf_nl_recv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct tf_verdict *vd;
	struct tf_pending *p;
	unsigned long flags;

	nlh = nlmsg_hdr(skb);
	if (skb->len < NLMSG_HDRLEN)
		return;
	if (nlmsg_len(nlh) < (int)sizeof(*vd))
		return;

	vd = nlmsg_data(nlh);
	if (vd->magic != TF_VERDICT_MAGIC)
		return;

	spin_lock_irqsave(&tf_pending_lock, flags);
	hash_for_each_possible(tf_pending_tbl, p, node, vd->cookie) {
		if (p->cookie == vd->cookie) {
			p->result = vd->result;
			p->answered = true;
			wake_up_interruptible(&p->wq);
			break;
		}
	}
	spin_unlock_irqrestore(&tf_pending_lock, flags);
}

/* ---- Decision dispatch -------------------------------------------------- */

static int tf_decide(struct tf_event *ev)
{
	struct tf_pending *p;
	long remaining;
	int result;

	if (!tf_enabled)
		return 0;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return tf_fail_open ? 0 : -ENOMEM;

	p->cookie = tf_next_cookie();
	init_waitqueue_head(&p->wq);
	ev->cookie = p->cookie;
	ev->magic = TF_EVENT_MAGIC;
	ev->version = 1;
	tf_pending_insert(p);

	if (tf_send_event(ev) < 0) {
		tf_pending_remove(p);
		result = tf_fail_open ? 0 : -EACCES;
		kfree(p);
		return result;
	}

	remaining = wait_event_interruptible_timeout(
		p->wq, p->answered,
		msecs_to_jiffies(tf_timeout_ms));

	tf_pending_remove(p);
	if (remaining > 0 && p->answered)
		result = p->result;
	else
		result = tf_fail_open ? 0 : -EACCES;

	kfree(p);
	return result;
}

/* ---- Path helpers ------------------------------------------------------- */

static void tf_fill_path_from_dentry(struct tf_event *ev, struct dentry *dentry)
{
	char buf[TF_MAX_PATH];
	char *p;
	struct path path = { .dentry = dentry, .mnt = NULL };

	if (!dentry) {
		ev->path[0] = '\0';
		ev->path_len = 0;
		return;
	}
	p = dentry_path_raw(dentry, buf, sizeof(buf));
	if (IS_ERR(p)) {
		ev->path[0] = '\0';
		ev->path_len = 0;
		return;
	}
	strncpy(ev->path, p, TF_MAX_PATH - 1);
	ev->path[TF_MAX_PATH - 1] = '\0';
	ev->path_len = strnlen(ev->path, TF_MAX_PATH);
	(void)path;
}

static void tf_fill_creds(struct tf_event *ev)
{
	const struct cred *c = current_cred();
	ev->pid = task_tgid_nr(current);
	ev->uid = from_kuid(&init_user_ns, c->uid);
	ev->gid = from_kgid(&init_user_ns, c->gid);
}

/* ---- LSM hooks ---------------------------------------------------------- */

static int tf_inode_permission(struct inode *inode, int mask)
{
	struct tf_event ev = {0};
	struct dentry *d;

	if (!inode)
		return 0;
	ev.kind = TF_EV_INODE_PERMISSION;
	ev.mask = (u32)mask;
	tf_fill_creds(&ev);
	d = d_find_alias(inode);
	if (d) {
		tf_fill_path_from_dentry(&ev, d);
		dput(d);
	}
	return tf_decide(&ev);
}

static int tf_file_permission(struct file *file, int mask)
{
	struct tf_event ev = {0};

	if (!file)
		return 0;
	ev.kind = TF_EV_FILE_PERMISSION;
	ev.mask = (u32)mask;
	tf_fill_creds(&ev);
	tf_fill_path_from_dentry(&ev, file->f_path.dentry);
	return tf_decide(&ev);
}

static int tf_socket_create(int family, int type, int protocol, int kern)
{
	struct tf_event ev = {0};

	if (kern)
		return 0;
	ev.kind = TF_EV_SOCKET_CREATE;
	ev.mask = ((u32)(family & 0xffff) << 16) |
		  ((u32)(type & 0xff) << 8) |
		  (u32)(protocol & 0xff);
	tf_fill_creds(&ev);
	return tf_decide(&ev);
}

static int tf_socket_connect(struct socket *sock, struct sockaddr *address,
			     int addrlen)
{
	struct tf_event ev = {0};

	if (!address)
		return 0;
	ev.kind = TF_EV_SOCKET_CONNECT;
	ev.mask = (u32)address->sa_family;
	tf_fill_creds(&ev);

	if (address->sa_family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)address;
		snprintf(ev.path, TF_MAX_PATH, "ip4:%pI4:%u",
			 &sin->sin_addr, ntohs(sin->sin_port));
		ev.path_len = strnlen(ev.path, TF_MAX_PATH);
	} else if (address->sa_family == AF_INET6 &&
		   addrlen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		snprintf(ev.path, TF_MAX_PATH, "ip6:%pI6c:%u",
			 &sin6->sin6_addr, ntohs(sin6->sin6_port));
		ev.path_len = strnlen(ev.path, TF_MAX_PATH);
	}
	return tf_decide(&ev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static int tf_bprm_set_creds(struct linux_binprm *bprm)
#else
static int tf_bprm_set_creds(struct linux_binprm *bprm)
#endif
{
	struct tf_event ev = {0};

	if (!bprm || !bprm->file)
		return 0;
	ev.kind = TF_EV_BPRM_SET_CREDS;
	ev.mask = 0;
	tf_fill_creds(&ev);
	tf_fill_path_from_dentry(&ev, bprm->file->f_path.dentry);
	return tf_decide(&ev);
}

/* ---- Hook table & init/exit -------------------------------------------- */

static struct security_hook_list tf_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_permission, tf_inode_permission),
	LSM_HOOK_INIT(file_permission,  tf_file_permission),
	LSM_HOOK_INIT(socket_create,    tf_socket_create),
	LSM_HOOK_INIT(socket_connect,   tf_socket_connect),
	LSM_HOOK_INIT(bprm_set_creds,   tf_bprm_set_creds),
};

static struct lsm_blob_sizes tf_blob_sizes __ro_after_init = { 0 };

static int __init tf_lsm_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input  = tf_nl_recv,
		.groups = TF_NL_GROUP,
	};

	pr_info("trustforge: LSM init (timeout=%ums fail_open=%d)\n",
		tf_timeout_ms, tf_fail_open ? 1 : 0);

	tf_nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
	if (!tf_nl_sock) {
		pr_err("trustforge: failed to create netlink socket\n");
		return -ENOMEM;
	}

	hash_init(tf_pending_tbl);

	security_add_hooks(tf_hooks, ARRAY_SIZE(tf_hooks), TF_LSM_NAME);
	pr_info("trustforge: %zu hooks installed\n", ARRAY_SIZE(tf_hooks));
	return 0;
}

static void __exit tf_lsm_exit(void)
{
	if (tf_nl_sock) {
		netlink_kernel_release(tf_nl_sock);
		tf_nl_sock = NULL;
	}
	pr_info("trustforge: LSM unloaded\n");
}

DEFINE_LSM(trustforge) = {
	.name = TF_LSM_NAME,
	.init = tf_lsm_init,
	.blobs = &tf_blob_sizes,
};

module_init(tf_lsm_init);
module_exit(tf_lsm_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("TrustForge Authors");
MODULE_DESCRIPTION("TrustForge LSM: kernel hooks bridged to userspace policy daemon");
MODULE_VERSION("0.1.0");
