// SPDX-License-Identifier: GPL-2.0
/*
 * lsm_inode_permission.bpf.c
 *
 * BPF LSM program attached at lsm/inode_permission. Each call pushes
 * a compact event to a per-CPU ring buffer; userspace reads it,
 * consults the TrustForge daemon, and writes a verdict into the
 * `verdict_map`. The program polls the map briefly for the matching
 * cookie and either returns 0 (allow) or -EACCES (deny). On timeout
 * we FAIL OPEN to match the M1 module's policy.
 *
 * Requires: kernel >= 5.7 with CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TF_MAX_PATH       256
#define TF_KIND_INODE     1
#define TF_VERDICT_TIMEOUT_NS  (100ULL * 1000ULL * 1000ULL)  /* 100 ms */
#define TF_FAIL_OPEN      1

struct tf_event_t {
	__u64 cookie;
	__u32 kind;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u32 mask;
	char  comm[16];
	char  path[TF_MAX_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);   /* 1 MiB */
} events SEC(".maps");

/* verdict_map: cookie -> int (0 allow, <0 deny). Userspace writes,
 * BPF reads. We use HASH so that we can delete entries after consume. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __s32);
	__uint(max_entries, 65536);
} verdict_map SEC(".maps");

/* monotonic 64-bit cookie counter (per-cpu to avoid contention) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} cookie_ctr SEC(".maps");

static __always_inline __u64 next_cookie(void)
{
	__u32 zero = 0;
	__u64 *c = bpf_map_lookup_elem(&cookie_ctr, &zero);
	if (!c) return bpf_ktime_get_ns();
	*c += 1;
	/* Mix in CPU id to keep cookies globally unique. */
	return ((__u64)bpf_get_smp_processor_id() << 56) | (*c & 0x00ffffffffffffffULL);
}

static __always_inline int wait_verdict(__u64 cookie)
{
	__u64 start = bpf_ktime_get_ns();
	__s32 *v;

	#pragma unroll
	for (int i = 0; i < 32; i++) {
		v = bpf_map_lookup_elem(&verdict_map, &cookie);
		if (v) {
			__s32 r = *v;
			bpf_map_delete_elem(&verdict_map, &cookie);
			return r;
		}
		if (bpf_ktime_get_ns() - start > TF_VERDICT_TIMEOUT_NS)
			break;
	}
	return TF_FAIL_OPEN ? 0 : -13; /* -EACCES */
}

SEC("lsm/inode_permission")
int BPF_PROG(tf_inode_permission, struct inode *inode, int mask, int ret)
{
	if (ret != 0) return ret;
	if (!inode)  return 0;

	struct tf_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return TF_FAIL_OPEN ? 0 : -13;

	__u64 cookie = next_cookie();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->cookie = cookie;
	e->kind   = TF_KIND_INODE;
	e->pid    = bpf_get_current_pid_tgid() >> 32;
	e->uid    = (__u32)uid_gid;
	e->gid    = (__u32)(uid_gid >> 32);
	e->mask   = (__u32)mask;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->path[0] = '\0';

	bpf_ringbuf_submit(e, 0);
	return wait_verdict(cookie);
}

char LICENSE[] SEC("license") = "GPL";
