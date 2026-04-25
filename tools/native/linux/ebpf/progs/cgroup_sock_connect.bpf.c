// SPDX-License-Identifier: GPL-2.0
/*
 * cgroup_sock_connect.bpf.c
 *
 * cgroup/connect4 program for per-cgroup, per-process connection
 * authorization. Logs each attempt via the shared ringbuf and returns
 * 1 (allow) or 0 (deny) directly, based on a synchronous decision
 * polled from `verdict_map`. Unlike the lsm/* programs this hook
 * cannot return -EACCES; the cgroup BPF ABI is boolean.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TF_MAX_PATH        256
#define TF_KIND_CGROUP_C4  10
#define TF_VERDICT_TIMEOUT_NS  (50ULL * 1000ULL * 1000ULL)  /* 50 ms */
#define TF_FAIL_OPEN       1

struct tf_event_t {
	__u64 cookie;
	__u32 kind;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u32 mask;       /* high 16 = port, low 16 = family */
	char  comm[16];
	char  path[TF_MAX_PATH];   /* "ip4:%pI4:%u" rendered by userspace */
};

extern struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

extern struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __s32);
	__uint(max_entries, 65536);
} verdict_map SEC(".maps");

extern struct {
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
	return ((__u64)bpf_get_smp_processor_id() << 56) | (*c & 0x00ffffffffffffffULL);
}

static __always_inline int wait_verdict_bool(__u64 cookie)
{
	__u64 start = bpf_ktime_get_ns();
	__s32 *v;

	#pragma unroll
	for (int i = 0; i < 16; i++) {
		v = bpf_map_lookup_elem(&verdict_map, &cookie);
		if (v) {
			__s32 r = *v;
			bpf_map_delete_elem(&verdict_map, &cookie);
			return r == 0 ? 1 : 0;   /* 0 -> allow (1), nonzero -> deny (0) */
		}
		if (bpf_ktime_get_ns() - start > TF_VERDICT_TIMEOUT_NS)
			break;
	}
	return TF_FAIL_OPEN ? 1 : 0;
}

SEC("cgroup/connect4")
int tf_cgroup_connect4(struct bpf_sock_addr *ctx)
{
	struct tf_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return TF_FAIL_OPEN ? 1 : 0;

	__u64 cookie = next_cookie();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 dport = bpf_ntohs((__u16)ctx->user_port);

	e->cookie = cookie;
	e->kind   = TF_KIND_CGROUP_C4;
	e->pid    = bpf_get_current_pid_tgid() >> 32;
	e->uid    = (__u32)uid_gid;
	e->gid    = (__u32)(uid_gid >> 32);
	e->mask   = (dport << 16) | (__u32)ctx->family;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Render the IPv4 address into path[] for userspace logging. */
	__builtin_memset(e->path, 0, sizeof(e->path));
	__u32 ip = ctx->user_ip4;
	e->path[0] = 'i'; e->path[1] = 'p'; e->path[2] = '4'; e->path[3] = ':';
	/* Don't bother formatting decimals in BPF — userspace will. */
	__builtin_memcpy(e->path + 4, &ip, sizeof(ip));

	bpf_ringbuf_submit(e, 0);
	return wait_verdict_bool(cookie);
}

char LICENSE[] SEC("license") = "GPL";
