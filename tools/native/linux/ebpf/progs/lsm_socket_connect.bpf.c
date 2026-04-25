// SPDX-License-Identifier: GPL-2.0
/*
 * lsm_socket_connect.bpf.c
 *
 * BPF LSM program attached at lsm/socket_connect. Records the target
 * sockaddr (family-only here for portability), pushes an event to the
 * shared ring buffer, and waits briefly for a verdict written to the
 * shared verdict_map.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TF_MAX_PATH       256
#define TF_KIND_CONNECT   4
#define TF_VERDICT_TIMEOUT_NS  (100ULL * 1000ULL * 1000ULL)
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
	return TF_FAIL_OPEN ? 0 : -13;
}

SEC("lsm/socket_connect")
int BPF_PROG(tf_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret != 0) return ret;
	if (!address) return 0;

	struct tf_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return TF_FAIL_OPEN ? 0 : -13;

	__u64 cookie = next_cookie();
	__u64 uid_gid = bpf_get_current_uid_gid();
	sa_family_t family = 0;
	bpf_core_read(&family, sizeof(family), &address->sa_family);

	e->cookie = cookie;
	e->kind   = TF_KIND_CONNECT;
	e->pid    = bpf_get_current_pid_tgid() >> 32;
	e->uid    = (__u32)uid_gid;
	e->gid    = (__u32)(uid_gid >> 32);
	e->mask   = (__u32)family;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->path[0] = '\0';

	bpf_ringbuf_submit(e, 0);
	return wait_verdict(cookie);
}

char LICENSE[] SEC("license") = "GPL";
