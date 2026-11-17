// SPDX-License-Identifier: GPL-2.0
// Recorder receipt-lag cross-check (SPEC 5.3, E0).
//
// kprobes on the kernel functions that change the IPv4 FIB and that send
// rtnetlink notifications, filtered to one network namespace. The recorder's
// receipt time minus these timestamps bounds its lag. Kprobes on internal
// functions are version-specific: this is a cross-check, never required.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define FN_NOTIFY 0
#define FN_INSERT 1
#define FN_DELETE 2

volatile const __u32 filter_netns = 0;

struct lag_event {
	__u64 ts_ns;
	__u32 fn;
	__u32 group;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} lag_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lag_lost SEC(".maps");

static __always_inline void emit(struct net *net, __u32 fn, __u32 group)
{
	if (BPF_CORE_READ(net, ns.inum) != filter_netns)
		return;
	struct lag_event *e = bpf_ringbuf_reserve(&lag_events, sizeof(*e), 0);
	if (!e) {
		__u32 z = 0;
		__u64 *l = bpf_map_lookup_elem(&lag_lost, &z);
		if (l)
			__sync_fetch_and_add(l, 1);
		return;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->fn = fn;
	e->group = group;
	bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/rtnl_notify")
int BPF_KPROBE(k_notify, struct sk_buff *skb, struct net *net, u32 pid, u32 group)
{
	emit(net, FN_NOTIFY, group);
	return 0;
}

SEC("kprobe/fib_table_insert")
int BPF_KPROBE(k_insert, struct net *net)
{
	emit(net, FN_INSERT, 0);
	return 0;
}

SEC("kprobe/fib_table_delete")
int BPF_KPROBE(k_delete, struct net *net)
{
	emit(net, FN_DELETE, 0);
	return 0;
}
