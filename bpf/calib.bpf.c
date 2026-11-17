// SPDX-License-Identifier: GPL-2.0
// Preflight and calibration probe.
//
// Attaches to net/netif_receive_skb and skb/kfree_skb and counts events per
// (tracepoint, network-namespace inode). kfree_skb events whose netns matches
// the optional filter are also sent to a ring buffer with their drop reason,
// so calibration can learn the reason codes this kernel actually uses.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TP_RECV 0
#define TP_DROP 1

struct count_key {
	__u32 tp;
	__u32 netns;
};

struct drop_event {
	__u64 ts_ns;
	__u32 netns;
	__u32 ifindex;
	__u32 reason;
	__u16 protocol;
	__u16 _pad;
};

// Set by userspace before load. 0 means "send no drop events".
volatile const __u32 filter_netns = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct count_key);
	__type(value, __u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

static __always_inline __u32 skb_netns(struct sk_buff *skb, __u32 *ifindex)
{
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	if (!dev)
		return 0;
	*ifindex = BPF_CORE_READ(dev, ifindex);
	return BPF_CORE_READ(dev, nd_net.net, ns.inum);
}

static __always_inline void bump(__u32 tp, __u32 netns)
{
	struct count_key k = {.tp = tp, .netns = netns};
	__u64 one = 1, *v = bpf_map_lookup_elem(&counts, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
	else
		bpf_map_update_elem(&counts, &k, &one, BPF_NOEXIST);
}

SEC("tracepoint/net/netif_receive_skb")
int tp_recv(struct trace_event_raw_net_dev_template *ctx)
{
	__u32 ifindex = 0;
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	bump(TP_RECV, skb_netns(skb, &ifindex));
	return 0;
}

SEC("tracepoint/skb/kfree_skb")
int tp_drop(struct trace_event_raw_kfree_skb *ctx)
{
	__u32 ifindex = 0;
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	__u32 ns = skb_netns(skb, &ifindex);
	bump(TP_DROP, ns);

	if (filter_netns == 0 || ns != filter_netns)
		return 0;
	struct drop_event *e = bpf_ringbuf_reserve(&drops, sizeof(*e), 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *l = bpf_map_lookup_elem(&lost, &zero);
		if (l)
			__sync_fetch_and_add(l, 1);
		return 0;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->netns = ns;
	e->ifindex = ifindex;
	e->reason = ctx->reason;
	e->protocol = ctx->protocol;
	e->_pad = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
