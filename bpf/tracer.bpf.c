// SPDX-License-Identifier: GPL-2.0
// Hop-by-hop probe tracer (SPEC 5.4).
//
// net/netif_receive_skb  -> one "rx" event per hop (ingress of each netns)
// skb/kfree_skb          -> one "drop" event with the kernel's drop reason
//
// Only probe packets are recorded: IPv4, UDP, destination port PROBE_PORT and
// the probe magic at payload offset 0 (layout: go/internal/probe). Every
// event carries CLOCK_MONOTONIC time, the network-namespace inode, ifindex,
// IP TTL and the probe's flow ID and sequence number.
//
// veth hands the same sk_buff from namespace to namespace, so the namespace
// of a probe's last ingress is remembered by skb address and used when a
// drop has no device.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define PROBE_MAGIC 0x52504d43
#define EV_RX 0
#define EV_DROP 1

volatile const __u16 probe_port = 7777;

struct event {
	__u64 ts_ns;
	__u64 location; // kfree_skb caller, for diagnostics
	__u64 seq;
	__u32 netns;
	__u32 ifindex;
	__u32 reason;
	__u16 sport;
	__u8 kind;
	__u8 ttl;
	__u8 src;
	__u8 dst;
	__u8 ns_from_skb_map; // drop placed using the last ingress, not skb->dev
	__u8 _pad[5];
};

struct loc {
	__u32 netns;
	__u32 ifindex;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 << 20);
} events SEC(".maps");

// [0] events written, [1] ring-buffer reservations that failed
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct loc);
} last_rx SEC(".maps");

struct probe_hdr {
	__u32 magic;
	__u8 version;
	__u8 src;
	__u8 dst;
	__u8 _r;
	__u16 sport;
	__u16 _r2;
	__u64 seq; // offset 12: packed, or the compiler would pad it to 16
} __attribute__((packed));

static __always_inline void count(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &i);
	if (v)
		*v += 1;
}

// parse reads the IPv4 header at l3 and, for probes, fills e. Returns 0 for a probe.
static __always_inline int parse(void *l3, struct event *e)
{
	struct iphdr iph;
	if (bpf_probe_read_kernel(&iph, sizeof(iph), l3))
		return -1;
	if (iph.version != 4 || iph.protocol != IPPROTO_UDP)
		return -1;
	void *l4 = l3 + iph.ihl * 4;
	struct udphdr udp;
	if (bpf_probe_read_kernel(&udp, sizeof(udp), l4))
		return -1;
	if (udp.dest != bpf_htons(probe_port))
		return -1;
	struct probe_hdr p;
	if (bpf_probe_read_kernel(&p, sizeof(p), l4 + sizeof(udp)))
		return -1;
	if (p.magic != PROBE_MAGIC)
		return -1;
	e->ttl = iph.ttl;
	e->src = p.src;
	e->dst = p.dst;
	e->sport = p.sport;
	e->seq = p.seq;
	return 0;
}

static __always_inline void emit(struct event *e)
{
	struct event *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r) {
		count(1);
		return;
	}
	__builtin_memcpy(r, e, sizeof(*r));
	bpf_ringbuf_submit(r, 0);
	count(0);
}

SEC("tracepoint/net/netif_receive_skb")
int tp_rx(struct trace_event_raw_net_dev_template *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (BPF_CORE_READ(skb, protocol) != bpf_htons(ETH_P_IP))
		return 0;
	struct event e = {};
	// eth_type_trans has pulled the Ethernet header: data is at L3.
	if (parse(BPF_CORE_READ(skb, data), &e))
		return 0;
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	e.ts_ns = bpf_ktime_get_ns();
	e.kind = EV_RX;
	e.ifindex = BPF_CORE_READ(dev, ifindex);
	e.netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
	struct loc l = {.netns = e.netns, .ifindex = e.ifindex};
	__u64 key = (__u64)skb;
	bpf_map_update_elem(&last_rx, &key, &l, BPF_ANY);
	emit(&e);
	return 0;
}

SEC("tracepoint/skb/kfree_skb")
int tp_drop(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (ctx->protocol != ETH_P_IP)
		return 0;
	struct event e = {};
	// In the IP layer the network header offset is valid; data may have
	// moved (e.g. after a link-layer header was pushed for output).
	void *head = BPF_CORE_READ(skb, head);
	__u16 nh = BPF_CORE_READ(skb, network_header);
	if (parse(head + nh, &e) && parse(BPF_CORE_READ(skb, data), &e))
		return 0;
	e.ts_ns = bpf_ktime_get_ns();
	e.kind = EV_DROP;
	e.reason = ctx->reason;
	e.location = (__u64)ctx->location;
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	__u64 key = (__u64)skb;
	if (dev) {
		e.ifindex = BPF_CORE_READ(dev, ifindex);
		e.netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
	} else {
		struct loc *l = bpf_map_lookup_elem(&last_rx, &key);
		if (l) {
			e.netns = l->netns;
			e.ifindex = l->ifindex;
			e.ns_from_skb_map = 1;
		}
	}
	bpf_map_delete_elem(&last_rx, &key);
	emit(&e);
	return 0;
}
