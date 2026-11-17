# Phase 0: environment, preflight and the eBPF gate

## Decision: Tier A (full)

Every eBPF check in SPEC section 3 passed from inside the devcontainer, and netlink recording works. The full spec, including the hop-by-hop tracer (5.4), will be built.

Source: `results/preflight.json` (commit bd796b2, `git_tree_clean: true`).

## What was built

- `.devcontainer/`: `ghcr.io/srl-labs/containerlab/devcontainer-dind:0.83.0`, privileged, sshd feature; `post-create.sh` adds clang/llvm, libbpf headers, bpftool, Go 1.26.11 in `/opt/go` (ADR-004) and the Python package.
- `bpf/calib.bpf.c` and `go/cmd/ebpfcheck`: a cilium/ebpf (bpf2go, CO-RE) program on `tracepoint/net/netif_receive_skb` and `tracepoint/skb/kfree_skb`. It counts events per network-namespace inode and sends drop events for one chosen namespace through a ring buffer, with lost-reservation counting. Drop-reason names are read from the kernel's BTF (ADR-003).
- `scripts/preflight.sh` with a two-router FRR lab (`scripts/preflight-lab/`), writing `results/preflight.json` plus raw evidence in `results/preflight/`.
- `labctl/machine.py`: the `machine` record every results file starts with.
- `images/host/Dockerfile`: Alpine 3.24.4 with iproute2, iputils, tcpdump and the prober binary (a stub until phase 3). Built image size: 14.1 MB.
- `docs/decisions.md`: ADR-001 to ADR-005.

## What was measured

| Check | Result | Evidence |
|---|---|---|
| Kernel 5.17 or newer | pass | 6.8.0-1070-azure |
| `/sys/kernel/btf/vmlinux` | pass | 6,243,148 bytes |
| eBPF build (bpf2go) | pass | clang 14.0.6 |
| Attach both tracepoints in the devcontainer | pass | 44 events across 2 namespaces in 3 s |
| Events from a containerlab node's netns, by inode | pass | r1 netns 4026532290: 29 `netif_receive_skb`, 7 `kfree_skb`; reasons NO_SOCKET (code 3) x5 from the UDP-to-closed-port test, NOT_SPECIFIED (code 2) x2; ring buffer lost 0 |
| Netlink route and nexthop monitoring in r1's netns | pass | FRR 10.7.1 installed nexthop object `id 15` first, then `192.0.2.0/24 nhid 15`; the route delete arrived as RTM_DELROUTE |
| `tc netem` on a veth | pass | 100% loss with netem, 0% after removal |
| Shared time namespace | pass | devcontainer and r1 both in time ns 4026531834 |
| Environment | recorded | 2 vCPU AMD EPYC 7763, 8.3 GB RAM, Docker 26.1.5, containerlab 0.83.0, FRR 10.7.1, Go 1.26.11, Python 3.11.18 |

## What broke, and what it means for later phases

1. **Go toolchain collision.** The Go devcontainer feature installed over the image's Go 1.22 and every build failed. Fixed by ADR-004.
2. **tracefs not mounted** in the Codespace container, so tracepoint attach failed. Fixed by ADR-005.
3. **The machine record called its own output file a dirty tree.** `git_tree_clean` now ignores `results/`, which only holds outputs.
4. **Drops with no device (open problem for the tracer).** In the unfiltered attach test, all 18 `kfree_skb` events had `skb->dev == NULL`, so their namespace read as 0. The tracer (phase 4) cannot rely on `skb->dev` alone to place a drop at a router. Options to evaluate: fall back to the socket's namespace, or remember the namespace from the probe's last `netif_receive_skb` keyed by skb address. Calibration (5.5) will show whether forwarding-path drops (no route, TTL expiry) keep `dev` set.
5. **FRR keeps nexthop objects after the route is gone.** No RTM_DELNEXTHOP arrived within the 2 s window after the static route was removed. The recorder (phase 3) must treat a route's next-hop set as defined by the route plus its current nexthop object, not assume nexthop deletes follow route deletes.
6. The 2-core Codespace has 8.3 GB RAM, the spec's lower bound. Phases 1 to 5 stay on it; sweeps (E3 to E5) may move to 4 cores.
