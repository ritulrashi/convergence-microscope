# Architecture decision records

Each ADR: context, decision, alternatives, consequence.

## ADR-001: Pinned versions

- **Context:** Ground rule 7 (determinism) and rule 1 (every result names its environment) need fixed versions.
- **Decision:** devcontainer image `ghcr.io/srl-labs/containerlab/devcontainer-dind:0.83.0` (containerlab 0.83.0), router image `quay.io/frrouting/frr:10.7.1` (latest stable 10.x on 2026-11-17, stored in `images/frr-image.txt` so scripts and the machine record read one source), Go 1.26, `github.com/cilium/ebpf` v0.22.0, host image on `alpine:3.24.4` built with `golang:1.26.11-alpine`.
- **Alternatives:** floating tags (`latest`, `10`); rejected because results would not be reproducible.
- **Consequence:** Go 1.26 instead of the spec's minimum 1.22, because cilium/ebpf v0.22 requires Go 1.25+ and `golang.org/x/sys` v0.50 requires 1.26.

## ADR-002: Commit bpf2go output

- **Context:** eBPF C is compiled with clang via `bpf2go`. CI runners and the host image build should not need clang or a `vmlinux.h`.
- **Decision:** `bpf/vmlinux.h` is generated from the running kernel's BTF and not committed. The bpf2go outputs (`*_bpfel.go`, `*_bpfel.o`) are committed. CO-RE relocations make the objects portable across kernels with BTF.
- **Alternatives:** commit `vmlinux.h` (several MB, kernel-specific noise in diffs); compile in CI (adds clang to every job).
- **Consequence:** after editing any `.bpf.c` file, run `make generate` and commit the regenerated objects.

## ADR-003: Drop-reason names come from kernel BTF

- **Context:** Ground rule 4 and SPEC 5.5 forbid hard-coding drop-reason codes from documentation. The numeric values of `enum skb_drop_reason` change between kernel versions.
- **Decision:** userspace reads `enum skb_drop_reason` from `/sys/kernel/btf/vmlinux` at runtime to name codes, and calibration records which codes this kernel emits for constructed blackholes and loops.
- **Alternatives:** a static table copied from kernel headers.
- **Consequence:** names always match the running kernel; the classifier mapping is a calibration output, not source code.

## ADR-004: Go installed into /opt/go, not via the devcontainer Go feature

- **Context:** The containerlab devcontainer image ships Go 1.22 in `/usr/local/go` and exports `GOROOT=/usr/local/go`. The devcontainer Go feature unpacked 1.26 over it, leaving 1.22 runtime files behind, and every build failed with "redeclared in this block" errors in `runtime`.
- **Decision:** `post-create.sh` installs the pinned Go release into an empty `/opt/go`. `devcontainer.json` sets `GOROOT=/opt/go` and puts `/opt/go/bin` first on `PATH`; the Makefile exports the same, so non-login shells (for example `gh codespace ssh -- cmd`) also get the right toolchain.
- **Alternatives:** delete `/usr/local/go` first (modifies the base image's layout); build a custom image (slower Codespace creation).
- **Consequence:** one toolchain, one version, independent of the base image's Go.

## ADR-005: Preflight mounts tracefs when missing

- **Context:** Codespaces do not mount tracefs inside the devcontainer. `link.Tracepoint` needs it to look up tracepoint IDs, and fails with "neither debugfs nor tracefs are mounted".
- **Decision:** `scripts/preflight.sh` (and later the tracer startup) mounts tracefs at `/sys/kernel/tracing` if neither tracing path is mounted, and records that as its own check.
- **Alternatives:** a bind mount in `devcontainer.json` (only takes effect after a full rebuild, and depends on the host path existing); `tp_btf` raw tracepoints (no tracefs needed, but a different program type than the spec names).
- **Consequence:** the privileged devcontainer gains one extra mount, done visibly and recorded in `results/preflight.json`.

## ADR-006: Spines do not expect each other's loopbacks in leaf-spine eBGP

- **Context:** In T1 eBGP, spines share ASN 65000 and leaves export only their own prefixes (SPEC 4.2). The first `verify` failed because `spine1` had no route to `spine2`'s loopback.
- **Decision:** That is the intended RFC 7938 behavior, so `verify` excludes other spines' loopbacks from a spine's expected RIB in leaf-spine eBGP. All other prefixes are still required everywhere.
- **Alternatives:** let leaves re-export spine loopbacks (makes leaves transit for spine-to-spine traffic, which the spec forbids); give spines distinct ASNs (not RFC 7938 style).
- **Consequence:** spine-to-spine reachability is not part of the fabric's contract and is not probed.

## ADR-007: Lab plumbing choices

- **Context:** Containers keep Docker's management interface (eth0, 172.20.20.0/24) with a default route.
- **Decision:** Hosts get `10.0.0.0/8 via <gateway>` instead of replacing the default route, so the management path keeps working and all lab traffic uses the fabric. Router sysctls (`ip_forward`, `fib_multipath_hash_policy=1`, `rp_filter=0`, IPv6 off) are set through containerlab's `sysctls` so they apply before FRR starts. Interface addresses are configured by FRR (`zebra`), so the generated `frr.conf` is the single source of addressing.
- **Alternatives:** `exec` sysctls after start (race with FRR); addresses via `ip addr` in `exec` (two sources of truth for drift checks).
- **Consequence:** `labctl diff` compares one config per router.

## ADR-008: Generated configs use FRR's canonical running-config form

- **Context:** `labctl diff` compares running and generated configs (SPEC 4.4). FRR rewrites its input: it reorders blocks (prefix-lists and route-maps first, interfaces sorted, `lo` after `eth*`), reorders lines inside blocks, turns `passive-interface X` into `ip ospf passive` under the interface, and hides defaults (`isis metric 10`, `maximum-paths 64`, `metric-style wide`, `bgp log-neighbor-changes` under `frr defaults datacenter`). It also shows `use-underlays-nexthop-weight`, which FRR 10.7 adds on its own.
- **Decision:** the templates emit exactly FRR 10.7.1's canonical form. Normalisation in `labctl/drift.py` only strips FRR's banner, version line, `!` separators and `end`. A clean deploy diffing empty is a tested property (`tests/test_drift.py`, running configs captured from clean deploys of every mode).
- **Alternatives:** a semantic normaliser that parses both configs into (block, line) sets with a table of FRR rewrites. More code, and every new FRR rewrite is silently "normalised away" instead of showing up as a failing test.
- **Consequence:** a new FRR version may change the canonical form; the drift fixtures will then fail and must be recaptured with the new image. Relying on FRR's default `maximum-paths` (64) is covered by `verify`'s ECMP-width check.

## ADR-009: Probe flows and rates

- **Context:** SPEC 5.2 asks for a flow ID of (source host, destination host, source port), source ports rotated from a fixed set to cover ECMP paths, and 1,000 pps per flow by default.
- **Decision:** the rate and the sequence numbers belong to a (source, destination) pair: packet `seq` is due at `start + seq/rate` and leaves from `ports[seq % 4]` (40000 to 40003). Each packet still carries the full flow ID. With 4 ports, each (src, dst, sport) flow is probed every 4 ms at the default rate.
- **Alternatives:** 1,000 pps for every (src, dst, sport) flow (4x the packet rate: 48,000 pps on T1 all-pairs, too much for the target VM); one source port per pair (only one ECMP path probed).
- **Consequence:** the loss timeline for a pair has 1 ms resolution, and each ECMP path a pair uses has about 4 ms resolution.

## ADR-010: The recorder models the kernel's silent link-down flush

- **Context:** Calibration showed that when a link goes down, the kernel removes nexthop objects on that device and the routes that depended only on them without sending RTM_DELNEXTHOP or RTM_DELROUTE, and zebra does not resend them. A recorder that only applies netlink messages kept stale ECMP sets (calibration steps B2/B3 failed: no event at all for 7 prefixes).
- **Decision:** on a link message showing admin down, or up without carrier (`!IFF_RUNNING && !IFF_LOWER_UP`), the recorder applies the kernel's rule itself: delete every nexthop object on the device (with the group and route cascade), and, for admin down only, drop inline next hops on the device. These changes are logged with `via: link-flush`. 100 ms after each link-down the recorder dumps the kernel tables and logs any difference from its model (`kind: check`); the count is in its stats.
- **Alternatives:** dump after every link event and diff (correct, but the change time would be the dump time, not the link event time); `nexthop_compat_mode` (affects route notifications on nexthop updates, not this flush).
- **Consequence:** link-down changes are timestamped at the link event. Calibration exercises both admin down and carrier loss, and every cross-check so far found 0 mismatches.

## ADR-011: Kernel-semantics calibration runs without a routing daemon

- **Context:** zebra adopts nexthop groups created outside FRR (`show nexthop-group rib` lists them as `(zebra)`) and reverts outside changes to them about 10 ms later. Calibrating the recorder's nexthop handling on a router therefore measured zebra, not the kernel.
- **Decision:** calibration part A runs in a dedicated namespace with dummy and veth interfaces and no daemon. Part B checks FRR-driven changes and link events on a real T1 router.
- **Consequence:** fault injection must never edit kernel nexthop objects on a router directly; it acts on links, FRR config or FRR daemons.

## ADR-012: Probe-schedule tolerance and the 2-core limit

- **Context:** The prober flags a run invalid if any send leaves more than the tolerance (5 ms) after its scheduled time. On the 2-core Codespace, T1 all-pairs probing (12 pairs, 12,000 pps total) with 6 recorders lost no packets, but every trial had a few sends 5 to 12 ms late (p99 about 2 ms), and so did 500 pps per pair. One pair alone stayed under 2 ms. The cause is CPU scheduling contention among 4 probers, 6 FRR routers and 6 recorders on 2 vCPUs (steal time was 0).
- **Decision:** keep the 5 ms tolerance and run experiments on the spec's 4-core target. Results from 2 cores are kept under `results/p3/two_core/` as a measured limit, not dropped.
- **Alternatives:** raise the tolerance until 2-core runs pass (hides real gaps in probe coverage); probe fewer pairs on 2 cores (possible later for specific experiments).
- **Consequence:** the 2-core VM still runs everything, but runs marked invalid there are expected.

## ADR-013: Routers have no default route

- **Context:** containerlab nodes keep Docker's management interface and its default route (`default via 172.20.20.1 dev eth0`). A router whose fabric route for a prefix disappeared would send the packet to the management bridge instead of dropping it, so blackholes during convergence would turn into leaks and look like something else.
- **Decision:** each router runs `ip route del default` at start (containerlab `exec`), and `verify` fails if any router's RIB has a default route.
- **Alternatives:** a separate VRF for management (more config, and FRR would need VRF awareness); leave it and filter in analysis (the packets would really leave the fabric).
- **Consequence:** the management network still reaches routers through its connected /24, which is all `docker exec` and containerlab need.

## ADR-014: node_down freezes FRR with SIGSTOP

- **Context:** SPEC 6 defines `node_down` as stopping routing on a router while its interfaces stay up. The FRR image runs `watchfrr` as the container's main process: it restarts killed daemons, and stopping it ends the container (and its interfaces).
- **Decision:** `node_down` sends SIGSTOP from the host to every FRR process in the container (watchfrr, zebra, mgmtd, staticd, bgpd/ospfd/isisd, bfdd); undo sends SIGCONT.
- **Alternatives:** `frrinit.sh stop` (kills the container); SIGKILL the daemons (watchfrr restarts them mid-run, and zebra's restart rewrites the FIB); stop the container (interfaces vanish, which is `carrier_down` on every link).
- **Consequence:** this models a hung control plane: hellos, keepalives and BFD stop, the kernel keeps forwarding with the last FIB, and neighbors detect the failure through BFD or protocol hold timers. A graceful shutdown (neighbors told explicitly) is not modeled.

## ADR-015: What raw data each run keeps

- **Context:** a run probes 12 host pairs at 1,000 pps for 8 s: about 200,000 probe records and up to 400,000 tracer records. E3 alone is up to 960 runs, far too much to commit.
- **Decision:** every run keeps `run.json`, `plan.json`, the full `fib_events.jsonl.gz`, and replay's per-probe output for every probe that was lost or predicted lost (`replay/predictions.jsonl`), mismatches, FIB loops and summary, plus `report.json` and `timeline.html`. Probe and tracer logs of delivered probes are summarized by replay and then deleted, except in evidence runs (`--keep-raw`), which keep them gzipped.
- **Alternatives:** keep everything (tens of GB); keep only summaries (loses the per-packet evidence for lost packets).
- **Consequence:** every number in FINDINGS can be recomputed from committed files, and per-packet evidence exists for every lost packet.

## ADR-016: Recorder lag is bounded with kprobes on rtnl_notify and fib_table_insert/delete

- **Context:** SPEC 5.3 asks to bound the recorder's receipt lag, with a kprobe cross-check on `fib_table_insert`/`fib_table_delete`.
- **Decision:** `bpf/lag.bpf.c` probes all three: `rtnl_notify` (the kernel sending the netlink message) and the two FIB functions. E0 reports the recorder's receipt time minus each.
- **Consequence:** the `rtnl_notify` figure isolates the netlink delivery plus user-space scheduling delay; the FIB-function figure adds the kernel's own work between changing the table and notifying. Both are cross-checks: kprobes on internal functions can disappear between kernel versions, and `lagprobe` reports which ones attached.

## ADR-017: Drops are classified by reason code and kernel function

- **Context:** tracer calibration showed that blackhole and unreachable routes both drop with `SKB_DROP_REASON_NOT_SPECIFIED` (code 2), a code many unrelated paths also use. The reason code alone cannot separate a blackhole from other drops.
- **Decision:** the tracer resolves the `kfree_skb` call site to a function name through `/proc/kallsyms`, and calibration writes classes as `code@function` pairs (`results/calibration/drop_reasons.json`). On kernel 6.8: blackhole = `2@ip_error`, `70@ip_error` (`IP_INNOROUTES`); TTL expiry = `11@ip_forward` (`IP_INHDR`).
- **Alternatives:** raw addresses (change every boot with KASLR); reason codes only (misclassifies).
- **Consequence:** any other (code, function) pair is reported as `other:<reason>`, never guessed.
