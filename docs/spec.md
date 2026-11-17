# Convergence Microscope: Build Spec

**One-line pitch:** routing verifiers check a network before and after a change. This project shows what happens in between, packet by packet.

**What it is:** an emulated network (FRRouting in containerlab) that records:

- every routing-table change on every router, against one shared clock
- the hop-by-hop path of every probe packet, using eBPF

It then rebuilds the network's forwarding state at every instant of a failure or drain. From that it explains each lost packet as a **blackhole** (no route), a **microloop** (routers briefly pointing at each other) or another cause. It also checks its own predictions against what packets actually did.

**The insight that makes it possible:** every router container shares one Linux kernel. So there is one clock for every event, and one kernel that sees every packet. Real networks have neither, which is why this kind of per-packet convergence forensics is hard outside a lab.

It is an independent portfolio project, not affiliated with Meta. The related published work:

- RFC 7938, BGP in large data centers
- "Running BGP in Data Centers at Scale" (Meta, NSDI '21)
- NetNORAD, Meta's end-to-end probing
- RFC 8333, microloop prevention

**Target role:** Meta Network Production Engineer (University Grad).
**It covers:**

- BGP, OSPF and IS-IS
- data center and backbone-style topologies
- config generation and consistency
- root-cause analysis from data
- automated mitigation (a measured, safe drain sequence)
- network performance improvement
- Linux and eBPF, with Python and Go

---

## 1. Ground rules (read before writing any code)

1. **No unmeasured numbers.** Every number in README, FINDINGS, BENCHMARKS or TESTING must come from a committed script. Its raw output goes in `results/<experiment>/`.
   - Each raw file starts with a `machine` record: CPU count and model, RAM, kernel version, Docker version, containerlab version, FRR image tag, Go and Python versions, git commit and a tree-clean flag.
2. **Never fake a feature.** README lists only what is implemented and tested.
   - A "Scope and limits" section says: everything runs as containers on one VM; there are no switch ASICs; timings are lab timings, not hardware timings.
3. **Report problems, don't hide them.** FINDINGS.md and BENCHMARKS.md each have a "Problems found" section.
4. **Calibrate before trusting.** Every classifier, such as drop-reason codes and loop detection, is validated against deliberately constructed cases with known answers before it is used in an experiment.
5. **Invalid runs are reported, never silently dropped.** Mark a run invalid, keep it in the raw data, and exclude it from summary tables with the reason, if:
   - the tracer loses events (ring buffer overflow)
   - the recorder misses messages
   - the probe sender falls behind schedule
6. **Work in phases** (section 10). Each phase ends with:
   - green tests
   - a short `reports/phaseN.md` (what was built, what was measured, what broke)
   - a commit
   - Stop after each phase and summarize for me before starting the next.
7. **Be deterministic.** The same intent produces byte-identical configs. Every experiment takes a seed. Probe schedules are reproducible.
8. **Fit in a 4-core / 16 GB Codespace,** at most about 14 containers. It must still run, slower, on 2-core / 8 GB.
9. **Stacks:**
   - **Python 3.11+** (type hints, ruff, pytest, pydantic, Typer) for the generator, orchestration, analysis and reports.
   - **Go 1.22+** (gofmt, `go test`, `github.com/cilium/ebpf` with `bpf2go`) for the prober, recorder, tracer loader and replay engine.
   - **eBPF programs in C,** compiled with clang, using CO-RE.
   - No em dashes in any docs.
10. **Record decisions.** Every non-obvious design choice gets an ADR in `docs/decisions.md` (context, decision, alternatives, consequence).

---

## 2. Environment

- `.devcontainer/devcontainer.json` uses the containerlab Docker-in-Docker devcontainer image (`ghcr.io/srl-labs/containerlab/devcontainer-dind`), pinned to a version tag. Add the Go and Python features, clang/llvm, libbpf headers and bpftool.
- Router image: `quay.io/frrouting/frr`, pinned to the latest stable 10.x tag at build time. Record the tag.
- Host image: build `images/host/Dockerfile` from Alpine with iproute2, iputils, tcpdump and the Go prober. Keep it small.

---

## 3. Phase 0 gate: the eBPF check and the fallback decision

`scripts/preflight.sh` writes `results/preflight.json`. Every check gets a pass/fail and evidence:

| Check | Why |
|---|---|
| Kernel 5.17 or newer | `kfree_skb` drop reasons |
| `/sys/kernel/btf/vmlinux` present | CO-RE |
| A trivial eBPF program attaches to `tracepoint/skb/kfree_skb` and `tracepoint/net/netif_receive_skb` **from inside the devcontainer** | Basic eBPF access |
| It sees events from packets inside a containerlab node's network namespace, with that namespace's inode | Cross-namespace visibility |
| Netlink route monitoring from inside a router container sees `RTM_NEWROUTE`/`RTM_DELROUTE` **and** `RTM_NEWNEXTHOP` | FRR 8+ installs kernel nexthop groups, so ECMP changes may appear only as nexthop updates |
| `tc qdisc ... netem` works on a veth | Silent-failure injection |
| CPU count, memory, Docker and containerlab versions | Recorded for every result |

**Decision rule.** Write it in `reports/phase0.md`.

- **Tier A (full):** all eBPF checks pass. Build everything in this spec.
- **Tier B (no eBPF):** eBPF checks fail, but netlink recording works.
  - Build everything except the hop-by-hop tracer (5.4).
  - The replay engine still predicts the fate of each probe packet.
  - Validation uses the receivers' sequence numbers. Each packet's observed fate (delivered or lost) is compared with the prediction, so the comparison is still per packet; only the observed hop path is missing.
  - Cause attribution is labeled "predicted, not observed" everywhere.
- **Tier C:** netlink recording also fails (unlikely). Stop and report to me before doing anything else.

---

## 4. Network foundation

### 4.1 Topologies, both generated from the intent

- **T1, leaf-spine:**
  - 2 spines and 4 leaves; every leaf connects to both spines, for 8 fabric links
  - 4 hosts, one per leaf; each leaf is its host's L3 gateway
- **T2, backbone-style mesh:**
  - 6 routers in a ring with 2 chords, with **uneven link costs** chosen so that some single-link failures create alternate paths through routers that converge at different times; this is where microloops happen
  - 3 hosts attached at different sites
- **Addressing,** allocated by the generator from pools:
  - loopbacks: `10.0.0.0/24` (/32 each)
  - links: `10.1.0.0/16` as /31s
  - host subnets: `10.10.<site>.0/24`
- Set `net.ipv4.fib_multipath_hash_policy=1` (L4 hashing) on routers.

### 4.2 Routing modes (intent field `routing.mode`)

| Mode | Design |
|---|---|
| `ebgp` | RFC 7938 style on T1: spines share one ASN, each leaf has its own, eBGP on every link, `maximum-paths`, BFD optional, outbound prefix-lists so leaves never carry transit traffic. On T2, each router has its own ASN. |
| `ospf` | OSPFv2 area 0, point-to-point links, link costs from the intent, BFD optional, SPF throttle timers from the intent. |
| `isis` | IS-IS level-2, point-to-point, wide metrics, metrics from the intent, BFD optional, SPF delay timers from the intent. |

The intent can set timers per router, including SPF delays. That makes it possible to emulate routers that converge at different speeds. Experiments using this must say so in the results.

### 4.3 Config generation: `labgen` (Python)

- **Intent model:** `intent/*.yaml` with a pydantic schema covering topology, roles, links and costs, the ASN scheme, address pools, mode, timers and BFD.
- **Validation rejects bad intent with clear errors:**
  - duplicate ASNs or router IDs
  - overlapping or exhausted pools
  - links to unknown nodes
  - a leaf with fewer than 2 uplinks in T1
- **Rendering:** Jinja2 templates produce `generated/<topology>-<mode>/<node>/frr.conf`, the FRR `daemons` file and the containerlab topology.
- **Tests:** golden files for every topology-mode pair, a determinism test, and one failing input per validation rule.

### 4.4 Lab control and verification: `labctl` (Python, Typer)

- **Commands:** `up`, `down`, `verify`, `diff`, `snapshot`, `run`, `report`.
- **`verify`** uses FRR JSON output only:
  - every expected session or adjacency is up
  - every expected prefix is in every RIB
  - the expected ECMP width on T1
  - a full-mesh host ping passes
- **`diff`** detects config drift: running config vs generated config, normalized.
- **`snapshot`** dumps every router's kernel routes and nexthop objects (`ip -j route`, `ip -j nexthop`) with a monotonic timestamp. Snapshots are the starting state for replay.

---

## 5. The microscope

### 5.1 The shared clock

All timestamps use `CLOCK_MONOTONIC` nanoseconds:

- eBPF: `bpf_ktime_get_ns`
- Go: `unix.ClockGettime(CLOCK_MONOTONIC)`

Containers share the kernel, so these are directly comparable across routers. Document this in DESIGN.md, and show that containerlab does not use time namespaces.

### 5.2 Prober: `go/cmd/prober`

- **Senders** on hosts send UDP probes on a fixed destination port. The payload carries:
  - a magic number
  - flow ID (source host, destination host, source port)
  - sequence number
  - send timestamp
- Flows rotate source ports from a fixed set, so they cover multiple ECMP paths.
- **Rates:** configurable, defaulting to 1,000 pps per flow during experiments.
- **Receivers** log every received sequence number. The prober flags a run invalid if the send schedule slips beyond a set tolerance.
- Output: `probes.jsonl` (sent and received records).

### 5.3 Route recorder: `go/cmd/recorder`

- One process per router network namespace. It joins the namespace with `setns`.
- It subscribes to IPv4 route and nexthop netlink groups, and timestamps each message on receipt.
- It resolves nexthop-group updates into effective next-hop sets per prefix, so a change to a nexthop group counts as a route change for every prefix that uses it.
  - Alternative: configure FRR not to use kernel nexthop groups. That must be an ADR with the tradeoff.
- It detects and reports netlink buffer overruns (`ENOBUFS`). Any overrun marks the run invalid.
- Output: `fib_events.jsonl` with router, timestamp, prefix, old next-hop set and new next-hop set.
- **Known limitation to measure:** receipt time lags the kernel change by userspace scheduling delay.
  - Bound it in E0, using an optional kprobe on `fib_table_insert`/`fib_table_delete` as a cross-check where the kernel allows.
  - Kprobes on internal functions are version-specific. They are a cross-check only, never required.

### 5.4 Packet tracer: `go/cmd/tracer` plus `bpf/tracer.bpf.c` (Tier A only)

- **Attach points:**
  - `tracepoint/net/netif_receive_skb`: each hop's ingress
  - `tracepoint/skb/kfree_skb`: drops, with reason
  - Optionally, `net_dev_xmit` for egress.
- **In-kernel filtering:** only probe packets (UDP destination port plus magic) are recorded, to keep overhead low.
- **Per event, record:**
  - timestamp
  - network-namespace inode (mapped to a router name using a table built at startup)
  - ifindex
  - flow ID, sequence number and IP TTL
  - for drops, the drop reason
- Send events through a BPF ring buffer, and count lost or failed reservations. Any loss marks the run invalid.
- Output: `hops.jsonl`.
- **Loop signature:** the same probe seen twice at the same router with decreasing TTL. Its final fate is usually a TTL-expiry drop.

### 5.5 Calibration, which must pass before any experiment

The goal is to build deliberate failure cases with known answers, then confirm each tool reports them correctly:

- **Blackhole:** install a static route with no valid next hop (or a blackhole route) on one router. Confirm the tracer reports the drop at that router and record the exact drop-reason code this kernel uses.
- **Loop:** install two static routes that point two routers at each other for one prefix. Confirm the tracer sees repeated visits and a TTL-expiry drop, and record that drop-reason code.
- **Recorder:** apply scripted route changes. Confirm every change appears in `fib_events.jsonl`, with the right before and after next-hop sets.
- **Clock sanity:** for a probe crossing several hops, hop timestamps must increase monotonically.

Results go to `results/calibration/`. The classifier's reason-code mapping is generated from these results, not hard-coded from documentation.

### 5.6 Replay engine: `go/cmd/replay`

- **Input:** starting snapshots, `fib_events.jsonl`, `probes.jsonl` and (in Tier A) `hops.jsonl`.
- **Forwarding state:** it builds a function `F(router, destination, t)` that returns the next-hop set at time t.
- **Prediction per probe packet:** it walks hops from the source at send time, using F at each hop's arrival time.
  - Tier A uses the observed per-hop timestamps.
  - Tier B uses the measured median per-hop latency.
- **ECMP choices are not predicted exactly,** because the kernel's hash isn't modeled. Predict at the set level instead:
  - **delivered:** every branch reaches the destination
  - **blackhole:** every branch hits a router with no route
  - **loop:** a cycle is reachable on every branch
  - **ambiguous:** the branches disagree
- **Two validation metrics (Tier A):**
  1. **Path consistency:** the share of observed hop transitions that are allowed by F at that hop's timestamp.
  2. **Fate agreement:** among non-ambiguous predictions, the share whose observed fate matches.
- **Tier B:** fate agreement only, using receiver sequence numbers.
- Every mismatch is logged with context and classified in FINDINGS.md. Possible reasons: recorder lag, a missed event, ECMP ambiguity, a model bug.

### 5.7 Loss attribution: `labctl report`

For each run:

- packets lost by cause: blackhole, microloop, other or unknown
- the loss window per flow
- the number of microloops, and each loop's duration and the routers involved
- convergence time: from the triggering event until the last route change and until probes stop being lost

### 5.8 Timeline report

- A self-contained static HTML page per run, written by Python with inline SVG and JS, and no external CDN.
- Routers run down the side and time runs across.
- It marks the triggering event, every route change, every lost packet colored by cause, and microloop intervals.
- Commit a few evidence runs, and put a screenshot or GIF at the top of the README.

### 5.9 Safe drain sequencer: `labctl drain`

- **Strategies compared:**
  1. **Abrupt:** shut the link.
  2. **Naive:** raise the cost (or apply a BGP graceful drain), then shut immediately.
  3. **Sequenced:** raise the cost or drain, wait until the recorder shows **no route changes on any router for a quiet period**, and wait until the link's traffic counters are near zero; then shut.
- **The eBGP drain must work in both directions:**
  - lower the preference of routes received over the link (local-pref, or the RFC 8326 GRACEFUL_SHUTDOWN community)
  - prepend the router's own prefixes towards the peer
  - Check the exact FRR syntax for the pinned version, and write an ADR on why both directions are needed.
- Undrain is sequenced the same way. Link recovery is an event worth measuring, not a free action.

### 5.10 Monitoring export

The recorder and tracer expose Prometheus metrics:

- `fib_changes_total{router}`
- `probe_loss_total{cause}`
- `tracer_events_lost_total`
- `recorder_overruns_total`
- `last_convergence_seconds`

Ship a small Prometheus config to scrape them. This is optional during experiments.

---

## 6. Fault catalog: `labctl run --event ...` (seeded)

| Event | How |
|---|---|
| `carrier_down` | `ip link set <if> down` on one end; the veth peer sees carrier loss, so detection is immediate |
| `silent_down` | `tc netem loss 100%` on one direction; detection relies on BFD or protocol timers, like a real one-sided fiber fault |
| `link_up` | restore a downed link (recovery) |
| `node_down` | stop routing on a router (stop the FRR daemons), keeping its interfaces up |
| `drain` | run one of the 5.9 strategies |

Every run writes `run.json` with the topology, mode, timers, event, location, seed, event timestamp and validity flags.

---

## 7. Experiments (FINDINGS.md and BENCHMARKS.md)

Each experiment has a script in `bench/`, a fixed trial count and raw output in `results/`. Report median, p95 and max. Predict nothing.

| ID | Experiment | Trials |
|---|---|---|
| E0 | Instrument overhead and lag: max probe rate with zero tracer loss; probe-path CPU cost with the tracer on vs off; recorder receipt lag (bounded with the kprobe cross-check if available) | 10 per setting |
| E1 | Bring-up time to the first passing `verify`, for every topology-mode pair | 10 each |
| E2 | Replay fidelity: path consistency and fate agreement across all experiment runs, plus a mismatch breakdown | all runs |
| E3 | Failure matrix: topology x mode x event (`carrier_down`, `silent_down`, `link_up`, `node_down`) x BFD on/off; packets lost by cause, loss window, microloop count and duration | 20 per cell |
| E4 | SPF timer skew on T2: microloop occurrence and duration as the skew between routers' SPF delays grows (labeled as emulated heterogeneity) | 20 per setting |
| E5 | Drain strategies (abrupt vs naive vs sequenced) in every mode: packets lost by cause | 20 per cell |

Trim cells that the Codespace can't finish in reasonable time, and say which were trimmed and why. Record CPU load during each run.

**FINDINGS.md** is written like a short paper:

- the question
- the method
- the results, with tables and links to timeline reports
- surprises
- mismatches between prediction and observation, and their explanations
- limits
- what would change on real hardware

If a result looks like an FRR behavior worth reporting upstream, write a minimal reproduction in `repro/` and note it. I'll decide whether to file an issue.

---

## 8. Tests and CI

- **Unit tests:**
  - generator validation, golden files and determinism
  - probe payload encode/decode
  - nexthop-group resolution in the recorder (with recorded netlink fixtures)
  - replay engine on hand-built timelines with known answers: blackhole, two-router loop, ECMP ambiguity, mid-path route change
  - loss attribution
  - drain-sequencer quiet-period logic
- **Calibration tests:** 5.5, rerunnable via `make calibrate`.
- **GitHub Actions integration** (containerlab runs on `ubuntu-latest` with sudo):
  - bring up T1 in `ebgp` mode, run `verify`, run one `carrier_down` run with the recorder and prober
  - check that the replay produces a report
  - run the tracer only if the runner kernel passes the eBPF checks; otherwise skip it with a logged reason
  - keep it under about 10 minutes
- `TESTING.md` lists every test group, how to run it and the latest pass counts.

---

## 9. Repo layout

```
convergence-microscope/
  .devcontainer/devcontainer.json
  intent/                 t1-leafspine.yaml  t2-mesh.yaml  examples/
  labgen/                 model.py ipam.py render.py templates/
  labctl/                 cli.py lab.py verify.py drift.py snapshot.py events.py drain.py report.py timeline/
  go/cmd/prober/  go/cmd/recorder/  go/cmd/tracer/  go/cmd/replay/  go/internal/
  bpf/                    tracer.bpf.c  calib.bpf.c
  images/host/Dockerfile
  bench/                  e0_overhead.py ... e5_drains.py
  scripts/                preflight.sh calibrate.sh
  results/  reports/  repro/
  docs/                   DESIGN.md RUNBOOK.md decisions.md
  README.md  FINDINGS.md  BENCHMARKS.md  TESTING.md
```

---

## 10. Phases

| Phase | Deliverable | Done when |
|---|---|---|
| P0 | Devcontainer, preflight, eBPF gate, host image | `results/preflight.json` committed; tier decided in `reports/phase0.md` |
| P1 | Intent model, generator, T1 in `ebgp` mode, `up`/`down`/`verify`/`snapshot` | `verify` passes; golden and determinism tests green |
| P2 | `ospf` and `isis` modes, BFD, T2 mesh, drift `diff` | `verify` passes for every topology-mode pair; E1 measured |
| P3 | Prober and route recorder (nexthop-aware) | Recorder calibration passes; probes run clean at the target rate |
| P4 | eBPF tracer and full calibration (Tier A only) | Blackhole and loop calibration pass; E0 measured |
| P5 | Replay engine, loss attribution, timeline report | Known-answer tests pass; first E2 numbers on a pilot run |
| P6 | Event harness and experiment matrix | E2, E3 and E4 measured |
| P7 | Drain sequencer and Prometheus export | E5 measured |
| P8 | README, FINDINGS, BENCHMARKS, TESTING, DESIGN, RUNBOOK | Every README claim maps to a test or a results file |

**The minimum that is resume-worthy is P0 through P6.** P7 adds the mitigation story; P8 makes it presentable.

---

## 11. DESIGN.md must cover

- Why one shared kernel gives a shared clock and full packet visibility, and why real networks can't do this.
- How blackholes and microloops form during convergence, with an example from the T2 mesh.
- Why `carrier_down` and `silent_down` behave differently, and what BFD changes.
- Why FRR's kernel nexthop groups matter for recording, and how the recorder handles them.
- Why ECMP fates are predicted at the set level, and what the ambiguous class means.
- How drop-reason codes were calibrated, not assumed.
- Why the eBGP drain must act in both directions, and what RFC 8326 does.
- Why the sequenced drain waits for routes to stop changing, not for a fixed timer.
- The threats to validity: recorder lag, emulated timer skew, single-VM CPU contention, and what real hardware would change (hardware FIB programming time, separate clocks).

---

## 12. Resume bullets (templates only; fill in after measuring)

Every `[ ]` is a placeholder. A bullet must not be used until its value comes from `results/`. Each bullet is 15-19 words.

- Built an eBPF convergence tracer reconstructing every probe packet's hop-by-hop path across emulated FRR networks during failures.
- Attributed [N] lost packets to blackholes or microloops, with FIB-timeline predictions matching observed packet fates [X]% of the time.
- Measured convergence loss across BGP, OSPF, and IS-IS for [N] failure types, finding [finding] through per-packet attribution.
- Cut drain-related packet loss from [X] to [Y] by sequencing cost-out, FIB quiescence checks, and shutdown across [N] trials.
- Calibrated kernel drop-reason classification against constructed blackholes and loops before trusting it in [N] experiment runs.

Header line: `Convergence Microscope | Go, eBPF, Python, FRRouting (BGP, OSPF, IS-IS), containerlab | github.com/ritulrashi/convergence-microscope`
