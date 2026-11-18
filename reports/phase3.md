# Phase 3: prober and nexthop-aware route recorder

## What was built

- `go/cmd/prober`: per-host UDP prober. Fixed schedule per (src, dst) pair, source port rotated over 4 ports (ADR-009), shared CLOCK_MONOTONIC start, per-packet JSONL, lateness histogram; a run is invalid if any send is more than 5 ms late.
- `go/cmd/recorder` and `go/internal/rtnl`: one process per router netns (`setns`), raw rtnetlink parsing for routes, nexthop objects and links, resolution of nexthop groups into per-prefix next-hop sets, ENOBUFS detection with resync, and a model of the kernel's silent flush on link down (ADR-010), cross-checked against a fresh dump 100 ms after every link down.
- Recorder calibration in two parts (ADR-011): kernel semantics in a daemon-free namespace, FRR behavior on a T1 router.

## What was measured

- Recorder calibration, `results/calibration/recorder.jsonl` (commit 3d23eed): 15 of 15 steps pass, including nexthop-group shrink, member change, group delete, admin down and carrier loss. 4 post-link-down cross-checks, 0 mismatches. No overruns.
- Replaying the raw netlink captured during calibration reproduces the live recorder output record for record (`go/cmd/recorder/replay_test.go`).
- Clean probing, `results/p3/probes_clean.jsonl` (4 vCPU, T1 all 12 pairs, 1,000 pps per pair, 10 s, recorders on): 3 of 3 trials clean, 360,000 probes, 0 lost, 0 duplicates, 0 FIB changes, max send lateness 3.6 ms.

## What broke

1. The recorder missed every link-down FIB change: the kernel flushes nexthops without netlink messages. Fixed by modelling the flush (ADR-010).
2. zebra adopts kernel nexthop groups and reverts outside edits within about 10 ms, so calibrating on a router measured zebra (ADR-011).
3. On 2 vCPUs, all-pairs probing with recorders on lost no packets, but every trial had sends 5 to 12 ms late (`results/p3/two_core/`). Experiments run on 4 vCPUs (ADR-012).
4. Later, with the tracer also on, 1,000 pps per pair was valid in only 8 of 10 runs; experiments use 500 pps (ADR-018).
