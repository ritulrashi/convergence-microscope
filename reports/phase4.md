# Phase 4: eBPF tracer and full calibration (Tier A)

## What was built

- `bpf/tracer.bpf.c` and `go/cmd/tracer`: `netif_receive_skb` (each hop's ingress) and `kfree_skb` (drops with reason), in-kernel filtering on UDP port 7777 plus the probe magic, ring buffer with failed-reservation counting, a netns inode to node name table, a last-ingress map for drops without a device, and the drop call site resolved to a kernel function name (ADR-017).
- `bench/calib_tracer.py`: clean path, blackhole route, unreachable route, no route, two-router loop. It writes `results/calibration/drop_reasons.json`, the classifier's only source of reason codes.
- `bpf/lag.bpf.c` and `go/cmd/lagprobe`: kprobes on `rtnl_notify`, `fib_table_insert`, `fib_table_delete` (ADR-016). `bench/e0_overhead.py`.

## What was measured

Tracer calibration (`results/calibration/tracer.jsonl`), 200 probes per case, 5 of 5 pass, 0 events lost:

| Case | Result | Drop class |
|---|---|---|
| clean | 200 of 200 seen at all 4 hops; TTL falls as time rises on every probe | none |
| blackhole route | all dropped once at leaf1 | `NOT_SPECIFIED` (2) in `ip_error` |
| unreachable route | all dropped once at leaf1 | `NOT_SPECIFIED` (2) in `ip_error` |
| no route | all dropped once at leaf1 | `IP_INNOROUTES` (70) in `ip_error` |
| leaf1/spine1 loop | every probe seen 64 times alternating, then dropped | `IP_INHDR` (11) in `ip_forward` |

E0 (`results/e0/e0.jsonl`, 10 trials per setting, T1 all 12 pairs, 4 vCPU):

- Tracer loss: 0 events lost at every rate tried, 1,000 to 8,000 pps per pair (up to 1.9 million receive events per 5 s trial). The probers, not the tracer, are the limit: with stats-only logging their schedule stayed within 5 ms in 6 of 10 trials at 1,000 pps and in none at 2,000 pps and above.
- CPU cost at 1,000 pps per pair, 10 s: whole-VM utilisation median 25.6% with the tracer off, 36.9% on. The receive program's own run time is about 2.9 to 4.2 us per call (median per setting, measured with `kernel.bpf_stats_enabled=1`, which itself adds overhead).
- Recorder receipt lag after `rtnl_notify` (500 route changes per condition): idle median 44 us, p95 280 us, max 579 us; with probes, tracer and recorders running, median 44 us, p95 339 us, max 2.24 ms. Medians against `fib_table_insert/delete` are 67 us idle and 72 us loaded.

## What broke

1. Blackhole and unreachable routes drop with the generic `NOT_SPECIFIED` code; classification needed the kernel function too (ADR-017).
2. The tracer did not stop on SIGTERM: a read deadline set while `Read` is blocked is ignored, so it kept running into the next calibration case and wrote that case's events. Fixed with a rolling deadline.
3. `pkill -f build/tracer` matched the shell running it and killed the session; processes are now matched by exact name.
