# Phase 2: OSPF and IS-IS, BFD, T2 mesh, drift `diff`

## What was built

- OSPF (area 0, point-to-point, per-link costs, SPF throttle timers) and IS-IS (level 2, point-to-point, wide metrics, `spf-delay-ietf`) templates; BFD for every mode through a shared `fast` profile; a `--bfd/--no-bfd` override.
- T2: six routers in a ring with chords r1-r4 (cost 25) and r2-r5 (cost 30); hosts on r1, r3 and r4. The costs are chosen so that when r3-r4 fails, r3's new path goes through r2 while r2's old path went through r3 (the microloop the pilot later caught).
- `labctl diff`: running config vs generated config. Templates emit FRR 10.7.1's canonical running-config form, so normalisation only strips FRR's banner lines (ADR-008).
- `bench/p2_verify_all.py`, `bench/e1_bringup.py`.

## What was measured

`results/p2/verify_all.jsonl` (commit 3d23eed, tree clean, 4 vCPU): all 12 combinations (T1, T2) x (eBGP, OSPF, IS-IS) x (BFD off, on) deploy, pass `verify` (T1: 16 sessions, 58 prefix checks, 12 pings; T2: 16 sessions, 54 prefix checks, 6 pings) and show 0 drifted routers right after deploy.

E1, bring-up time to the first passing `verify`, 10 trials each, `results/e1/e1.jsonl`:

| Pair | Median | p95 | Max |
|---|---|---|---|
| T1 eBGP | 8.50 s | 8.76 s | 8.76 s |
| T1 OSPF | 15.06 s | 18.97 s | 18.97 s |
| T1 IS-IS | 37.67 s | 39.11 s | 39.11 s |
| T2 eBGP | 8.22 s | 8.33 s | 8.33 s |
| T2 OSPF | 13.46 s | 13.64 s | 13.64 s |
| T2 IS-IS | 38.67 s | 38.83 s | 38.83 s |

## What broke

1. FRR rewrites its input config (block order, `passive-interface` into per-interface lines, hidden defaults, BFD profile line order, IS-IS metric position). The first drift run flagged every router. Fixed by emitting the canonical form; 12 running configs from clean deploys are test fixtures.
2. IS-IS takes about 38 s to its first passing `verify` in both topologies, against 8 s for eBGP and 13 to 15 s for OSPF. Not yet explained; to be investigated before FINDINGS.
3. Routers kept Docker's default route through the management interface, which would have turned blackholes into leaks. Removed, and `verify` now fails if any router has a default route (ADR-013).
