# Phase 5: replay engine, loss attribution, timeline report

## What was built

- `go/internal/replay`: per-router, per-prefix FIB timelines from the recorder (`init` records are the starting snapshot); `F(router, dst, t)` by longest match over prefixes that exist at t; set-level prediction over every ECMP branch with per-hop arrival times (observed in Tier A); forwarding-loop intervals per destination (strongly connected components at every change time).
- `go/cmd/replay`: predictions for every lost or predicted-lost probe, mismatches with a first automatic class, FIB loops, and the two metrics. A third metric, FIB-only fate agreement, leaves out packets dropped for reasons the FIB cannot show (netem on a silently failed link).
- `labctl run` (seeded event harness, ADR-014, ADR-015, ADR-019), `labctl report` (`report.json`: loss by cause, loss window per flow, microloops, convergence; `timeline.html`: self-contained SVG and JS).

## Tests

- Replay known-answer tests: delivered, blackhole (no route and blackhole route), two-router loop and its interval, ECMP ambiguity, mid-path route change read at the hop's arrival time, a short loop the packet survives and a long one it does not, longest-prefix fallback, transition check.
- Loss attribution on a hand-built run directory (Tier A observed causes, Tier B predicted causes, windows, microloops, convergence) and a self-contained timeline.

## First E2 numbers (pilot)

T2 OSPF, 500 pps per pair, 8 s, event at 2 s, one run per event, raw data kept (`results/pilot/`):

| Event | Lost (of 24,000) | Cause | Last loss after event | Fate agreement | FIB-only agreement | Path consistency |
|---|---|---|---|---|---|---|
| carrier_down r3-r4 | 64 | 62 blackhole, 1 microloop, 1 other | 61 ms | 0.99988 | 0.99992 | 0.99990 |
| silent_down r3-r4 | 1,440 | 1,440 other (netem) | 2,878 ms | 0.94 | 1.0 | 1.0 |
| link_up r3-r4 | 0 | none | none | 1.0 | 1.0 | 0.99998 |
| node_down r3 | 3,672 | 3,672 blackhole | continues to end of run | 1.0 | 1.0 | 1.0 |

- The carrier_down run contains the microloop T2 was designed for: F has an r2-r3 loop towards h4 for 1.38 ms, starting 61 ms after the link went down, and the tracer saw one probe bounce between r3 and r2 64 times before dying of TTL expiry at r2. Replay predicted "blackhole" for that probe; it reached r3 just before the recorder logged r3's new route (recorder lag, see E0).
- node_down freezes r3's control plane. r3 still forwards, but once its neighbors time out (OSPF dead interval 3 s) they withdraw h3's subnet, which is only reachable through r3, so h3 is cut off for the rest of the run. The report flags this as ongoing loss.

## What broke

1. The event time was taken before the slow part of firing it: the first pilot showed loss starting 254 ms "after" the event. Fixed (ADR-019).
2. `labctl run` assumes the lab is already up; the first pilot attempt failed on that. To be documented in RUNBOOK (phase 8).
