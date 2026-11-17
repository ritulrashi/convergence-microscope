# Phase 1: intent model, generator, T1 eBGP, labctl basics

## What was built

- `labgen/model.py`: pydantic intent schema (topology, roles, links and costs, ASN scheme, pools, mode, BFD, global and per-router timers). Unknown fields are rejected.
- `labgen/ipam.py`: deterministic allocation from pools: loopbacks /32 in node order, links /31 in link order, host sites `10.10.<site>.0/24` (gateway .1, host .10). The resolved plan is written as `plan.json`.
- `labgen/render.py` and `labgen/templates/`: FRR `frr.conf`, `daemons`, `vtysh.conf` per router and the containerlab topology. eBGP follows RFC 7938: spines share one ASN, each leaf its own, `maximum-paths 64`, `multipath-relax`, leaves export only their own prefixes through prefix-list `LOCAL`. OSPF and IS-IS templates exist and are golden-tested, but are only brought up in phase 2.
- `intent/t1-leafspine.yaml` and `intent/t2-mesh.yaml`.
- `labctl` (Typer): `up`, `down`, `verify` (FRR JSON only: session state, every expected prefix selected and installed, ECMP width, full-mesh host ping; `--wait` retries; `--out` writes a results file), `snapshot` (`ip -j route` and `ip -j nexthop` per router via `nsenter`, stamped with `CLOCK_MONOTONIC`).
- `labctl/results.py`: JSONL results writer whose first record is the machine record.

## Tests (28 passing)

- Golden files for all 6 topology-mode pairs, determinism for all 6, T1 shape, leaf export policy, per-router timer override.
- One failing input per validation rule: duplicate ASN, duplicate router ID, overlapping pools, exhausted loopback pool, exhausted link pool, link to unknown node, leaf with one uplink, unknown field.
- `verify` checks against FRR 10.7.1 JSON captured from the running lab (`tests/fixtures/frr/`): passing case, peer down, missing prefix, ECMP width 1 instead of 2.

## What was measured

From `results/p1/verify-t1-ebgp.jsonl` (commit 8bb1f74, tree clean, 2 vCPU Codespace):

- `verify` passed: 16 BGP sessions Established, 58 prefix checks, ECMP width 2 on every leaf for every remote leaf prefix, 12 of 12 host pings.
- First passing attempt started 6.3 s after `verify` began (attempt 5), following a 4.9 s `containerlab deploy`. One trial only; E1 (phase 2) measures this 10 times per pair.
- `results/p1/snapshot-t1-ebgp.json`: FRR installs ECMP routes through a kernel nexthop group (on leaf1, group 32 = {25 via spine1, 28 via spine2}), which confirms the recorder must resolve nexthop groups (SPEC 5.3).

## What broke

1. The first `verify` failed: spines lacked each other's loopbacks. This is RFC 7938 behavior, so the expectation was wrong, not the network (ADR-006).
2. Syncing the Codespace with `git pull` failed when results produced there were later committed locally. The Codespace is now treated as a runner: reset to `origin/main` before each run, results copied back and committed locally.
3. The first Codespace resume plus `ssh` took several minutes before any command ran, so measurements are always taken in a separate command after the environment is up.
