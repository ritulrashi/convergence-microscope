"""Recorder calibration (SPEC 5.5): scripted route changes with known answers.

Part A, kernel semantics, runs in a dedicated namespace `cm-calib` with no
routing daemon (FRR's zebra adopts kernel nexthop groups and reverts outside
changes within about 10 ms, which would hide what the kernel itself does).
Interfaces: dummies d1, d2 and veth v1 whose peer v2 sits in `cm-calib-peer`,
so carrier loss can be caused by taking v2 down.

Part B, FRR behavior, runs on a T1 eBGP lab with recorders on leaf1 and
spine2: an FRR static ECMP route, and leaf1's uplink to spine2 going down
(admin down on leaf1, carrier loss on spine2) and back up.

For every step, every expected (router, prefix) change must appear with the
right before and after next-hop sets, no other prefix may change unless the
step allows it, and every post-link-down cross-check must find the recorder's
model equal to a fresh kernel dump.

Output: results/calibration/recorder.jsonl plus raw recorder output and the
raw netlink hex (used as Go test fixtures).
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import typer

from bench.common import RESULTS
from labctl import lab as labmod
from labctl.lab import run, sudo_prefix
from labctl.procs import BUILD, build_go, start_recorders, stop_recorders
from labctl.results import ResultWriter
from labctl.verify import verify_wait
from labgen.model import Mode

Key = tuple[str, str]  # (router, prefix)


@dataclass
class Step:
    name: str
    cmds: list[list[str]]
    expect: dict[Key, tuple[list[str], list[str]]]
    settle_s: float = 0.5
    final_only: bool = False
    allow_other: bool = False
    events: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)


def judge(st: Step) -> tuple[bool, list[str]]:
    problems = []
    by: dict[Key, list[dict]] = {}
    for e in st.events:
        if e.get("kind") == "fib":
            by.setdefault((e["router"], e["prefix"]), []).append(e)
    for k, (old, new) in st.expect.items():
        evs = by.get(k, [])
        if not evs:
            problems.append(f"{k}: no event (expected {old} -> {new})")
            continue
        if not st.final_only and len(evs) != 1:
            problems.append(f"{k}: {len(evs)} events, expected 1")
        if evs[0]["old"] != old:
            problems.append(f"{k}: first old {evs[0]['old']} != {old}")
        if evs[-1]["new"] != new:
            problems.append(f"{k}: last new {evs[-1]['new']} != {new}")
    if not st.allow_other:
        extra = sorted(set(by) - set(st.expect))
        if extra:
            problems.append(f"unexpected changes: {extra}")
    for c in st.checks:
        if c["mismatches"]:
            problems.append(f"{c['router']}: model differs from kernel dump: {c['mismatches']}")
    return not problems, problems


# --- part A: kernel semantics in a daemon-free namespace ------------------------

NS, PEER = "cm-calib", "cm-calib-peer"


def sh(*args: str) -> None:
    run([*sudo_prefix(), *args])


def setup_ns() -> None:
    teardown_ns()
    sh("ip", "netns", "add", NS)
    sh("ip", "netns", "add", PEER)
    for i, d in ((1, "d1"), (2, "d2")):
        sh("ip", "-n", NS, "link", "add", d, "type", "dummy")
        sh("ip", "-n", NS, "addr", "add", f"10.99.{i}.1/24", "dev", d)
        sh("ip", "-n", NS, "link", "set", d, "up")
    sh("ip", "-n", NS, "link", "add", "v1", "type", "veth", "peer", "name", "v2", "netns", PEER)
    sh("ip", "-n", NS, "addr", "add", "10.99.3.1/24", "dev", "v1")
    sh("ip", "-n", NS, "link", "set", "v1", "up")
    sh("ip", "-n", PEER, "link", "set", "v2", "up")
    sh("ip", "-n", NS, "link", "set", "lo", "up")


def teardown_ns() -> None:
    for n in (NS, PEER):
        run([*sudo_prefix(), "ip", "netns", "del", n], check=False)


def steps_a() -> list[Step]:
    r = "calib"
    g1, g2, g3 = "10.99.1.2@d1", "10.99.2.2@d2", "10.99.3.2@v1"
    both = sorted([g1, g2])
    ip = ["ip", "-n", NS]
    return [
        Step(
            "static route via gateway",
            [ip + ["route", "add", "192.0.2.1/32", "via", "10.99.1.2", "dev", "d1"]],
            {(r, "192.0.2.1/32"): ([], [g1])},
        ),
        Step(
            "route through a nexthop group",
            [
                ip + ["nexthop", "add", "id", "9001", "via", "10.99.1.2", "dev", "d1"],
                ip + ["nexthop", "add", "id", "9002", "via", "10.99.2.2", "dev", "d2"],
                ip + ["nexthop", "add", "id", "9003", "group", "9001/9002"],
                ip + ["route", "add", "192.0.2.2/32", "nhid", "9003"],
            ],
            {(r, "192.0.2.2/32"): ([], both)},
        ),
        Step(
            "group shrinks (nexthop message only)",
            [ip + ["nexthop", "replace", "id", "9003", "group", "9001"]],
            {(r, "192.0.2.2/32"): (both, [g1])},
        ),
        Step(
            "group member changes gateway",
            [ip + ["nexthop", "replace", "id", "9001", "via", "10.99.2.2", "dev", "d2"]],
            {(r, "192.0.2.2/32"): ([g1], [g2])},
        ),
        Step(
            "route replaced by blackhole",
            [ip + ["route", "replace", "blackhole", "192.0.2.1/32"]],
            {(r, "192.0.2.1/32"): ([g1], ["blackhole"])},
        ),
        Step(
            "route deleted",
            [ip + ["route", "del", "192.0.2.1/32"]],
            {(r, "192.0.2.1/32"): (["blackhole"], [])},
        ),
        Step(
            "nexthop group deleted removes its route",
            [
                ip + ["nexthop", "del", "id", "9003"],
                ip + ["nexthop", "del", "id", "9001"],
                ip + ["nexthop", "del", "id", "9002"],
            ],
            {(r, "192.0.2.2/32"): ([g2], [])},
        ),
        Step(
            "setup: ECMP group over d1 and d2, single nexthop over v1",
            [
                ip + ["nexthop", "add", "id", "9011", "via", "10.99.1.2", "dev", "d1"],
                ip + ["nexthop", "add", "id", "9012", "via", "10.99.2.2", "dev", "d2"],
                ip + ["nexthop", "add", "id", "9013", "group", "9011/9012"],
                ip + ["nexthop", "add", "id", "9014", "via", "10.99.3.2", "dev", "v1"],
                ip + ["route", "add", "192.0.2.4/32", "nhid", "9013"],
                ip + ["route", "add", "192.0.2.5/32", "nhid", "9014"],
                ip + ["route", "add", "192.0.2.6/32", "via", "10.99.3.2", "dev", "v1"],
            ],
            {
                (r, "192.0.2.4/32"): ([], both),
                (r, "192.0.2.5/32"): ([], [g3]),
                (r, "192.0.2.6/32"): ([], [g3]),
            },
        ),
        Step(
            "admin down d2: silent nexthop flush and connected route removal",
            [ip + ["link", "set", "d2", "down"]],
            {
                (r, "192.0.2.4/32"): (both, [g1]),
                (r, "10.99.2.0/24"): (["direct@d2"], []),
            },
        ),
        Step(
            "carrier loss on v1: nexthop objects flushed, inline routes kept",
            [["ip", "-n", PEER, "link", "set", "v2", "down"]],
            {(r, "192.0.2.5/32"): ([g3], [])},
        ),
        Step(
            "carrier back on v1: no FIB change by itself",
            [["ip", "-n", PEER, "link", "set", "v2", "up"]],
            {},
        ),
    ]


# --- part B: FRR on a T1 lab ---------------------------------------------------


def steps_b(lab: labmod.Lab) -> list[Step]:
    leaf1 = lab.plan.router("leaf1")
    up = [i for i in leaf1.ifaces if i.kind == "fabric"]
    (e1, s1), (e2, s2) = (up[0].name, up[0].peer_address), (up[1].name, up[1].peer_address)
    h1, h2 = f"{s1}@{e1}", f"{s2}@{e2}"
    both = sorted([h1, h2])
    remote = []
    for x in lab.plan.routers:
        if x.role == "leaf" and x.name != "leaf1":
            remote += [x.loopback, *x.host_subnets]
    spine2 = lab.plan.router(up[1].peer)
    sp_if = next(i for i in spine2.ifaces if i.peer == "leaf1")
    sp_hop = f"{sp_if.peer_address}@{sp_if.name}"
    leaf1_pfx = [leaf1.loopback, *leaf1.host_subnets]
    vt = ["vtysh", "-c", "configure terminal", "-c"]
    return [
        Step(
            "FRR static ECMP route",
            [vt + [f"ip route 192.0.2.3/32 {s1}"], vt + [f"ip route 192.0.2.3/32 {s2}"]],
            {("leaf1", "192.0.2.3/32"): ([], both)},
            settle_s=2.0,
            final_only=True,
        ),
        Step(
            "FRR static route removed",
            [vt + [f"no ip route 192.0.2.3/32 {s1}"], vt + [f"no ip route 192.0.2.3/32 {s2}"]],
            {("leaf1", "192.0.2.3/32"): (both, [])},
            settle_s=2.0,
            final_only=True,
        ),
        Step(
            "leaf1 uplink admin down (spine2 sees carrier loss)",
            [["ip", "link", "set", e2, "down"]],
            {
                **{("leaf1", p): (both, [h1]) for p in sorted(remote)},
                ("leaf1", spine2.loopback): ([h2], []),
                **{("spine2", p): ([sp_hop], []) for p in leaf1_pfx},
            },
            settle_s=3.0,
            final_only=True,
            allow_other=True,
        ),
        Step(
            "leaf1 uplink back up restores ECMP",
            [["ip", "link", "set", e2, "up"]],
            {
                **{("leaf1", p): ([h1], both) for p in sorted(remote)},
                ("leaf1", spine2.loopback): ([], [h2]),
                **{("spine2", p): ([], [sp_hop]) for p in leaf1_pfx},
            },
            settle_s=12.0,
            final_only=True,
            allow_other=True,
        ),
    ]


def run_steps(plan: list[Step], do) -> list[tuple[int, int]]:
    bounds = []
    for st in plan:
        t0 = time.monotonic_ns()
        for c in st.cmds:
            do(c)
        time.sleep(st.settle_s)
        bounds.append((t0, time.monotonic_ns()))
    return bounds


def attach(plan: list[Step], bounds, outs: list[Path]) -> None:
    rows = []
    for p in outs:
        rows += [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    for st, (a, b) in zip(plan, bounds, strict=True):
        st.events = [e for e in rows if e.get("kind") in ("fib", "link") and a <= e["t"] < b]
        st.checks = [e for e in rows if e.get("kind") == "check" and a <= e["t"] < b]


def start_ns_recorder(out_dir: Path) -> subprocess.Popen:
    out_dir.mkdir(parents=True, exist_ok=True)
    ready = out_dir / ".ready_calib"
    ready.unlink(missing_ok=True)
    p = subprocess.Popen(
        [
            *sudo_prefix(),
            str(BUILD / "recorder"),
            "-router",
            "calib",
            "-netns",
            f"/run/netns/{NS}",
            "-out",
            str(out_dir / "fib_calib.jsonl"),
            "-raw",
            str(out_dir / "fib_calib.raw"),
            "-ready",
            str(ready),
        ],
        stderr=subprocess.PIPE,
        text=True,
    )
    while not ready.exists():
        if p.poll() is not None:
            raise RuntimeError(p.stderr.read())
        time.sleep(0.05)
    ready.unlink()
    return p


def main(out_dir: Path = RESULTS / "calibration") -> None:
    build_go()
    work = out_dir / "recorder"
    results: list[tuple[str, int, Step, bool, list[str]]] = []
    stats: list[dict] = []

    # Part A
    setup_ns()
    plan_a = steps_a()
    p = start_ns_recorder(work)
    try:
        bounds = run_steps(plan_a, lambda c: sh(*c))
    finally:
        from labctl.procs import Recorder

        stats += stop_recorders([Recorder("calib", work / "fib_calib.jsonl", p)])
        teardown_ns()
    attach(plan_a, bounds, [work / "fib_calib.jsonl"])
    for i, st in enumerate(plan_a):
        ok, problems = judge(st)
        results.append(("A", i, st, ok, problems))

    # Part B
    lab = labmod.load(Path("intent/t1-leafspine.yaml"), Mode.ebgp, False)
    labmod.up(lab)
    try:
        res, _, _ = verify_wait(lab, 120)
        if not res.ok:
            raise SystemExit(f"lab did not verify: {res.failures}")
        plan_b = steps_b(lab)
        recs = start_recorders(lab, work, ["leaf1", "spine2"], raw=True)
        try:
            bounds = run_steps(
                plan_b,
                lambda c: lab.exec("leaf1", *c) if c[0] == "vtysh" else lab.netns_exec("leaf1", *c),
            )
        finally:
            stats += stop_recorders(recs)
        attach(plan_b, bounds, [r.out for r in recs])
        for i, st in enumerate(plan_b):
            ok, problems = judge(st)
            results.append(("B", i, st, ok, problems))
    finally:
        labmod.down(lab)

    passed = sum(1 for *_, ok, _ in results if ok)
    with ResultWriter(out_dir / "recorder.jsonl") as w:
        for part, i, st, ok, problems in results:
            w.write(
                {
                    "record": "step",
                    "part": part,
                    "step": i,
                    "name": st.name,
                    "pass": ok,
                    "problems": problems,
                    "expected": [
                        {"router": k[0], "prefix": k[1], "old": o, "new": n}
                        for k, (o, n) in st.expect.items()
                    ],
                    "observed": [e for e in st.events if e["kind"] == "fib"],
                    "checks": st.checks,
                }
            )
            typer.echo(f"{'PASS' if ok else 'FAIL'} {part}{i} {st.name} {problems or ''}")
        for s in stats:
            w.write({"record": "recorder_stats", **s})
        valid = all(s.get("valid") for s in stats)
        w.write(
            {"record": "summary", "steps": len(results), "passed": passed, "recorders_valid": valid}
        )
    typer.echo(f"{passed}/{len(results)} steps passed; recorders valid: {valid}")
    if passed != len(results) or not valid:
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
