"""Recorder calibration (SPEC 5.5): scripted route changes with known answers.

On a running T1 eBGP lab, record leaf1 while applying route and nexthop
changes with `ip` (inside leaf1's netns) and FRR, and check that every
expected change appears in the recorder output with the right before and
after next-hop sets. Step boundaries are CLOCK_MONOTONIC, the recorder's clock.

Output: results/calibration/recorder.jsonl (machine record, one record per
step, a summary), plus the recorder's own output and raw netlink hex.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import typer

from bench.common import RESULTS
from labctl import lab as labmod
from labctl.procs import build_go, start_recorders, stop_recorders
from labctl.results import ResultWriter
from labgen.model import Mode


@dataclass
class Step:
    name: str
    cmds: list[list[str]]  # each: ["ip", ...] in netns, or ["vtysh", ...]
    expect: dict[str, tuple[list[str], list[str]]]  # prefix -> (old, new)
    settle_s: float = 0.5
    final_only: bool = False  # compare only the last new set (multi-event steps)
    allow_other: bool = False  # other prefixes may change too
    events: list[dict] = field(default_factory=list)


def steps(e1: str, e2: str, s1: str, s2: str, remote: list[str], spine2_lo: str) -> list[Step]:
    """e1/e2: leaf1's uplink names; s1/s2: spine1/spine2 link addresses."""
    h1, h2, both = f"{s1}@{e1}", f"{s2}@{e2}", sorted([f"{s1}@{e1}", f"{s2}@{e2}"])
    ip = ["ip"]
    return [
        Step(
            "static route via gateway",
            [ip + ["route", "add", "192.0.2.1/32", "via", s1, "dev", e1]],
            {"192.0.2.1/32": ([], [h1])},
        ),
        Step(
            "route through a nexthop group",
            [
                ip + ["nexthop", "add", "id", "9001", "via", s1, "dev", e1],
                ip + ["nexthop", "add", "id", "9002", "via", s2, "dev", e2],
                ip + ["nexthop", "add", "id", "9003", "group", "9001/9002"],
                ip + ["route", "add", "192.0.2.2/32", "nhid", "9003"],
            ],
            {"192.0.2.2/32": ([], both)},
        ),
        Step(
            "group shrinks (nexthop message only)",
            [ip + ["nexthop", "replace", "id", "9003", "group", "9001"]],
            {"192.0.2.2/32": (both, [h1])},
        ),
        Step(
            "group member changes gateway",
            [ip + ["nexthop", "replace", "id", "9001", "via", s2, "dev", e2]],
            {"192.0.2.2/32": ([h1], [h2])},
        ),
        Step(
            "route replaced by blackhole",
            [ip + ["route", "replace", "blackhole", "192.0.2.1/32"]],
            {"192.0.2.1/32": ([h1], ["blackhole"])},
        ),
        Step(
            "route deleted",
            [ip + ["route", "del", "192.0.2.1/32"]],
            {"192.0.2.1/32": (["blackhole"], [])},
        ),
        Step(
            "nexthop group deleted removes its route",
            [
                ip + ["nexthop", "del", "id", "9003"],
                ip + ["nexthop", "del", "id", "9001"],
                ip + ["nexthop", "del", "id", "9002"],
            ],
            {"192.0.2.2/32": ([h2], [])},
        ),
        Step(
            "FRR static ECMP route",
            [
                ["vtysh", "-c", "configure terminal", "-c", f"ip route 192.0.2.3/32 {s1}"],
                ["vtysh", "-c", "configure terminal", "-c", f"ip route 192.0.2.3/32 {s2}"],
            ],
            {"192.0.2.3/32": ([], both)},
            settle_s=2.0,
            final_only=True,
        ),
        Step(
            "FRR static route removed",
            [
                ["vtysh", "-c", "configure terminal", "-c", f"no ip route 192.0.2.3/32 {s1}"],
                ["vtysh", "-c", "configure terminal", "-c", f"no ip route 192.0.2.3/32 {s2}"],
            ],
            {"192.0.2.3/32": (both, [])},
            settle_s=2.0,
            final_only=True,
        ),
        Step(
            "uplink carrier down shrinks every ECMP prefix",
            [ip + ["link", "set", e2, "down"]],
            {**{p: (both, [h1]) for p in remote}, spine2_lo: ([h2], [])},
            settle_s=3.0,
            final_only=True,
            allow_other=True,
        ),
        Step(
            "uplink back up restores ECMP",
            [ip + ["link", "set", e2, "up"]],
            {**{p: ([h1], both) for p in remote}, spine2_lo: ([], [h2])},
            settle_s=12.0,
            final_only=True,
            allow_other=True,
        ),
    ]


def judge(step: Step) -> tuple[bool, list[str]]:
    problems = []
    fib = [e for e in step.events if e.get("kind") == "fib"]
    by: dict[str, list[dict]] = {}
    for e in fib:
        by.setdefault(e["prefix"], []).append(e)
    for p, (old, new) in step.expect.items():
        evs = by.get(p, [])
        if not evs:
            problems.append(f"{p}: no event (expected {old} -> {new})")
            continue
        if not step.final_only and len(evs) != 1:
            problems.append(f"{p}: {len(evs)} events, expected 1")
        if evs[0]["old"] != old:
            problems.append(f"{p}: first old {evs[0]['old']} != {old}")
        if evs[-1]["new"] != new:
            problems.append(f"{p}: last new {evs[-1]['new']} != {new}")
    if not step.allow_other:
        extra = sorted(set(by) - set(step.expect))
        if extra:
            problems.append(f"unexpected prefixes changed: {extra}")
    return not problems, problems


def main(out_dir: Path = RESULTS / "calibration") -> None:
    build_go()
    lab = labmod.load(Path("intent/t1-leafspine.yaml"), Mode.ebgp, False)
    labmod.up(lab)
    from labctl.verify import verify_wait

    res, _, _ = verify_wait(lab, 120)
    if not res.ok:
        raise SystemExit(f"lab did not verify: {res.failures}")
    leaf1 = lab.plan.router("leaf1")
    up = [i for i in leaf1.ifaces if i.kind == "fabric"]
    (e1, s1), (e2, s2) = (up[0].name, up[0].peer_address), (up[1].name, up[1].peer_address)
    remote = []
    for r in lab.plan.routers:
        if r.role == "leaf" and r.name != "leaf1":
            remote += [r.loopback, *r.host_subnets]
    spine2_lo = lab.plan.router(up[1].peer).loopback
    plan = steps(e1, e2, s1, s2, sorted(remote), spine2_lo)

    work = out_dir / "recorder"
    recs = start_recorders(lab, work, ["leaf1"], raw=True)
    bounds = []
    try:
        for st in plan:
            t0 = time.monotonic_ns()
            for c in st.cmds:
                if c[0] == "vtysh":
                    lab.exec("leaf1", *c)
                else:
                    lab.netns_exec("leaf1", *c)
            time.sleep(st.settle_s)
            bounds.append((t0, time.monotonic_ns()))
    finally:
        stats = stop_recorders(recs)
        if len(bounds) != len(plan):
            labmod.down(lab)

    events = [json.loads(x) for x in (work / "fib_leaf1.jsonl").read_text().splitlines()]
    for st, (a, b) in zip(plan, bounds, strict=True):
        st.events = [e for e in events if e.get("kind") in ("fib", "link") and a <= e["t"] < b]

    passed = 0
    with ResultWriter(out_dir / "recorder.jsonl") as w:
        for i, st in enumerate(plan):
            ok, problems = judge(st)
            passed += ok
            w.write(
                {
                    "record": "step",
                    "step": i,
                    "name": st.name,
                    "pass": ok,
                    "problems": problems,
                    "expected": {p: {"old": o, "new": n} for p, (o, n) in st.expect.items()},
                    "observed": [e for e in st.events if e["kind"] == "fib"],
                }
            )
            typer.echo(f"{'PASS' if ok else 'FAIL'} {i} {st.name} {problems or ''}")
        w.write({"record": "recorder_stats", **stats[0]})
        w.write(
            {
                "record": "summary",
                "steps": len(plan),
                "passed": passed,
                "recorder_valid": stats[0].get("valid", False),
            }
        )
    labmod.down(lab)
    if passed != len(plan) or not stats[0].get("valid"):
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
