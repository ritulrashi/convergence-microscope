"""Tracer calibration (SPEC 5.5): constructed failures with known answers.

On a T1 eBGP lab, h1 probes h2 (100 pps, 2 s) through each case while the
tracer runs:

  clean        every probe is seen at every hop with TTL falling as time rises
               (clock sanity: hop timestamps increase along the path)
  blackhole    `ip route add blackhole <h2>/32` on leaf1: every probe dropped
               at leaf1, never seen past it
  unreachable  `ip route add unreachable <h2>/32` on leaf1: same, other type
  no_route     h1 probes an address no router has a route for: dropped at leaf1
  loop         leaf1 and spine1 point <h2>/32 at each other: each probe seen
               repeatedly at both with falling TTL, then a TTL-expiry drop

The drop-reason code(s) each case produces on this kernel are written to
results/calibration/drop_reasons.json, which the loss classifier reads. They
are never taken from documentation.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

import typer

from bench.common import RESULTS
from labctl import lab as labmod
from labctl.procs import build_go, read_hops, start_probers, start_tracer, stop_tracer
from labctl.results import ResultWriter
from labctl.verify import verify_wait
from labgen.model import Mode

RATE, DUR = 100, 2.0
SRC, DST = "h1", "h2"


def probe_fake(lab: labmod.Lab, ip: str, fake_id: int) -> int:
    """h1 probes an address no host owns; return the number sent."""
    start = time.monotonic_ns() + 300_000_000
    lab.exec(
        SRC,
        "prober",
        "-id",
        "1",
        "-dst",
        f"{fake_id}={ip}",
        "-rate",
        str(RATE),
        "-start-at",
        str(start),
        "-duration",
        f"{DUR}s",
        "-grace",
        "1s",
        "-out",
        "/tmp/fake.jsonl",
        timeout=DUR + 30,
    )
    return int(DUR * RATE)


def probe_pair(lab: labmod.Lab) -> int:
    pr = start_probers(lab, RATE, DUR, pairs=[(SRC, DST)], grace_s=1.0)
    for p in pr.procs.values():
        p.wait(timeout=DUR + 30)
    return int(DUR * RATE)


def by_probe(hops: list[dict], src: int, dst: int) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = defaultdict(list)
    for h in hops:
        if h["src"] == src and h["dst"] == dst:
            out[h["seq"]].append(h)
    for v in out.values():
        v.sort(key=lambda h: h["t"])
    return out


def ttl_falls_with_time(evs: list[dict]) -> bool:
    rx = [e for e in evs if e["ev"] == "rx"]
    return all(a["ttl"] > b["ttl"] and a["t"] < b["t"] for a, b in zip(rx, rx[1:], strict=False))


def judge_clean(probes: dict[int, list[dict]], sent: int, path: list[str]) -> dict:
    full = sum(
        1
        for evs in probes.values()
        if [e["node"] for e in evs if e["ev"] == "rx"][:1] == [path[0]]
        and [e["node"] for e in evs if e["ev"] == "rx"][-1:] == [path[-1]]
        and len([e for e in evs if e["ev"] == "rx"]) == len(path)
    )
    mono = sum(1 for evs in probes.values() if ttl_falls_with_time(evs))
    drops = sum(1 for evs in probes.values() for e in evs if e["ev"] == "drop")
    ok = full == sent and mono == len(probes) and drops == 0
    return {
        "pass": ok,
        "sent": sent,
        "probes_seen": len(probes),
        "full_path": full,
        "clock_sane": mono,
        "drops": drops,
        "expected_path_len": len(path),
    }


def judge_drop_at(probes: dict[int, list[dict]], sent: int, node: str) -> dict:
    reasons: Counter = Counter()
    good = 0
    for evs in probes.values():
        drops = [e for e in evs if e["ev"] == "drop"]
        beyond = [e for e in evs if e["ev"] == "rx" and e["node"] not in ("leaf1",)]
        if len(drops) == 1 and drops[0]["node"] == node and not beyond:
            good += 1
        for d in drops:
            reasons[(d["reason"], d["reason_name"])] += 1
    ok = good == sent and len(reasons) == 1
    return {
        "pass": ok,
        "sent": sent,
        "probes_seen": len(probes),
        "dropped_once_at_expected_node": good,
        "reasons": [{"code": c, "name": n, "count": k} for (c, n), k in sorted(reasons.items())],
    }


def judge_loop(probes: dict[int, list[dict]], sent: int, pair: set[str]) -> dict:
    reasons: Counter = Counter()
    good = 0
    visits = []
    for evs in probes.values():
        rx = [e for e in evs if e["ev"] == "rx"]
        drops = [e for e in evs if e["ev"] == "drop"]
        cnt = Counter(e["node"] for e in rx if e["node"] in pair)
        visits.append(sum(cnt.values()))
        ok = (
            all(cnt[n] >= 2 for n in pair)
            and ttl_falls_with_time(evs)
            and len(drops) == 1
            and drops[0]["node"] in pair
            and drops[-1]["t"] >= rx[-1]["t"]
        )
        good += ok
        for d in drops:
            reasons[(d["reason"], d["reason_name"])] += 1
    return {
        "pass": good == sent and len(reasons) == 1,
        "sent": sent,
        "probes_seen": len(probes),
        "loop_signature": good,
        "visits_in_loop_min": min(visits) if visits else 0,
        "visits_in_loop_max": max(visits) if visits else 0,
        "reasons": [{"code": c, "name": n, "count": k} for (c, n), k in sorted(reasons.items())],
    }


def main(out_dir: Path = RESULTS / "calibration") -> None:
    build_go()
    lab = labmod.load(Path("intent/t1-leafspine.yaml"), Mode.ebgp, False)
    labmod.up(lab)
    res, _, _ = verify_wait(lab, 120)
    if not res.ok:
        raise SystemExit(f"lab did not verify: {res.failures}")
    ids = {h.name: h.site for h in lab.plan.hosts}
    h2ip = next(h.address.split("/")[0] for h in lab.plan.hosts if h.name == DST)
    leaf1, spine1 = lab.plan.router("leaf1"), lab.plan.router("spine1")
    l1_to_s1 = next(i for i in leaf1.ifaces if i.peer == "spine1")
    s1_to_l1 = next(i for i in spine1.ifaces if i.peer == "leaf1")
    work = out_dir / "tracer"
    cases = []

    def case(name: str, setup, teardown, run_probes, judge):
        for c in setup:
            c()
        tr = start_tracer(lab, work / f"hops_{name}.jsonl")
        try:
            sent = run_probes()
            time.sleep(0.5)
        finally:
            stats = stop_tracer(tr)
            for c in teardown:
                c()
        hops = read_hops(tr.out)
        r = judge(hops, sent)
        r.update({"record": "case", "case": name, "tracer": stats})
        r["pass"] = r["pass"] and stats.get("valid", False)
        cases.append(r)
        typer.echo(
            f"{'PASS' if r['pass'] else 'FAIL'} {name}: "
            + json.dumps({k: v for k, v in r.items() if k not in ("record", "tracer")})
        )

    def nx(node: str, *args: str):
        return lambda: lab.netns_exec(node, *args)

    try:
        case(
            "clean",
            [],
            [],
            lambda: probe_pair(lab),
            lambda hops, sent: judge_clean(
                by_probe(hops, ids[SRC], ids[DST]),
                sent,
                # The middle hop is spine1 or spine2 (ECMP); first, last and count are checked.
                ["leaf1", "spine1|spine2", "leaf2", DST],
            ),
        )
        case(
            "blackhole",
            [nx("leaf1", "ip", "route", "add", "blackhole", f"{h2ip}/32")],
            [nx("leaf1", "ip", "route", "del", "blackhole", f"{h2ip}/32")],
            lambda: probe_pair(lab),
            lambda hops, sent: judge_drop_at(by_probe(hops, ids[SRC], ids[DST]), sent, "leaf1"),
        )
        case(
            "unreachable",
            [nx("leaf1", "ip", "route", "add", "unreachable", f"{h2ip}/32")],
            [nx("leaf1", "ip", "route", "del", "unreachable", f"{h2ip}/32")],
            lambda: probe_pair(lab),
            lambda hops, sent: judge_drop_at(by_probe(hops, ids[SRC], ids[DST]), sent, "leaf1"),
        )
        case(
            "no_route",
            [],
            [],
            lambda: probe_fake(lab, "10.10.99.10", 99),
            lambda hops, sent: judge_drop_at(by_probe(hops, ids[SRC], 99), sent, "leaf1"),
        )
        case(
            "loop",
            [
                nx("leaf1", "ip", "route", "add", f"{h2ip}/32", "via", l1_to_s1.peer_address),
                nx("spine1", "ip", "route", "add", f"{h2ip}/32", "via", s1_to_l1.peer_address),
            ],
            [
                nx("leaf1", "ip", "route", "del", f"{h2ip}/32"),
                nx("spine1", "ip", "route", "del", f"{h2ip}/32"),
            ],
            lambda: probe_pair(lab),
            lambda hops, sent: judge_loop(
                by_probe(hops, ids[SRC], ids[DST]), sent, {"leaf1", "spine1"}
            ),
        )
    finally:
        labmod.down(lab)

    mapping = {}
    for c in cases:
        if c["case"] != "clean" and c.get("reasons"):
            mapping[c["case"]] = c["reasons"]
    passed = sum(c["pass"] for c in cases)
    with ResultWriter(out_dir / "tracer.jsonl") as w:
        for c in cases:
            w.write(c)
        w.write({"record": "summary", "cases": len(cases), "passed": passed})
    # Classifier input: which codes mean what on this kernel, from the runs above.
    (out_dir / "drop_reasons.json").write_text(
        json.dumps(
            {
                "source": "results/calibration/tracer.jsonl",
                "kernel": subprocess.run(
                    ["uname", "-r"], capture_output=True, text=True
                ).stdout.strip(),
                "blackhole": sorted(
                    {
                        r["code"]
                        for k in ("blackhole", "unreachable", "no_route")
                        for r in mapping.get(k, [])
                    }
                ),
                "ttl_expired": sorted({r["code"] for r in mapping.get("loop", [])}),
                "cases": mapping,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    typer.echo(f"{passed}/{len(cases)} cases passed")
    if passed != len(cases):
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
